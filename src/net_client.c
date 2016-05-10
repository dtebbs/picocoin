/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "net_client.h"
#include "peerman.h"

#include <ccoin/util.h>
#include <ccoin/clist.h>
#include <ccoin/message.h>
#include <ccoin/core.h>
#include <ccoin/net.h>

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <event2/event.h>
#include <openssl/rand.h>
#if defined(__APPLE__)
# include <sys/uio.h>
#endif

#define LOGGING

#if defined(LOGGING)
# define LOG( _msg_, ... )					\
	{							\
		printf("net_client: %s: " _msg_,		\
		       __FUNCTION__, ##__VA_ARGS__);		\
		if ('\n' != _msg_[strlen(_msg_)-1]) {		\
			printf("\n");				\
		}						\
	}
#else
# define LOG( ... )
#endif

#define ERROR( _msg_, ... )						\
	{								\
		fprintf(stderr, "net_client: %s: ERROR: " _msg_,	\
			__FUNCTION__, ##__VA_ARGS__);			\
		if ('\n' != _msg_[strlen(_msg_)-1]) {			\
			fprintf(stderr, "\n");				\
		}							\
	}

static unsigned int   CONN_TIMEOUT = 11;

static char *copy_string(const char *s)
{
	if (!s) {
		return NULL;
	}
	size_t sz = strlen(s);
	char *copy = (char *)malloc(sz+1);
	if (copy) {
		strcpy(copy, s);
		return copy;
	}
	return NULL;
}

static uint64_t generate_instance_nonce()
{
	uint64_t n;
	RAND_bytes((unsigned char *)&n, sizeof(n));
	return n;
}

static cstring *nc_version_build(const char *version,
				 uint64_t services,
				 uint64_t nonce,
				 uint32_t starting_height,
				 bool relay)
{
	struct msg_version mv;

	msg_version_init(&mv);

	mv.nVersion = PROTO_VERSION;
	mv.nServices = services;
	mv.nTime = (int64_t) time(NULL);
	mv.nonce = nonce;
	sprintf(mv.strSubVer, "/%s/", version);
	mv.nStartingHeight = starting_height;
	mv.bRelay = relay;

	cstring *rs = ser_msg_version(&mv);

	msg_version_free(&mv);

	return rs;
}

// -----------------------------------------------------------------------------
// nc_conn
// -----------------------------------------------------------------------------

static bool nc_conn_write_disable(struct nc_conn *conn);

static bool nc_conn_init(nc_conn *conn,
			 net_client *client,
			 const struct peer *peer)
{
	memset(conn, 0, sizeof(nc_conn));

	conn->client = client;
	conn->fd = -1;
	memcpy(conn->netmagic, client->netmagic, 4);

	peer_copy(&conn->peer, peer);
	bn_address_str(conn->addr_str, sizeof(conn->addr_str), peer->addr.ip);
	conn->ipv4 = is_ipv4_mapped(peer->addr.ip);

		       return true;
}

static nc_conn *nc_conn_new(net_client *client,
			    const struct peer *peer)
{
	struct nc_conn *conn = malloc(sizeof(nc_conn));
	if (conn) {
		if (nc_conn_init(conn, client, peer)) {
			return conn;
		}
		free(conn);
	}
	return NULL;
}

static void nc_conn_free(nc_conn *conn)
{
	if (conn->write_q) {
		clist *tmp = conn->write_q;

		while (tmp) {
			struct buffer *buf;

			buf = tmp->data;
			tmp = tmp->next;

			free(buf->p);
			free(buf);
		}

		clist_free(conn->write_q);
	}

	if (conn->ev) {
		event_del(conn->ev);
		event_free(conn->ev);
	}
	if (conn->write_ev) {
		event_del(conn->write_ev);
		event_free(conn->write_ev);
	}

	if (conn->fd >= 0)
		close(conn->fd);

	free(conn->msg.data);

	memset(conn, 0, sizeof(*conn));
	free(conn);
}

void nc_conn_kill(struct nc_conn *conn, bool forget_peer)
{
	// assert(conn->dead == false);

	conn->dead = true;
	conn->forget_peer = forget_peer;
	conn->client->dead_connections = true;
	event_base_loopbreak(conn->client->eb);
}

static bool nc_msg_version(struct nc_conn *conn)
{
	if (conn->seen_version) {
		ERROR("already seen version: %s", conn->addr_str);
		return true;
	}

	conn->seen_version = true;

	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_version mv;
	bool rc = false;

	msg_version_init(&mv);

	if (!deser_msg_version(&mv, &buf))
		goto out;

	{
		char fromstr[64], tostr[64];
		bn_address_str(fromstr, sizeof(fromstr), mv.addrFrom.ip);
		bn_address_str(tostr, sizeof(tostr), mv.addrTo.ip);
		LOG("%s version(%u, 0x%llx, %lld, To:%s, From:%s, %s, %u)\n",
		    conn->addr_str,
		    mv.nVersion,
		    (unsigned long long) mv.nServices,
		    (long long) mv.nTime,
		    tostr,
		    fromstr,
		    mv.strSubVer,
		    mv.nStartingHeight);
	}

	/* require NODE_NETWORK */
	if (!(mv.nServices & NODE_NETWORK)) {
		ERROR("NODE_NETWORK not set: %s", conn->addr_str);
		goto out;
	}

	/* connected to ourselves? */
	if (mv.nonce == conn->client->instance_nonce) {
		ERROR("connected to ourselves: %s", conn->addr_str);
		goto out;
	}

	conn->protover = MIN(mv.nVersion, PROTO_VERSION);

	/* acknowledge version receipt */
	if (!nc_conn_send(conn, "verack", NULL, 0)) {
		ERROR("failed to send 'verack': %s", conn->addr_str);
		goto out;
	}

	rc = true;

out:
	msg_version_free(&mv);
	return rc;
}

static bool nc_msg_verack(struct nc_conn *conn)
{
	if (conn->seen_verack)
		return false;
	conn->seen_verack = true;
	peerman_mark_ok(conn->client->peers, &conn->peer);

	/* request peer addresses */
	if ((conn->protover >= CADDR_TIME_VERSION) &&
	    (!nc_conn_send(conn, "getaddr", NULL, 0)))
		return false;

	return true;
}

static bool nc_msg_addr(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_addr ma;
	bool rc = false;

	msg_addr_init(&ma);

	if (!deser_msg_addr(conn->protover, &ma, &buf)) {
		goto out;
	}

	unsigned int i;
	time_t cutoff = time(NULL) - (7 * 24 * 60 * 60);

	/* ignore ancient addresses */
	if (conn->protover < CADDR_TIME_VERSION) {
		goto out_ok;
	}

	/* feed addresses to peer manager and count the old ones */
	unsigned int old = 0;
	for (i = 0; i < ma.addrs->len; i++) {
		struct bp_address *addr = parr_idx(ma.addrs, i);

		if (addr->nTime > cutoff) {
			peerman_add_addr(conn->client->peers, addr, false);
		} else {
			old++;
		}
	}
	LOG("%s addr(%zu addresses, %u old)\n",
	    conn->addr_str, ma.addrs->len, old);

out_ok:
	rc = true;

out:
	msg_addr_free(&ma);
	return rc;
}

static bool nc_msg_ping(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };

	bool rc = false;

	struct msg_ping ping;
	msg_ping_init(&ping);
	if (deser_msg_ping(conn->protover, &ping, &buf)) {
		/* struct msg_ping pong; */
		/* msg_ping_init(pong); */
		/* pong.nonce = ping.nonce; */

		cstring *s = ser_msg_ping(conn->protover, &ping);
		if (s) {
			rc = nc_conn_send(conn, "pong", s->str, s->len);
			cstr_free(s, true);
		}
	}
	msg_ping_free(&ping);

	return rc;
}

static bool nc_msg_inv(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_vinv mv;
	bool rc = false;

	msg_vinv_init(&mv);

	if (!deser_msg_vinv(&mv, &buf)) {
		LOG("invalid \"inv\" msg: %s", conn->addr_str);
		goto out;
	}

#if defined(LOGGING)
	if (mv.invs && mv.invs->len == 1) {
		struct bp_inv *inv = parr_idx(mv.invs, 0);
		char hexstr[BU256_STRSZ];
		bu256_hex(hexstr, &inv->hash);

		char typestr[32];
		switch (inv->type) {
		case MSG_TX: strcpy(typestr, "tx"); break;
		case MSG_BLOCK: strcpy(typestr, "block"); break;
		case MSG_FILTERED_BLOCK: strcpy(typestr, "fltrd-block"); break;
		default: sprintf(typestr, "unknown 0x%x", inv->type); break;
		}

		LOG("%s inv %s %s\n", conn->addr_str, typestr, hexstr);
	}
	else if (mv.invs) {
		LOG("%s inv (%zu sz)\n", conn->addr_str, mv.invs->len);
	}
#endif

	net_client *client = conn->client;
	on_msg_inv_t on_inv = client->on_msg_inv;
	if (on_inv) {
		on_inv(client, conn, &mv);
	}

	rc = true;

out:
	msg_vinv_free(&mv);
	return rc;
}

static bool nc_msg_block(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct bp_block block;
	bp_block_init(&block);

	bool rc = false;

	/* deserialize and validate the block */

	if (!deser_bp_block(&block, &buf)) {
		goto out;
	}

	bp_block_calc_sha256(&block);

#if defined(LOGGING)
	{
		char hexstr[BU256_STRSZ];
		bu256_hex(hexstr, &block.sha256);
		LOG("%s block %s", conn->addr_str, hexstr);
	}
#endif

	if (!bp_block_valid(&block)) {
		char hexstr[BU256_STRSZ];
		bu256_hex(hexstr, &block.sha256);
		LOG("%s invalid block %s\n", conn->addr_str, hexstr);
		goto out;
	}

	net_client *client = conn->client;
	on_msg_block_t on_block = client->on_msg_block;
	if (on_block) {
		on_block(client, conn, &block);
	}

	rc = true;

out:
	bp_block_free(&block);
	return rc;
}

static bool nc_msg_headers(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };

	bool rc = false;

	struct msg_headers mh;
	msg_headers_init(&mh);
	if (!deser_msg_headers(&mh, &buf)) {
		goto out;
	}

#if defined(LOGGING)
	{
		LOG("%s headers (%d entries)",
		    conn->addr_str, (int )mh.headers->len);
	}
#endif

	net_client *client = conn->client;
	on_msg_headers_t on_headers = client->on_msg_headers;
	if (on_headers) {
		on_headers(client, conn, &mh);
	}

	rc = true;

out:
	msg_headers_free(&mh);
	return rc;
}

static bool nc_conn_message(struct nc_conn *conn)
{
	char *command = conn->msg.hdr.command;

	LOG("got '%s' (%d bytes)",
	    command, conn->msg.hdr.data_len);

	net_client *client = conn->client;

	/* verify correct network */
	if (memcmp(conn->msg.hdr.netmagic, client->netmagic, 4)) {
		ERROR("invalid network: %s", conn->addr_str);
		return false;
	}

	/* "version" must be first message */
	if (!conn->seen_version) {
		if (!strncmp(command, "version", 12)) {
			return nc_msg_version(conn);
		}

		ERROR("'version' not first: %s", conn->addr_str);
		return false;;
	}

	/* "verack" must be second message */
	if (!conn->seen_verack) {
		if (strncmp(command, "verack", 12)) {
			ERROR("'verack' not second %s", conn->addr_str);
			return false;
		}

		if (!nc_msg_verack(conn)) {
			ERROR("failed handling verack %s", conn->addr_str);
			return false;
		}


		if (client->on_connected) {
			client->on_connected(client, conn);
		}
		return true;
	}

	/* incoming message: addr */
	if (!strncmp(command, "addr", 12)) {
		return nc_msg_addr(conn);
	}

	/* incoming message: ping */
	if (!strncmp(command, "ping", 12)) {
		return nc_msg_ping(conn);
	}

	/* incoming message: inv */
	else if (!strncmp(command, "inv", 12)) {
		return nc_msg_inv(conn);
	}

	/* incoming message: getdata */

	/* incoming message: notfound */

	/* incoming message: getblocks */

	/* incoming message: getheaders */

	/* incoming message: tx */

	/* incoming message: block */
	else if (!strncmp(command, "block", 12)) {
		return nc_msg_block(conn);
	}

	/* incoming message: headers */
	else if (!strncmp(command, "headers", 12)) {
		return nc_msg_headers(conn);
	}

	/* incoming message: getaddr */

	/* incoming message: mempool */

	/* incoming message: filterload */

	/* incoming message: filteradd */

	/* incoming message: filterclear */

	/* incoming message: merkleblock */

	/* incoming message: alter */

	/* incoming message: sendheaders */

	LOG("unknown message %s: %s \n", conn->addr_str, command);

	/* ignore unknown messages */
	return true;
}

static bool nc_conn_got_header(struct nc_conn *conn)
{
	parse_message_hdr(&conn->msg.hdr, conn->hdrbuf);

	unsigned int data_len = conn->msg.hdr.data_len;

	if (data_len > (16 * 1024 * 1024)) {
		free(conn->msg.data);
		conn->msg.data = NULL;
		return false;
	}

	// TODO: reuse a single buffer instead of allocating each time

	conn->msg.data = malloc(data_len);

	/* switch to read-body state */
	conn->msg_p = conn->msg.data;
	conn->expected = data_len;
	conn->reading_hdr = false;

	return true;
}

static bool nc_conn_got_msg(struct nc_conn *conn)
{
	if (!message_valid(&conn->msg)) {
		ERROR("invalid message: %s\n", conn->addr_str);
		return false;
	}

	if (!nc_conn_message(conn)) {
		return false;
	}

	free(conn->msg.data);
	conn->msg.data = NULL;

	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;

	return true;
}

static void nc_conn_read_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;

	ssize_t rrc = read(fd, conn->msg_p, conn->expected);
	if (rrc <= 0) {
		if (rrc < 0) {
			ERROR("read error: %s: %s\n",
			      conn->addr_str,
			      strerror(errno));
		} else {
			ERROR("llnet: %s read EOF\n", conn->addr_str);
		}

		goto err_out;
	}

	conn->msg_p += rrc;
	conn->expected -= rrc;

	/* execute our state machine at most twice */
	uint32_t i;
	for (i = 0; i < 2; i++) {
		if (conn->expected == 0) {
			if (conn->reading_hdr) {
				if (!nc_conn_got_header(conn)) {
					goto err_out;
				}
			} else {
				if (!nc_conn_got_msg(conn)) {
					goto err_out;
				}
			}
		}
	}

	return;

err_out:
	nc_conn_kill(conn, true);
}

static bool nc_conn_read_enable(struct nc_conn *conn)
{
	if (conn->ev) {
		return true;
	}

	conn->ev = event_new(conn->client->eb,
			     conn->fd,
			     EV_READ | EV_PERSIST,
			     nc_conn_read_evt,
			     conn);
	if (!conn->ev) {
		ERROR("failed to create read event");
		return false;
	}

	if (event_add(conn->ev, NULL) != 0) {
		ERROR("failed to register read event");
		event_free(conn->ev);
		conn->ev = NULL;
		return false;
	}

	return true;
}

static void nc_conn_build_iov(clist *write_q, unsigned int partial,
			      struct iovec **iov_, unsigned int *iov_len_)
{
	*iov_ = NULL;
	*iov_len_ = 0;

	unsigned int i, iov_len = clist_length(write_q);
	struct iovec *iov = calloc(iov_len, sizeof(struct iovec));

	clist *tmp = write_q;

	i = 0;
	while (tmp) {
		struct buffer *buf = tmp->data;

		iov[i].iov_base = buf->p;
		iov[i].iov_len = buf->len;

		if (i == 0) {
			iov[0].iov_base += partial;
			iov[0].iov_len -= partial;
		}

		tmp = tmp->next;
		i++;
	}

	*iov_ = iov;
	*iov_len_ = iov_len;
}

static void nc_conn_written(struct nc_conn *conn, size_t bytes)
{
	while (bytes > 0) {
		clist *tmp;
		struct buffer *buf;
		unsigned int left;

		tmp = conn->write_q;
		buf = tmp->data;
		left = buf->len - conn->write_partial;

		/* buffer fully written; free */
		if (bytes >= left) {
			free(buf->p);
			free(buf);
			conn->write_partial = 0;
			conn->write_q = clist_delete(tmp, tmp);

			bytes -= left;
		}

		/* buffer partially written; store state */
		else {
			conn->write_partial += bytes;
			break;
		}
	}
}

static void nc_conn_write_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;
	struct iovec *iov = NULL;
	unsigned int iov_len = 0;

	/* build list of outgoing data buffers */
	nc_conn_build_iov(conn->write_q, conn->write_partial, &iov, &iov_len);

	/* send data to network */
	ssize_t wrc = writev(conn->fd, iov, iov_len);
	free(iov);

	if (wrc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			goto err_out;
		return;
	}

	/* handle partially and fully completed buffers */
	nc_conn_written(conn, wrc);

	/* thaw read, if write fully drained */
	if (!conn->write_q) {
		LOG("wrote %d bytes (drained)", (int)wrc);

		if (!nc_conn_write_disable(conn) ||
		    !nc_conn_read_enable(conn)) {
			ERROR("failed to enable reading");
			nc_conn_kill(conn, false);
		}
	} else {
		LOG("wrote %d bytes (remaining)", (int)wrc);
	}

	return;

err_out:
	nc_conn_kill(conn, false);
}

static bool nc_conn_read_disable(struct nc_conn *conn)
{
	if (!conn->ev)
		return true;

	event_del(conn->ev);
	event_free(conn->ev);

	conn->ev = NULL;

	return true;
}

static bool nc_conn_write_enable(struct nc_conn *conn)
{
	if (conn->write_ev) {
		LOG("already writing");
		return true;
	}

	conn->write_ev = event_new(conn->client->eb, conn->fd,
				   EV_WRITE | EV_PERSIST,
				   nc_conn_write_evt, conn);
	if (!conn->write_ev) {
		ERROR("failed to enable: %s", conn->addr_str);
		return false;
	}

	if (event_add(conn->write_ev, NULL) != 0) {
		ERROR("failed reg evt: %s", conn->addr_str);
		event_free(conn->write_ev);
		conn->write_ev = NULL;
		return false;
	}

	LOG("enabled");
	return true;
}

static bool nc_conn_write_disable(struct nc_conn *conn)
{
	if (!conn->write_ev) {
		return true;
	}

	event_del(conn->write_ev);
	event_free(conn->write_ev);

	conn->write_ev = NULL;

	return true;
}

bool nc_conn_send(struct nc_conn *conn,
		  const char *command,
		  const void *data,
		  size_t data_len)
{
	/* build wire message */
	cstring *msg = message_str(conn->netmagic, command, data, data_len);
	if (!msg) {
		return false;
	}

	/* buffer now owns message data */
	struct buffer *buf = calloc(1, sizeof(struct buffer));
	buf->p = msg->str;
	buf->len = msg->len;

	cstr_free(msg, false);

	/* if write q exists, write_evt will handle output */
	if (conn->write_q) {
		conn->write_q = clist_append(conn->write_q, buf);
		LOG("msg '%s' len %d (queued)",
		    command, (int )data_len);
		return true;
	}

	/* attempt optimistic write */
	ssize_t wrc = write(conn->fd, buf->p, buf->len);

	if (wrc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			free(buf->p);
			free(buf);
			return false;
		}

		conn->write_q = clist_append(conn->write_q, buf);
		goto out_wrstart;
	}

	/* message fully sent */
	if (wrc == buf->len) {
		LOG("msg '%s' data_len:%d bytes) (full)",
		    command, (int )data_len);

		free(buf->p);
		free(buf);
		return true;
	}

	/* message partially sent; pause read; poll for writable */
	conn->write_q = clist_append(conn->write_q, buf);
	conn->write_partial = wrc;

	LOG("msg '%s' data_len:%d (%d written, remaining queued)",
	    command, (int )data_len, (int)wrc);

out_wrstart:
	nc_conn_read_disable(conn);
	nc_conn_write_enable(conn);
	return true;
}

static void nc_conn_evt_connected(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;

	/* clear event used for watching connect(2) */
	assert(conn->ev);
	event_free(conn->ev);
	conn->ev = NULL;

	if ((events & EV_WRITE) == 0) {
		LOG("%s connection timeout\n", conn->addr_str);
		goto err_out;
	}

	int err = 0;
	socklen_t len = sizeof(err);

	/* check success of connect(2) */
	if ((getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) ||
	    (err != 0)) {
		ERROR("connect %s failed: %s\n",
		      conn->addr_str, strerror(err));
		goto err_out;
	}

	LOG("connected to %s\n", conn->addr_str);

	conn->connected = true;

	/* build and send "version" message */
	uint32_t block_height = 0;
	net_client *client = conn->client;
	if (client->get_block_height) {
		block_height = client->get_block_height(client);
	}

	cstring *msg_data = nc_version_build(client->version_str,
					     client->services,
					     client->instance_nonce,
					     block_height,
					     conn->client->relay);
	bool rc = nc_conn_send(conn, "version", msg_data->str, msg_data->len);
	cstr_free(msg_data, true);

	if (!rc) {
		LOG("%s !conn_send\n", conn->addr_str);
		goto err_out;
	}

	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;

	if (!nc_conn_read_enable(conn)) {
		LOG("%s read not enabled\n", conn->addr_str);
		goto err_out;
	}

	return;

err_out:
	nc_conn_kill(conn, true);
}

static bool nc_conn_start(nc_conn *conn, struct event_base *eb)
{
	/* create socket */
	conn->fd = socket(conn->ipv4 ? AF_INET : AF_INET6,
			  SOCK_STREAM, IPPROTO_TCP);

	if (conn->fd < 0) {
		ERROR("failed to create socket: %s", strerror(errno));
		return false;
	}

	/* set non-blocking */
	int flags = fcntl(conn->fd, F_GETFL, 0);
	if ((flags < 0) ||
	    (fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) < 0)) {
		ERROR("failed to set socket non-blocking: %s", strerror(errno));
		return false;
	}

	struct sockaddr *saddr;
	struct sockaddr_in6 saddr6;
	struct sockaddr_in saddr4;
	socklen_t saddr_len;

	/* fill out connect(2) address */
	if (conn->ipv4) {
		memset(&saddr4, 0, sizeof(saddr4));
		saddr4.sin_family = AF_INET;
		memcpy(&saddr4.sin_addr.s_addr,
		       &conn->peer.addr.ip[12], 4);
		saddr4.sin_port = htons(conn->peer.addr.port);

		saddr = (struct sockaddr *) &saddr4;
		saddr_len = sizeof(saddr4);
	} else {
		memset(&saddr6, 0, sizeof(saddr6));
		saddr6.sin6_family = AF_INET6;
		memcpy(&saddr6.sin6_addr.s6_addr,
		       &conn->peer.addr.ip[0], 16);
		saddr6.sin6_port = htons(conn->peer.addr.port);

		saddr = (struct sockaddr *) &saddr6;
		saddr_len = sizeof(saddr6);
	}

	/* initiate TCP connection */
	if (connect(conn->fd, saddr, saddr_len) < 0) {
		if (errno != EINPROGRESS) {
			ERROR("connect failed: %s", strerror(errno));
			return false;
		}
	}

	/* add to our list of monitored event sources */
	conn->ev = event_new(eb, conn->fd, EV_WRITE,
			     nc_conn_evt_connected,
			     conn);
	if (!conn->ev) {
		ERROR("event_new failed for connect %s\n", conn->addr_str);
		return false;
	}

	struct timeval timeout = { CONN_TIMEOUT };
	if (event_add(conn->ev, &timeout) != 0) {
		ERROR(": event_add failed on %s\n", conn->addr_str);
		return false;
	}

	return true;
}

// -----------------------------------------------------------------------------
// net_client
//  -----------------------------------------------------------------------------

static bool net_client_have_connection_to_peer(const net_client *client,
					       const struct peer *peer)
{
	const size_t num_conns = client->connections.len;
	/* LOG("net_client_have_connection_to_peer: %d connections", */
	/*     (int )num_conns); */
	size_t i;
	for (i = 0 ; i < num_conns ; ++i) {
		const nc_conn *c = parr_idx(&client->connections, i);
		if (peer_compare_host(&c->peer, peer)) {
			/* LOG("net_client_have_connection_to_peer: conn %d: match", */
			/*     (int )i); */
			return true;
		}

		/* LOG("net_client_have_connection_to_peer: conn %d: no match", */
		/*     (int )i); */
	}

	return false;
}

/* net_client *net_client_new() */
/* { */
/* 	return (net_client *)calloc(1, sizeof(net_client)); */
/* } */

bool net_client_init(net_client *client,
		     enum chains chain_type,
		     uint32_t num_connections,
		     const char *version_str,
		     uint64_t services,
		     bool relay,
		     const char *peer_file,
		     bool debugging)
{
	memset(client, 0, sizeof(net_client));

	const struct chain_info *chain = chain_find_by_type(chain_type);
	if (!chain) {
		return false;
	}

	client->chain_type = chain_type;
	client->port = chain->port;
	memcpy(client->netmagic, chain->netmagic, 4);
	client->num_connections = num_connections;
	client->version_str = copy_string(version_str);
	client->services = services;
	client->instance_nonce = generate_instance_nonce();
	client->relay = relay;
	client->peers_file = copy_string(peer_file);
	client->debugging = debugging;

	if (!parr_init(&client->connections, 0, NULL)) {
		goto err;
	}
	assert(0 == client->connections.len);
	assert(0 == (&client->connections)->len);

	client->dead_connections = false;
	client->eb = event_base_new();
	if (NULL == client->eb) {
		goto err_free_connections;
	}

	if (client->peers_file) {
		client->peers = peerman_read_from_file(peer_file,
						       chain_type,
						       debugging);
	}
	if (!client->peers) {
		client->peers = peerman_seed(chain_type, true, debugging);
	}
	if (!client->peers) {
		ERROR("failed to create peer manager");
		return false;
	}

	return true;

 err_free_connections:
	parr_free(&client->connections, true);
 err:
	return false;

}

void net_client_free(net_client *client)
{
	if (client->peers) {
		peerman_free(client->peers);
		client->peers = NULL;
	}

	if (client->eb) {
		event_base_free(client->eb);
		client->eb = NULL;
	}

	if (client->version_str) {
		free(client->version_str);
		client->version_str = NULL;
	}

	if (client->peers_file) {
		free((char *)client->peers_file);
		client->peers_file = NULL;
	}
}

bool net_client_add_connection(net_client *client)
{
	assert(client->peers);

	struct peer peer;
	do {
		if (!peerman_get_next(client->peers, &peer)) {
			LOG("no more peers");
			return false;
		}
	} while (net_client_have_connection_to_peer(client, &peer));

#if defined(LOGGING)
	{
		char addr_str[64];
		bn_address_str(addr_str, sizeof(addr_str), peer.addr.ip);
		LOG("connecting to %s", addr_str);
	}
#endif

	nc_conn *conn = nc_conn_new(client, &peer);
	if (!conn) {
		ERROR("failed to create conn");
		return NULL;
	}

	if (!nc_conn_start(conn, client->eb)) {
		ERROR("failed to start conn");
		nc_conn_free(conn);
		return NULL;
	}

	LOG("new conn %p", conn);
	parr_add(&client->connections, conn);
	return true;
}

static void net_client_conns_gc(struct net_client *client)
{
	if (!client->dead_connections) {
		return;
	}

	clist *dead = NULL;
	unsigned int n_gc = 0;

	/* build list of dead connections */
	parr *connections = &client->connections;
	uint32_t i;
	for (i = 0; i < connections->len; ++i) {
		struct nc_conn *conn = parr_idx(connections, i);
		if (conn->dead) {
			dead = clist_prepend(dead, conn);
		}
	}

	/* remove and free dead connections */
	clist *tmp = dead;
	while (tmp) {
		nc_conn *conn = (nc_conn *)tmp->data;

		if (conn->forget_peer) {
			peerman_remove_host(client->peers, &conn->peer);
		}

		tmp = tmp->next;

		parr_remove(connections, conn);
        nc_conn_free(conn);
		n_gc++;
	}

	clist_free(dead);

	LOG("gc'd %u connections\n", n_gc);
}

bool net_client_tick(net_client *client)
{
	assert(NULL != client->eb);

	/* LOG("calling event_base_dispatch..."); */
	event_base_dispatch(client->eb);
	/* LOG("returned from event_base_dispatch."); */

	// Clean up dead connections, forgetting any peers that

	net_client_conns_gc(client);

	// Add a connection if there aren't enough

	parr *connections = &client->connections;

	/* LOG("got %d/%d connections:", */
	/*     (int )connections->len, */
	/*     (int )client->num_connections); */

	if (client->num_connections > connections->len) {
		LOG("%d/%d connections: calling net_client_add_connection ...",
		    (int )connections->len,
		    client->num_connections);
		net_client_add_connection(client);
		LOG("back from net_client_add_connection");
	}

	return true;
}

void net_client_break(net_client *client)
{
	event_base_loopbreak(client->eb);
}
