/* Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <../src/net_client.h>
#include <ccoin/coredefs.h>
#include <ccoin/blkdb.h>

#include <stdio.h>
#include <assert.h>
#include <sched.h>
#include <signal.h>

# define LOG( _msg_, ... )						\
	{								\
		printf("client_net (test): " _msg_, ##__VA_ARGS__);	\
		if ('\n' != _msg_[strlen(_msg_)-1]) {			\
			printf("\n");					\
		}							\
	}

# define ERROR( _msg_, ... )						\
	{								\
		fprintf(stderr, "client_net (test) ERROR: " _msg_,	\
			##__VA_ARGS__);					\
		if ('\n' != _msg_[strlen(_msg_)-1]) {			\
			fprintf(stderr, "\n");				\
		}							\
	}

static bool                s_running;
static net_client          s_client;
static struct blkdb        s_db;

static void int_signal(int signo)
{
	if (s_running) {
		s_running = false;
		net_client_break(&s_client);
	}
}

static bool getheaders(nc_conn *conn)
{
	struct msg_getblocks gb;
	msg_getblocks_init(&gb);
	gb.locator.nVersion = PROTO_VERSION;
	blkdb_locator(&s_db, NULL, &gb.locator);

	cstring *s = ser_msg_getblocks(&gb);
	bool rc = nc_conn_send(conn, "getheaders", s->str, s->len);

	cstr_free(s, true);
	msg_getblocks_free(&gb);
	return rc;
}

static void on_connected(net_client *client, nc_conn *conn)
{
	LOG("connected (client:%p, conn:%p)", client, conn);

	// Request headers

	if (!getheaders(conn)) {
		ERROR("failed to send 'getheaders' to %s", conn->addr_str);
		nc_conn_kill(conn, false);
	}
}



int main(int argc, char **argv)
{
	bool run = false;
	if (getenv("TEST_NET_CLIENT")) {
		run = true;
	}

	int a;
	for (a = 1 ; a < argc ; ++a) {
		if (0 == strcmp("--run", argv[a])) {
			run = true;
		} else {
			fprintf(stderr, "Unknown argument: %s", argv[a]);
			exit(1);
		}
	}

	if (!run) {
		fprintf(stderr,
	"net_client: skipping net_client test.  Use TEST_NET_CLIENT envvar or\n"
	"net_client: --run arg.\n"
		);
		return 77;
	}

	assert(net_client_init(&s_client,
			       CHAIN_REGTEST,
			       1, /* num_connections */
			       "picotest-0.0.1",
			       0, /* services */
			       false, /* relay */
			       "picotest.peers",
			       true /* debugging */
	       ));

	assert(blkdb_init_by_type(&s_db, CHAIN_REGTEST));
	s_client.on_connected = on_connected;

	s_running = true;
	signal(SIGINT, int_signal);

	while (s_running) {
		net_client_tick(&s_client);
		sched_yield();
		//usleep(1);
	}

	net_client_free(&s_client);
	blkdb_free(&s_db);

	return 0;
}
