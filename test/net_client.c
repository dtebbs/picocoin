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

static struct blkdb        s_db;

static bool getheaders(nc_conn *conn)
{
	struct msg_getblocks gb;
	msg_getblocks_init(&gb);
	gb.locator.nVersion = PROTO_VERSION;
	blkdb_locator(&s_db, NULL, &gb.locator);

	cstring *s = ser_msg_getblocks(&gb);
	bool rc = nc_conn_send(conn, "getheaders", s->str, s->len);

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
	// static const bool testnet = true;

	struct net_client client;
	assert(net_client_init(&client,
			       CHAIN_REGTEST,
			       1, /* num_connections */
			       "picotest-0.0.1",
			       0, /* services */
			       false, /* relay */
			       "picotest.peers",
			       true /* debugging */
			       ));

	assert(blkdb_init_by_type(&s_db, CHAIN_REGTEST));
	client.on_connected = on_connected;

	while (true) {
		net_client_tick(&client);
		sched_yield();
		//usleep(1);
	}

	return 0;
}
