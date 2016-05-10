#ifndef __LIBNODE_NET_CLIENT_H__
#define __LIBNODE_NET_CLIENT_H__
/* Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "peerman.h"

#include <ccoin/coredefs.h>
#include <ccoin/parr.h>
#include <ccoin/message.h>
#include <ccoin/message.h>

#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct event_base;
struct peer_manager;
typedef struct net_client net_client;

/**
 * constants
 */

static const uint32_t PROTO_VERSION = 70001;

/**
 * nc_conn
 */

typedef struct nc_conn {
	bool			dead;
	bool			forget_peer;

	net_client              *client;
	int			fd;
	uint8_t                 netmagic[4];

	struct peer		peer;
	char			addr_str[64];
	bool			ipv4;

	bool			connected;
	struct event		*ev;

	struct event		*write_ev;
	clist			*write_q;	/* of struct buffer */
	unsigned int		write_partial;

	struct p2p_message	msg;

	void			*msg_p;
	unsigned int		expected;
	bool			reading_hdr;
	unsigned char		hdrbuf[P2P_HDR_SZ];

	bool			seen_version;
	bool			seen_verack;
	uint32_t		protover;
} nc_conn;

extern bool nc_conn_send(nc_conn *, const char *cmd, const void *d, size_t sz);
extern void nc_conn_kill(struct nc_conn *conn, bool forget_peer);

/**
 * nc_client
 */

typedef int (*get_block_height_t)(net_client *);
typedef void (*on_connected_t)(net_client *, nc_conn *);
typedef void (*on_msg_inv_t)(net_client *, nc_conn *, const struct msg_vinv *);
typedef void (*on_msg_block_t)(net_client *, nc_conn *, const struct bp_block *);
typedef void (*on_msg_headers_t)(net_client *, nc_conn *, const struct msg_headers *);

typedef struct net_client {

	/* settings */
	enum chains		chain_type;
	short			port;
	uint8_t			netmagic[4];
	uint32_t	        num_connections;
	char                    *version_str;
	uint64_t		services;
	uint64_t                instance_nonce;
	bool			relay;
	const char 		*peers_file;
	bool			debugging;

	/* connections */
	parr			connections;
	bool                    dead_connections;
	struct event_base	*eb;

	/* peer tracking */
	struct peer_manager	*peers;

	/* callbacks */
	get_block_height_t       get_block_height;
	on_connected_t           on_connected;
	on_msg_inv_t             on_msg_inv;
	on_msg_block_t           on_msg_block;
	on_msg_headers_t         on_msg_headers;


} net_client;

// extern net_client *net_client_new();

extern bool net_client_init(net_client *client,
			    enum chains chain_type,
			    uint32_t num_connections,
			    const char *version_string,
			    uint64_t services,
			    bool relay,
			    const char *peers_file,
			    bool debugging);

extern void net_client_free(net_client *client);

extern bool net_client_add_connection(net_client *client);

extern bool net_client_tick(net_client *client);

extern void net_client_break(net_client *client);

#ifdef __cplusplus
}
#endif

#endif /* __LIBNODE_NET_CLIENT_H__ */
