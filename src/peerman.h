#ifndef __PICOCOIN_PEERMAN_H__
#define __PICOCOIN_PEERMAN_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/core.h>
#include <ccoin/clist.h>
#include <ccoin/hashtab.h>

#include <stdbool.h>
#include <string.h>

struct peer {
	/* serialized */
	struct bp_address	addr;

	int64_t			last_ok;
	uint32_t		n_ok;

	int64_t			last_fail;
	uint32_t		n_fail;

	/* calculated at runtime */
	unsigned char		group[20];
	unsigned int		group_len;
};

static inline void peer_init(struct peer *peer)
{
	memset(peer, 0, sizeof(*peer));
	bp_addr_init(&peer->addr);
}

static inline void peer_free(struct peer *peer)
{
	bp_addr_free(&peer->addr);
}

static inline void peer_copy(struct peer *dest, const struct peer *src)
{
	memcpy(dest, src, sizeof(*dest));
}

static inline bool peer_compare_host(const struct peer *this,
				     const struct peer *that)
{
	return	(!memcmp(this->addr.ip, that->addr.ip, 16)) &&
		(this->addr.port == that->addr.port);
}

extern bool deser_peer(unsigned int protover,
		       struct peer *peer, struct const_buffer *buf);
extern void ser_peer(cstring *s, unsigned int protover, const struct peer *peer);

struct peer_manager {
	struct bp_hashtab 	*map_addr;	/* binary IP addr -> struct peer */
	clist			*addrlist;	/* of struct bp_address */
	bool			debugging;
};

extern void peerman_free(struct peer_manager *peers);
extern struct peer_manager *peerman_read_from_file(const char *filename,
						   enum chains chain_type,
						   bool debugging);
/* extern struct peer_manager *peerman_read(void); */
extern struct peer_manager *peerman_seed(enum chains chain_type,
					 bool use_dns,
					 bool debugging);

extern bool peerman_write_to_file(struct peer_manager *peers,
				  const char *fname,
				  enum chains chain_type);

extern struct peer *peerman_pop(struct peer_manager *peers);
extern bool peerman_get_next(struct peer_manager *peers, struct peer *p);
extern void peerman_remove_host(struct peer_manager *peers,
				const struct peer *peer);
extern void peerman_mark_ok(struct peer_manager *peers, const struct peer *peer);
extern void peerman_sort(struct peer_manager *peers);
extern void peerman_add(struct peer_manager *peers,
			const struct peer *peer_in, bool known_working);
extern void peerman_add_addr(struct peer_manager *peers,
			     const struct bp_address *addr_in,
			     bool known_working);
extern void peerman_addstr(struct peer_manager *peers, const char *addr_str);

#endif /* __PICOCOIN_PEERMAN_H__ */
