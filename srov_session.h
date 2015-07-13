
/* srov_session.h */

#ifndef _SROV_SESSION_H_
#define _SROV_SESSION_H_

#include <linux/list.h>
#include <linux/rculist.h>


#define SROV_HASH_BITS   8
#define SROV_HASH_SIZE   (1<<SROV_HASH_BITS)

#define SROV_FLOW_KEY(p, sa, da, sp, dp) \
	((hash_32 (p + sa + da + sp, 16) << 16) | dp)

struct srov_session {
	struct hlist_node      	hlist;	/* private: used by ss table  */
	struct rcu_head		rcu;	/* private */
	unsigned int		key;
	unsigned long		update;	/* jiffies */

	u8	protocol;	/* ip protocol */
	__be32	saddr, daddr;	/* src/dst IP address */
	u16	sport, dport;	/* src/dst port number */

	/* packet counter */
	unsigned long	pkt_count;
	unsigned long	byte_count;

	unsigned int	dst;	/* destination node (srov_gw) */
};

struct srov_session_table {
	struct hlist_head session_list[SROV_HASH_SIZE];
	rwlock_t lock;
};


/* terrible macro */
#define READ_LOCK(name) read_lock_bh ((&(name)->lock))
#define READ_UNLOCK(name) read_unlock_bh ((&(name)->lock))

#define WRITE_LOCK(name) write_lock_bh ((&(name)->lock))
#define WRITE_UNLOCK(name) write_unlock_bh ((&(name)->lock))

static inline struct hlist_head *
srov_sst_head (struct srov_session_table * sst, unsigned int key)
{
	return &sst->session_list[hash_32 (key, SROV_HASH_BITS)];
}

static inline struct srov_session *
srov_session_find (struct srov_session_table * sst, u8 protocol,
		   __be32 saddr, __be32 daddr, u16 sport, u16 dport)
{
	unsigned int key;
	struct srov_session * ss;

	key = SROV_FLOW_KEY (protocol, saddr, daddr, sport, dport);

	READ_LOCK (sst);
	hlist_for_each_entry_rcu (ss, srov_sst_head (sst, key), hlist) {
		if (ss->protocol == protocol &&
		    ss->saddr == saddr && ss->daddr == daddr &&
		    ss->sport == sport && ss->dport == dport) {
			READ_UNLOCK (sst);
			return ss;
		}
	}
	READ_UNLOCK (sst);

	return NULL;
}

static inline struct srov_session *
srov_session_create (u8 protocol, __be32 saddr, __be32 daddr,
		     u16 sport, u16 dport, int f)
{
	unsigned int key;
	struct srov_session * ss;

	key = SROV_FLOW_KEY (protocol, saddr, daddr, sport, dport);
	ss = (struct srov_session *) kmalloc (sizeof (struct srov_session), f);
	if (!ss) {
		printk (KERN_ERR "srov:%s: failed to allocate memory\n",
			__func__);
		return NULL;
	}

	memset (ss, 0, sizeof (struct srov_session));
	ss->key		= key;
	ss->update	= jiffies;
	ss->protocol	= protocol;
	ss->saddr	= saddr;
	ss->daddr	= daddr;
	ss->sport	= sport;
	ss->dport	= dport;

	return ss;
}

static inline void
srov_session_add (struct srov_session_table * sst, struct srov_session * ss)
{
	hlist_add_head_rcu (&ss->hlist, srov_sst_head (sst, ss->key));
}

static inline void
srov_session_destroy (struct srov_session * ss)
{
	hlist_del_rcu (&ss->hlist);
	kfree_rcu (ss, rcu);
}

static inline void
srov_session_table_destroy (struct srov_session_table * sst)
{
	unsigned int h;
	struct srov_session * ss;

	for (h = 0; h < SROV_HASH_SIZE; h++) {
		struct hlist_node * p, * n;
		hlist_for_each_safe (p, n, &sst->session_list[h]) {
			ss = container_of (p, struct srov_session, hlist);
			srov_session_destroy (ss);
		}
	}
}

#endif
