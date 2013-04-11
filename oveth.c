/*
 * Overlay ethernet driver
 */

#ifndef DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/byteorer/generic.h>
#include <linux/hash.h>
#include <linux/udp.h>
#include <linux/etherdevice.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/inet_sock.h>
#include <net/inet_ecn.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "ovstack.h"

#define OVETH_VERSION "0.0.1"

MODULE_VERSION (OVETH_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");
MODULE_ALIAS_RTNL_LINK ("oveth");


#define VNI_MAX		0x00FFFFFF
#define VNI_HASH_BITS	8
#define FDB_HASH_BITS	8

#define VNI_HASH_SIZE (1 << VNI_HASH_BITS)
#define FDB_HASH_SIZE (1 << FDB_HASH_BITS)

/* IP + UDP + OVHDR + Ethernet */
#define OVETH_IPV4_HEADROOM (20 + 8 + 16 + 14)
#define OVETH_IPV6_HEADROOM (40 + 8 + 16 + 14)

static u32 oveth_salt __readmostly;


struct oveth_fdb_node {
	struct list_head	list;
	struct rcu_head		rcu;
	__be32			node_id;
};

struct oveth_fdb {
	struct list_head	list;
	struct list_head	chain;
	struct rcu_head		rcu;

	unsgined long		update;

	u8			eth_addr[ETH_ALEN];
	struct list_head	node_id_list;
	u8			node_id_count;
};

#define OVETH_FDB_FIRST_NODE(fdb) \
	(list_entry_rcu (&(fdb->node_id_list), struct oveth_fdb_node, list))

#define OVETH_FDB_NODE_COUNT(fdb) fdb->node_id_count


/* per network namespace instance */
static unsigned int oveth_net_id;
struct oveth_net {
	struct list_head vni_list[VNI_HASH_SIZE];	/* oveth_dev table */
};


/* per cpu network traffic stats */
struct oveth_stats {
	u64	rx_packets;
	u64	rx_bytes;
	u64	tx_packets;
	u64	tx_bytes;
	struct u64_stats_sync	syncp;
};

/* psuedo network device */
struct oveth_dev {
	struct list_head	list;
	struct net_device	* dev;
	struct oveth_stats	__percpu * stats;

	__u32			vni;
	struct list_head	fdb_head[FDB_HASH_SIZE];
	struct list_head	fdb_chain;
};


/* utirls */
static u32 eth_hash(const unsigned char *addr)
{
	/* from vxlan.c */

	u64 value = get_unaligned((u64 *)addr);

	/* only want 6 bytes */
	#ifdef __BIG_ENDIAN
	value >>= 16;
	#else
	value <<= 16;
	#endif

	return hash_64(value, FDB_HASH_BITS);
}


/* vni and fdb operations */
static inline struct list_head *
vni_head (struct net * net, u32 vni)
{
	struct oveth_net * ovnet = net_generic (net, oveth_net_id);
	
	return &(ovnet->vni_list[hash_32 (vni, VNI_HASH_BITS)]);
}

static struct oveth_dev *
find_oveth_by_vni (struct net * net, u32 vni)
{
	struct oveth_dev * oveth;

	list_for_each_entry_rcu (oveth, vni_head (net, vni), list) {
		if (oveth->vni == vni)
			return oveth;
	}

	return NULL;
}

static inline struct list_head *
oveth_fdb_head (struct oveth_dev * oveth, const u8 * mac)
{
	return &(oveth->fdb_head[eth_hash (mac)]);
}

static struct oveth_fdb *
find_oveth_fdb_by_mac (struct oveth_dev * oveth, const u8 * mac)
{
	struct list_head * head = oveth_fdb_head (oveth, mac);
	struct oveth_fdb * f;

	list_for_each_entry_rcu (f, head, list) {
		if (compare_ether_addr (mac, f->eth_addr) == 0)
			return f;
	}
	return NULL;
}

static struct oveth_fdb *
create_oveth_fdb (u8 * mac)
{
	struct oveth_fdb * f;

	f = kmalloc (sizeof (struct oveth_fdb), GFP_KERNEL);
	memset (f, 0, sizeof (struct oveth_fdb));
	
	INIT_LIST_HEAD (&(f->list));
	INIT_LIST_HEAD (&(f->chain));
	INIT_LIST_HEAD (&(f->node_id_list));
	memcpy (f->eth_addr, mac, ETH_ALEN);
	f->update = jiffies;

	return f;
}

static void
oveth_fdb_add (struct oveth_dev * oveth, struct oveth_fdb * f)
{
	list_add_rcu (&(f->list), fdb_oveth_head (oveth, f->mac));
	list_add_rcu (&(f->chain), &(oveth->fdb_chain));
	return;
}

static void
oveth_fdb_del (struct oveth_fdb * f)
{
	list_del_rcu (&(f->list));
	list_del_rcu (&(f->chain));
}

static struct oveth_fdb_node *
oveth_fdb_find_node (struct oveth_fdb * f, __be32 node_id)
{
	struct oveth_fdb_node * fn;

	list_for_each_entry_rcu (fn, &(f->node_id_list), list) {
		if (fn->node_id == node_id)
			return fn;
	}
	return NULL;
}

static void
oveth_fdb_add_node (struct oveth_fdb * f, __be32 node_id)
{
	struct oveth_fdb_node * fn;

	fn = kmalloc (sizeof (struct oveth_fdb_node), GFP_KERNEL);
	memset (fn, 0, sizeof (struct oveth_fdb_node));
	fn->node_id = node_id;
	list_add_rcu (&(fn->list), &(f->node_id_list));
	f->node_id_count++;
	return;
}

static void
oveth_fdb_del_node (struct oveth_fdb * f, __be32 node_id)
{
	struct oveth_fdb_node * fn;
	fn = oveth_fdb_find_node (f, node_id);
	if (fn == NULL)
		return;
	list_del_rcu (&(fn->list));
	f->node_id_count--;
	return;
}


/*************************************
 *	module init and exit
 *************************************/


