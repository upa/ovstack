/*
 * Overlay Routing Stack 
 */

#ifndef DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>


#include "ovstack.h"
#include "ovstack_netlink.h"

#define OVSTACK_VERSION "0.0.2"
MODULE_VERSION (OVSTACK_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");


#define LIB_HASH_BITS	8
#define ORT_HASH_BITS	8

#define LIB_HASH_SIZE	(1 << LIB_HASH_BITS)
#define ORT_HASH_SIZE	(1 << ORT_HASH_BITS)

#define OVSTACK_DEFAULT_WEIGHT 50

/* IP + UDP. OVHDR is already pushed by upper driver */
#define OVSTACK_IPV4_HEADROOM (20 + 8)
#define OVSTACK_IPV6_HEADROOM (40 + 8)

static unsigned int ovstack_net_id;
static u32 ovstack_salt __read_mostly;


/* Overlay Node */
struct ov_node {
	struct list_head	list;
	struct list_head	chain;
	struct rcu_head		rcu;
	unsigned long 		update;

	__be32			node_id;

	struct list_head	ipv4_locator_list;
	u8			ipv4_locator_count;
	u32			ipv4_locator_weight_sum;

	struct list_head	ipv6_locator_list;
	u8			ipv6_locator_count;
	u32			ipv6_locator_weight_sum;
};
#define OV_NODE_NEXT(ovnode) \
	list_entry_rcu (ovnode->chain.next, struct ov_node, chain)

#define OV_NODE_LOC_COUNT_OPERATION(ovnode, af, op)	\
	switch (af) {					\
	case AF_INET :					\
		ovnode->ipv4_locator_count += op;	\
			break;				\
	case AF_INET6 :					\
		ovnode->ipv6_locator_count += op;	\
			break;				\
	}						\

#define OV_NODE_LOC_WEIGHT_OPERATION(ovnode, af, op) 	\
	switch (af) {					\
	case AF_INET :					\
		ovnode->ipv4_locator_weight_sum += op;	\
			break;				\
	case AF_INET6 :					\
		ovnode->ipv6_locator_weight_sum += op;	\
			break;				\
	}						\

/* Locator */
struct ov_locator {
	struct list_head	list;
	struct rcu_head		rcu;

	struct ov_node		* node;		/* parent node */
	u8			remote_ip_family;
	u8			priority;
	u8			weight;
	union {
		__be32		__loc_addr4[1];
		__be32		__loc_addr6[4];
	} remote_ip;
#define remote_ip4	remote_ip.__loc_addr4
#define remote_ip6	remote_ip.__loc_addr6
};
#define OV_LOCATOR_NODE_ID(loc) ((loc)->node->node_id)


/* Overlay Routing Table */
struct ortable {
	struct list_head	list;
	struct list_head	chain;
	struct rcu_head		rcu;
	
	__be32			ort_dst;	/* destination node id */
	unsigned long		ort_nxt_count;	/* number of nexthops */
	struct list_head	ort_nxts;	/* next hop list */
};

struct ortable_nexthop {
	struct list_head 	list;
	struct rcu_head		rcu;
	struct ortable		* ort;
	__be32			ort_nxt;	/* next hop node id */
};
#define ort_nxt_dst ort->ort_dst

/* Ovelay Network Application */
struct ovstack_app {

	u8     ov_app;			/* application number */
	struct ovstack_net * ovnet;
	struct ov_node * own_node;			/* self */
	struct list_head ortable_list[ORT_HASH_SIZE];	/* routing table */
	struct list_head ortable_chain;			/* rtable chain  */
	struct list_head node_list[LIB_HASH_SIZE];	/* node list hash */
	struct list_head node_chain;			/* node chain */

	/* callback function for when a app's packet is received */
	int (* app_recv_ops) (struct sock * sk, struct sk_buff * skb);
};

#define OVSTACK_APP_OWNNODE(app) (app->own_node)

#define OVSTACK_APP_FIRSTNODE(app)					\
	((app->node_chain.next == &app->node_chain) ? NULL :		\
	 (list_entry_rcu (app->node_chain.next, struct ov_node, chain)))

#define OVSTACK_APP_LASTNODE(app)					\
	((app->node_chain.prev == &app->node_chain) ? NULL :	\
	 (list_entry_rcu (app->node_chain.prev, struct ov_node, chain)))

#define OVSTACK_APP_NEXTNUM(ovnet, app)					\
	do {								\
		int _n;							\
		for (_n = app; _n < OVSTACK_APP_MAX; _n++) {	\
			if (OVSTACK_NET_APP (ovnet, _n)) {		\
				app = _n;				\
				break;					\
			}						\
		}							\
	} while (0)							\

#define OVSTACK_APP_FIRSTROUTE(app)					\
	((app->ortable_chain.next == &app->ortable_chain) ? NULL :	\
	 (list_entry_rcu (app->ortable_chain.next, struct ortable, chain)))

#define OVSTACK_APP_LASTROUTE(app)					\
	((app->ortable_chain.prev == &app->ortable_chain) ? NULL :	\
	 (list_entry_rcu (app->ortable_chain.prev, struct ortable, chain)))



/* per network namespace structure */
struct ovstack_net {
	struct socket * sock;				/* udp encap socket */
	struct ovstack_app * apps[OVSTACK_APP_MAX + 1];	/* ov applications */
};
#define OVSTACK_NET_APP(ovnet, ovapp) (ovnet->apps[ovapp])


/*****************************
 ****	node and locator operations
 *****************************/

static inline struct list_head *
node_head (struct ovstack_app * ovapp, __be32 node_id)
{
	return &(ovapp->node_list[hash_32 (node_id, LIB_HASH_BITS)]);
}

static inline struct ov_node * 
ov_node_create (__be32 node_id)
{
	struct ov_node * node;

	node = kmalloc (sizeof (struct ov_node), GFP_KERNEL);
	memset (node, 0, sizeof (struct ov_node));
	INIT_LIST_HEAD (&(node->ipv4_locator_list));
	INIT_LIST_HEAD (&(node->ipv6_locator_list));
	node->node_id = node_id;
	node->update = jiffies;

	return node;
}

static void
ov_node_destroy (struct ov_node * node)
{
	struct list_head * p, * tmp;
	struct ov_locator * loc;

	list_for_each_safe (p, tmp, &(node->ipv4_locator_list)) {
		loc = list_entry (p, struct ov_locator, list);
		list_del_rcu (p);
		kfree_rcu (loc, rcu);
	}
	list_for_each_safe (p, tmp, &(node->ipv6_locator_list)) {
		loc = list_entry (p, struct ov_locator, list);
		list_del_rcu (p);
		kfree_rcu (loc, rcu);
	}
	
	kfree_rcu (node, rcu);

	return;
}

static inline void
ov_node_add (struct ovstack_app * ovapp, struct ov_node * node)
{
	list_add_rcu (&(node->list), node_head (ovapp, node->node_id));
	list_add_rcu (&(node->chain), &(ovapp->node_chain));
	return;
}

static inline void
ov_node_delete (struct ov_node * node) 
{
	list_del_rcu (&(node->list));
	list_del_rcu (&(node->chain));
	ov_node_destroy (node);
	return;
}

static struct ov_node *
find_ov_node_by_id (struct ovstack_app * ovapp, __be32 node_id)
{
	struct ov_node * node;

	list_for_each_entry_rcu (node, node_head (ovapp, node_id), list) {
		if (node->node_id == node_id)
			return node;
	}

	return NULL;
}

static struct ov_locator *
find_ov_locator_by_addr (struct ov_node * node, __be32 * addr, u8 ai_family)
{
	struct ov_locator * loc;
	struct list_head * li;

	if (node == NULL)
		return NULL;

	li = (ai_family == AF_INET) ? 
		&(node->ipv4_locator_list) : &(node->ipv6_locator_list);

	list_for_each_entry_rcu (loc, li, list) {
		if (ai_family == AF_INET) {
			if (memcmp (addr, loc->remote_ip4, 4) == 0)
				return loc;
		} else 
			if (memcmp (addr, loc->remote_ip6, 6) == 0)
				return loc;
	}

	return NULL;
}

static struct ov_locator *
find_ov_locator_by_hash (struct ov_node * node, u32 hash, u8 ai_family)
{
	struct list_head * li;
	struct ov_locator * loc;

	if (node->ipv4_locator_count == 0 && node->ipv6_locator_count == 0)
		return NULL;

	/* both */
	if (ai_family == AF_UNSPEC) {
		hash %= (node->ipv4_locator_weight_sum + 
			 node->ipv6_locator_weight_sum);
		li = &(node->ipv4_locator_list);
		list_for_each_entry_rcu (loc, li, list) {
			if (hash <= loc->weight)
				return loc;
			hash -= loc->weight;
		}
		li = &(node->ipv6_locator_list);
		list_for_each_entry_rcu (loc, li, list) {
			if (hash <= loc->weight)
				return loc;
			hash -= loc->weight;
		}
		return NULL;
	}

	/* ipv4 or ipv6 */
	if (ai_family == AF_INET && node->ipv4_locator_count) {
		li = &(node->ipv4_locator_list);
		hash %=	node->ipv4_locator_weight_sum;
	} else if (ai_family == AF_INET6 && node->ipv6_locator_count) {
		li = &(node->ipv6_locator_list);
		hash %=	node->ipv6_locator_weight_sum;
	} else 
		return NULL;
	
	list_for_each_entry_rcu (loc, li, list) {
		if (hash <= loc->weight)
			return loc;
		hash -= loc->weight;
	}

	return NULL;
}

static void
ov_locator_add (struct ov_node * node, struct ov_locator * loc)
{
	struct list_head * li;

	li = (loc->remote_ip_family == AF_INET) ?
		&(node->ipv4_locator_list) : &(node->ipv6_locator_list);

	loc->node = node;
	list_add_rcu (&(loc->list), li);
	OV_NODE_LOC_COUNT_OPERATION (node, loc->remote_ip_family, 1);
	OV_NODE_LOC_WEIGHT_OPERATION (node, loc->remote_ip_family, 
				      loc->weight);
	node->update = jiffies;

	return;
}

static void
ov_locator_delete (struct ov_node * node, struct ov_locator * loc)
{
	loc->node = NULL;
	list_del_rcu (&(loc->list));
	OV_NODE_LOC_COUNT_OPERATION (node, loc->remote_ip_family, -1);
	OV_NODE_LOC_WEIGHT_OPERATION (node, loc->remote_ip_family, 
				      -loc->weight);
	node->update = jiffies;

	return;
}

static void
ov_locator_weight_set (struct ov_locator * loc, u8 weight)
{
	struct ov_node * node = loc->node;

	if (!node) {
		pr_debug ("%s: locator has node null pointer\n", __func__);
		return;
	}
	
	OV_NODE_LOC_WEIGHT_OPERATION (node, loc->remote_ip_family,
				      +weight);
	OV_NODE_LOC_WEIGHT_OPERATION (node, loc->remote_ip_family,
				      -loc->weight);
	loc->weight = weight;

	return;
}


/***************************
 *** xmit related locator operations
 ***************************/

static void
ovstack_sock_free (struct sk_buff * skb)
{
	sock_put (skb->sk);
}

static void
ovstack_set_owner (struct net * net, struct sk_buff * skb)
{
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct sock * sk = ovnet->sock->sk;

	skb_orphan (skb);
	sock_hold (sk);
	skb->sk = sk;
	skb->destructor = ovstack_sock_free;
}

static int
ovstack_ipv4_loc_count (struct net * net, u8 app)
{
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}
	return OVSTACK_APP_OWNNODE(ovapp)->ipv4_locator_count;
}

static int
ovstack_ipv6_loc_count (struct net * net, u8 app)
{
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}
	return OVSTACK_APP_OWNNODE(ovapp)->ipv6_locator_count;
}

static int
ovstack_src_loc (void * addr, struct net * net, u8 app, u32 hash)
{
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	loc = find_ov_locator_by_hash (OVSTACK_APP_OWNNODE (ovapp),
				       hash, AF_UNSPEC);
	if (loc == NULL)
		return 0;

	memcpy (addr, &(loc->remote_ip),
		(loc->remote_ip_family == AF_INET) ?
		sizeof (struct in_addr) : sizeof (struct in6_addr));

	return loc->remote_ip_family;
}

#if 0
static int
ovstack_dst_loc (void * addr, struct net * net, u8 app, 
		 __be32 node_id, u32 hash)
{
	struct ov_node * node;
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	node = find_ov_node_by_id (ovapp, node_id);
	if (!node)
		return 0;

	loc = find_ov_locator_by_hash (node, hash, AF_UNSPEC);
	if (loc == NULL)
		return 0;

	memcpy (addr, &(loc->remote_ip),
		(loc->remote_ip_family == AF_INET) ?
		sizeof (struct in_addr) : sizeof (struct in6_addr));

	return loc->remote_ip_family;
}
#endif

static int
ovstack_ipv4_src_loc (void * addr, struct net * net, u8 app, u32 hash)
{
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	loc = find_ov_locator_by_hash (OVSTACK_APP_OWNNODE (ovapp),
				       hash, AF_INET);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip4, sizeof (struct in_addr));

	return AF_INET;
}

static int
ovstack_ipv4_dst_loc (void * addr, 
		      struct net * net, u8 app, __be32 node_id, u32 hash)
{
	struct ov_node * node;
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	node = find_ov_node_by_id (ovapp, node_id);
	if (unlikely (!node)) {
		pr_debug ("%s: node id %pI4 does not exist\n", 
			  __func__,  &node_id);
		return 0;
	}

	loc = find_ov_locator_by_hash (node, hash, AF_INET);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip4, sizeof (struct in_addr));

	return AF_INET;
}

static int
ovstack_ipv6_src_loc (void * addr, struct net * net, u8 app, u32 hash)
{
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	loc = find_ov_locator_by_hash (OVSTACK_APP_OWNNODE (ovapp),
				       hash, AF_INET6);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip6, sizeof (struct in6_addr));

	return AF_INET6;
}

static int
ovstack_ipv6_dst_loc (void * addr, 
		      struct net * net, u8 app, __be32 node_id, u32 hash)
{
	struct ov_node * node;
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	node = find_ov_node_by_id (ovapp, node_id);
	if (unlikely (!node)) {
		pr_debug ("%s: node id %pI4 does not exist\n", 
			  __func__, &node_id);
		return 0;
	}

	loc = find_ov_locator_by_hash (node, hash, AF_INET6);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip6, sizeof (struct in6_addr));

	return AF_INET6;
}

static inline int
ov_nexthop_rpf_check (struct sk_buff * skb, struct net * net, 
		      u8 app, __be32 node_id)
{
	struct iphdr * iph;
	struct ipv6hdr * ip6h;
	struct ov_node * node;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}

	node = find_ov_node_by_id (ovapp, node_id);
	if (!node)
		return 0;

	if (skb->protocol == htons (ETH_P_IP)) {
		iph = (struct iphdr *) skb_network_header (skb);
		if (find_ov_locator_by_addr (node, (__be32 *) &iph->saddr, 
					     AF_INET))
			return 1;
	}else if (skb->protocol == htons (ETH_P_IPV6)) {
		ip6h = (struct ipv6hdr *) skb_network_header (skb);
		if (find_ov_locator_by_addr (node, (__be32 *) &ip6h->saddr, 
					     AF_INET6))
			return 1;
	} else 
		pr_debug ("%s: invalid protocol %d", __func__, skb->protocol);
	
	return 0;
}



/*****************************
 ****	Routing table operations
 *****************************/

static inline struct list_head *
ortable_head (struct ovstack_app * ovapp, __be32 dst_node_id)
{
	return &(ovapp->ortable_list[hash_32 (dst_node_id, ORT_HASH_BITS)]);
}

static struct ortable * 
find_ortable (struct ovstack_app * ovapp, __be32 dst_node_id)
{
	struct ortable * ort;

	list_for_each_entry_rcu (ort, ortable_head (ovapp, dst_node_id), list) {
		if (ort->ort_dst == dst_node_id) 
			return ort;
	}

	return NULL;
}

int
ortable_add (struct ovstack_app * ovapp, __be32 dst_node_id, __be32 nxt_node_id)
{
	struct ortable * ort;
	struct ortable_nexthop * ortnxt;

	ort = find_ortable (ovapp, dst_node_id);
	if (!ort) {
		ort = kmalloc (sizeof (struct ortable), GFP_KERNEL);
		memset (ort, 0, sizeof (struct ortable));
		ort->ort_dst = dst_node_id;
		INIT_LIST_HEAD (&(ort->ort_nxts));
		list_add_rcu (&(ort->list), ortable_head (ovapp, dst_node_id));
		list_add_rcu (&(ort->chain), &(ovapp->ortable_chain));
	}

	list_for_each_entry_rcu (ortnxt, &(ort->ort_nxts), list) {
		if (ortnxt->ort_nxt == nxt_node_id) {
			pr_debug ("%s: dest node %pI4 already "
				  "has next hop %pI4", __func__, 
				  &dst_node_id, &nxt_node_id);
			return -EEXIST;
		}
	}
	
	ortnxt = kmalloc (sizeof (struct ortable_nexthop), GFP_KERNEL);
	memset (ortnxt, 0, sizeof (struct ortable_nexthop));
	ortnxt->ort_nxt = nxt_node_id;
	ortnxt->ort = ort;
	list_add_rcu (&(ortnxt->list), &(ort->ort_nxts));
	ort->ort_nxt_count++;

	return 1;
}


int
ortable_delete (struct ovstack_app * ovapp, 
		__be32 dst_node_id, __be32 nxt_node_id)
{
	struct list_head * p, * tmp;
	struct ortable * ort;
	struct ortable_nexthop * ortnxt;

	ort = find_ortable (ovapp, dst_node_id);
	if (!ort) {
		pr_debug ("%s: dst node %pI4 does not exist", 
			  __func__, &dst_node_id);
		return -ENOENT;
	}

	list_for_each_safe (p, tmp, &(ort->ort_nxts)) {
		ortnxt = list_entry (p, struct ortable_nexthop, list);
		if (ortnxt->ort_nxt == nxt_node_id) {
			list_del_rcu (p);
			kfree_rcu (ortnxt, rcu);
			ort->ort_nxt_count--;

			if (ort->ort_nxt_count == 0) {
				list_del_rcu (&(ort->list));
				list_del_rcu (&(ort->chain));
				kfree_rcu (ort, rcu);
			}
			return 1;
		}
	}

	pr_debug ("%s: dest node %pI4 does not have next hop %pI4", 
		  __func__, &dst_node_id, &nxt_node_id);

	return -ENOENT;
}

int
ortable_destroy (struct ortable * ort)
{
	struct list_head * p, * tmp;
	struct ortable_nexthop * ortnxt;

	list_for_each_safe (p, tmp, &(ort->ort_nxts)) {
		ortnxt = list_entry (p, struct ortable_nexthop, list);
		list_del_rcu (p);
		kfree_rcu (ortnxt, rcu);
		ort->ort_nxt_count--;
	}
	
	list_del_rcu (&(ort->list));
	list_del_rcu (&(ort->chain));
	kfree_rcu (ort, rcu);

	return 0;
}

/*****************************
 ****	pernet operations
 *****************************/

static int
ovstack_udp_encap_recv (struct sock * sk, struct sk_buff * skb)
{
	/*
	 * call function pointer according to ovstack protocl number
	 */

	struct ovhdr * ovh;
	struct net * net = sock_net (sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * ownnode;

	/* pop off outer UDP header */
	__skb_pull (skb, sizeof (struct udphdr));

	/* need ov and inner ether header to present */
	if (!pskb_may_pull (skb, sizeof (struct ovhdr))) {
		skb_push (skb, sizeof (struct udphdr));
		return 1;
	}

	ovh = (struct ovhdr *) skb->data;

	/* application check */
	if (!OVSTACK_NET_APP (ovnet, ovh->ov_app)) {
		netdev_dbg (skb->dev, "unknown application %d\n", ovh->ov_app);
		return 0;
	}
	ovapp = OVSTACK_NET_APP (ovnet, ovh->ov_app);
	ownnode = OVSTACK_APP_OWNNODE (ovapp);

	/* this packet is not for me. routing ! */
	if (ovh->ov_dst != ownnode->node_id) {
		ovh->ov_ttl--;
		if (ovh->ov_ttl == 0) 
			return 0;

		if (!skb->encapsulation)
			skb->encapsulation = 1;

		ovstack_xmit (skb, skb->dev);
		return 0;
	}

	/* callback function for overlay applicaitons */
	if (ovapp->app_recv_ops == NULL) {
		netdev_dbg (skb->dev, "application %d does not "
			    "register callback function\n", ovh->ov_app);
		return 0;
	}

	return ovapp->app_recv_ops (sk, skb);
}

static int
ovstack_udp_encap_mcast_recv (struct sock * sk, struct sk_buff * skb)
{
	/*
	 * Destination of packet is not for me. but send this packet to 
	 * upper layer according to ov routing table.
	 */

	struct ovhdr * ovh;
	struct net * net = sock_net (sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	ovh = (struct ovhdr *) skb->data;

	/* application check */
	if (!OVSTACK_NET_APP (ovnet, ovh->ov_app)) {
		netdev_dbg (skb->dev, "unknown application %d\n", ovh->ov_app);
		return 0;
	}
	ovapp = OVSTACK_NET_APP (ovnet, ovh->ov_app);

	/* do not check destination node id */

	/* callback function for overlay applicaitons */
	if (ovapp->app_recv_ops == NULL) {
		netdev_dbg (skb->dev, "application %d does not "
			    "register callback function\n", ovh->ov_app);
		return 0;
	}

	return ovapp->app_recv_ops (sk, skb);
	
}


static inline netdev_tx_t
ovstack_xmit_ipv4_loc (struct sk_buff * skb, struct net_device * dev,
		       struct in_addr * saddr, struct in_addr * daddr)
{
	int rc;
	struct iphdr * iph;
	struct udphdr * uh;
	struct flowi4 fl4;
	struct rtable * rt;

	memset (&fl4, 0, sizeof (fl4));
	fl4.saddr = *((__be32 *)(saddr));
	fl4.daddr = *((__be32 *)(daddr));

	rt = ip_route_output_key (dev_net (dev), &fl4);
	if (IS_ERR (rt)) {
		netdev_dbg (dev, "no route to %pI4\n", daddr);
		dev->stats.tx_carrier_errors++;
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}
	
	memset (&(IPCB (skb)->opt), 0, sizeof (IPCB (skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	skb_dst_drop (skb);
	skb_dst_set (skb, &rt->dst);
	
	/* setup udp header and ip header */
	if (skb_cow_head (skb, OVSTACK_IPV4_HEADROOM)) {
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}
	
	__skb_push (skb, sizeof (struct udphdr));
	skb_reset_transport_header (skb);
	uh 		= udp_hdr (skb);
	uh->dest	= htons (OVSTACK_PORT);
	uh->source	= htons (OVSTACK_PORT);
	uh->len		= htons (skb->len);
	uh->check	= 0;

	__skb_push (skb, sizeof (struct iphdr));
	skb_reset_network_header (skb);
	iph		= ip_hdr (skb);
	iph->version	= 4;
	iph->ihl	= sizeof (struct iphdr) >> 2;
	iph->frag_off	= 0;
	iph->protocol	= IPPROTO_UDP;
	iph->tos	= 0;
	iph->saddr	= *((__be32 *)(saddr));
	iph->daddr	= *((__be32 *)(daddr));
	iph->ttl	= 16;

	ovstack_set_owner (dev_net (dev), skb);
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_HOST;

	rc = ip_local_out (skb);

	if (net_xmit_eval (rc) == 0) 
		return rc;
	else {
		dev->stats.tx_errors++;
		dev->stats.tx_aborted_errors++;
	}
	
	return NETDEV_TX_OK;
}

static inline netdev_tx_t
ovstack_xmit_ipv6_loc (struct sk_buff * skb, struct net_device * dev,
		       struct in6_addr * saddr, struct in6_addr * daddr)
{
	int rc;
	struct ipv6hdr * ip6h;
	struct udphdr * uh;
	struct flowi6 fl6;
	struct dst_entry * dst;
	
	memset (&fl6, 0, sizeof (fl6));
	fl6.saddr = *saddr;
	fl6.daddr = *daddr;

	dst = ip6_route_output (dev_net (dev), skb->sk, &fl6);
	if (dst->error) {
		netdev_dbg (dev, "no route to %pI6\n", daddr);
		dev->stats.tx_carrier_errors++;
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (dst->dev == dev){
		netdev_dbg (dev, "circular route to %pI6\n", daddr);
		dst_free (dst);
		dev->stats.collisions++;
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

        memset (&(IPCB (skb)->opt), 0, sizeof (IPCB (skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);

	skb_dst_drop (skb);
	skb_dst_set (skb, dst);

	/* setup udp hdaer and ipv6 header */
	if (skb_cow_head (skb, OVSTACK_IPV6_HEADROOM)) {
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	__skb_push (skb, sizeof (struct udphdr));
	skb_reset_transport_header (skb);
	uh 		= udp_hdr (skb);
	uh->dest	= htons (OVSTACK_PORT);
	uh->source	= htons (OVSTACK_PORT);
	uh->len		= htons (skb->len);
	uh->check	= 0;

	__skb_push (skb, sizeof (struct ipv6hdr));
	skb_reset_network_header (skb);
	ip6h			= ipv6_hdr (skb);
	ip6h->version		= 6;
	ip6h->priority		= 0;
	ip6h->flow_lbl[0]	= 0l;
	ip6h->flow_lbl[1]	= 0l;
	ip6h->flow_lbl[2]	= 0l;
	ip6h->payload_len	= htons (skb->len);
	ip6h->nexthdr		= IPPROTO_UDP;
	ip6h->daddr		= *daddr;
	ip6h->saddr		= *saddr;
	ip6h->hop_limit		= 16;

	ovstack_set_owner (dev_net (dev), skb);
	skb->pkt_type = PACKET_HOST;

	rc = ip6_local_out (skb);

	if (net_xmit_eval (rc) == 0) {
		return rc;
	} else {
		dev->stats.tx_errors++;
		dev->stats.tx_aborted_errors++;
	}

	return NETDEV_TX_OK;
}

static inline netdev_tx_t
ovstack_xmit_node (struct sk_buff * skb, struct net_device * dev, __be32 nxt)
{
	int ret;
	u8 loc4count = 0, loc6count = 0, ai_family = 0;
	struct net * net = dev_net (dev);
	struct ovhdr * ovh;
	
	union addr {
		struct in_addr addr4;
		struct in6_addr addr6;
	} src_addr, dst_addr;

	ovh = (struct ovhdr *) skb->data;

	/* Nexthop only rpf check.
	 * if a node that send this packet same as next hop node,
	 * Dont't forward the packet. (for aovid multicast loop)
	 */
	if (skb->encapsulation && 
	    ov_nexthop_rpf_check (skb, net, ovh->ov_app, nxt))
		goto noroute_drop;

	if (!skb->encapsulation) {
		skb_reset_inner_headers (skb);
		skb->encapsulation = 1;
	}

	loc4count = ovstack_ipv4_loc_count (net, ovh->ov_app);
	loc6count = ovstack_ipv6_loc_count (net, ovh->ov_app);

	/* set src locator address */
	if (loc4count && loc6count)
		ai_family = ovstack_src_loc (&src_addr, net, 
					     ovh->ov_app, ovh->ov_hash);
	else if (loc4count)
		ai_family = ovstack_ipv4_src_loc (&src_addr, net, 
						  ovh->ov_app, ovh->ov_hash);
	else if (loc6count)
		ai_family = ovstack_ipv6_src_loc (&src_addr, net, 
						  ovh->ov_app, ovh->ov_hash);
	else 
		goto noroute_drop;
	
	/* set dst locator address */
	if (ai_family == AF_INET) {
		ret = ovstack_ipv4_dst_loc (&dst_addr, net, ovh->ov_app,
					    nxt, ovh->ov_hash);
		if (!ret)
			goto noroute_drop;

		return ovstack_xmit_ipv4_loc (skb, dev, &src_addr.addr4,
					      &dst_addr.addr4);

	} else if (ai_family == AF_INET6) {
		ret = ovstack_ipv6_dst_loc (&dst_addr, net, ovh->ov_app,
					    nxt, ovh->ov_hash);
		if (!ret)
			goto noroute_drop;

		return ovstack_xmit_ipv6_loc (skb, dev, &src_addr.addr6,
					      &dst_addr.addr6);
	} else  {
		pr_debug ("%s: unknwon locator family %d", 
			  __func__, ai_family);
		goto error_drop;
	}
	
error_drop:
	dev->stats.tx_errors++;
	dev->stats.tx_aborted_errors++;

noroute_drop:
	return NETDEV_TX_OK;
}

inline netdev_tx_t 
ovstack_xmit (struct sk_buff * skb, struct net_device * dev)
{
	int ret;
	struct ovhdr * ovh;
	struct net * net = dev_net (dev);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ortable * ort;
	struct ortable_nexthop * ortnxt;
	struct sk_buff * mskb;

	ovh = (struct ovhdr *) skb->data;
	ovapp = OVSTACK_NET_APP (ovnet, ovh->ov_app);

	if (!ovapp) {
		pr_debug ("%s: unregisterd ovstack app %d", 
			  __func__, ovh->ov_app);
		return NETDEV_TX_OK;
	}

	ort = find_ortable (ovapp, ovh->ov_dst);
	if (!ort || ort->ort_nxt_count == 0) {
		pr_debug ("%s: no route to host %pI4", __func__, &ovh->ov_dst);
		return NETDEV_TX_OK;
	}


	list_for_each_entry_rcu (ortnxt, &(ort->ort_nxts), list) {

		/* mcast packet  */
		if (OVSTACK_APP_OWNNODE (ovapp)->node_id != ovh->ov_src &&
		    OVSTACK_APP_OWNNODE (ovapp)->node_id == ortnxt->ort_nxt) {
			/* to me and not from me -> recv */
			mskb = skb_copy (skb, GFP_ATOMIC);
			if (!mskb) {
				printk (KERN_INFO "ovstack : no buffer space "
					"available for mcast packet\n");
				goto skip;
			}
			ovstack_udp_encap_mcast_recv (ovnet->sock->sk, mskb);
			goto skip;
		}

		/* mcast echo */
		if (OVSTACK_APP_OWNNODE (ovapp)->node_id == ovh->ov_src &&
		    OVSTACK_APP_OWNNODE (ovapp)->node_id == ortnxt->ort_nxt) {
			/* to me and from me -> drop */
			goto skip;
		}

		if (ort->ort_nxt_count > 1) 
			mskb = skb_clone (skb, GFP_ATOMIC);
		else 
			mskb = skb;

		if (unlikely (!mskb)) {
			dev->stats.tx_errors++;
			dev->stats.tx_aborted_errors++;
			printk (KERN_ERR "ovstack: failed to alloc skb\n");
			goto skip;
		}

		ret = ovstack_xmit_node (mskb, dev, ortnxt->ort_nxt);

		if (ret != NETDEV_TX_OK) 
			return ret;

	skip:;
	}

	return NETDEV_TX_OK;
}
EXPORT_SYMBOL (ovstack_xmit);

static __net_init int
ovstack_init_net (struct net * net)
{
	int n, rc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct sock * sk;
	struct sockaddr_in6 ovstack_addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons (OVSTACK_PORT),
		.sin6_addr	= IN6ADDR_ANY_INIT,
	};
	
	memset (ovnet, 0, sizeof (struct ovstack_net));

	for (n = 0; n < OVSTACK_APP_MAX + 1; n++) 
		ovnet->apps[n] = NULL;

	/* udp encapsulation socket init */
	rc = sock_create_kern (AF_INET6, SOCK_DGRAM, 
			       IPPROTO_UDP, &(ovnet->sock));
	if (rc < 0) {
		pr_debug ("UDP socket create failed\n");
		return rc;
	}
	
	sk = ovnet->sock->sk;
	sk_change_net (sk, net);

	rc = kernel_bind (ovnet->sock, (struct sockaddr *)&(ovstack_addr),
			  sizeof (ovstack_addr));
	if (rc < 0) {
		pr_debug ("bind for UDP socket %pI6:%u (%d) failed\n",
			  &(ovstack_addr.sin6_addr),
			  ntohs (ovstack_addr.sin6_port), rc);
		sk_release_kernel (sk);
		ovnet->sock = NULL;
		return rc;
	}

	udp_sk (sk)->encap_type = 1;
	udp_sk (sk)->encap_rcv = ovstack_udp_encap_recv;
	udp_encap_enable ();

	return 0;
}

static __net_exit void
ovstack_exit_net (struct net * net)
{
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	/* destroy socket */
	if (ovnet->sock) {
		sk_release_kernel (ovnet->sock->sk);
		ovnet->sock = NULL;
	}

	/* destroy apps */
	
	return;
}


static struct pernet_operations ovstack_net_ops = {
	.init	= ovstack_init_net,
	.exit	= ovstack_exit_net,
	.id	= &ovstack_net_id,
	.size	= sizeof (struct ovstack_net),
};


/*****************************
 ****	Generic Netwolink Operations
 *****************************/


static struct genl_family ovstack_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= OVSTACK_GENL_NAME,
	.version	= OVSTACK_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= OVSTACK_ATTR_MAX,
};


static int
ovstack_nl_cmd_node_id_set (struct sk_buff * skb, struct genl_info * info)
{
	u8 app;
	__be32 node_id;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_NODE_ID]) {
		pr_debug ("%s: node id is not specified\n", __func__);
		return -EINVAL;
	}
	node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NODE_ID]);

	OVSTACK_APP_OWNNODE (OVSTACK_NET_APP(ovnet, app))->node_id = node_id;

	return 0;
}

static int
ovstack_nl_cmd_locator_add (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr;
	u8 app, ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * ownnode;
	struct ov_locator * loc;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	addr = NULL;
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		ai_family = AF_INET;
		addr = (__be32 *)&addr4;
		addr4.s_addr = nla_get_be32 
			(info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]);
	}
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		ai_family = AF_INET6;
		addr = (__be32 *)&addr6;
		nla_memcpy (&addr6, info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR],
			    sizeof (addr6));
	}
	if (addr == NULL) {
		pr_debug ("%s: ip address is not specified\n", __func__);
		return -EINVAL;
	}

	if (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) {
		weight = nla_get_u8 (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);
		if (weight == 0) {
			pr_debug ("%s: weight must be lager than 0", __func__);
			return -EINVAL;
		}
	}

	/* add new locator */
	ovapp = OVSTACK_NET_APP (ovnet, app);
	ownnode = OVSTACK_APP_OWNNODE (ovapp);
	loc = find_ov_locator_by_addr (ownnode, addr, ai_family);
	if (loc != NULL) {
		pr_debug ("%s: locator exists\n", __func__);
		return -EEXIST;
	}
	loc = kmalloc (sizeof (struct ov_locator), GFP_KERNEL);
	memset (loc, 0, sizeof (struct ov_locator));
	loc->node = ownnode;
	loc->remote_ip_family = ai_family;
	loc->weight = weight;
	memcpy (&loc->remote_ip, addr, 
		(ai_family == AF_INET) ? sizeof (struct in_addr) :
		sizeof (struct in6_addr));
	ov_locator_add (ownnode, loc);

	return 0;
}

static int
ovstack_nl_cmd_locator_delete (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr;
	u8 app, ai_family;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * ownnode;
	struct ov_locator * loc;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	addr = NULL;
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		ai_family = AF_INET;
		addr = (__be32 *)&addr4;
		addr4.s_addr = nla_get_be32 
			(info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]);
	}
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		ai_family = AF_INET6;
		addr = (__be32 *)&addr6;
		nla_memcpy (&addr6, info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR],
			    sizeof (addr6));
	}
	if (addr == NULL) {
		pr_debug ("%s: ip address is not specified\n", __func__);
		return -EINVAL;
	}

	ovapp = OVSTACK_NET_APP (ovnet, app);
	ownnode = OVSTACK_APP_OWNNODE (ovapp);

	/* delete locator */
	loc = find_ov_locator_by_addr (ownnode, addr, ai_family);
	if (loc == NULL) {
		pr_debug ("%s: locator does not exist\n", __func__);
		return -ENOENT;
	}
	ov_locator_delete (ownnode, loc);
	kfree_rcu (loc, rcu);

	return 0;
}

static int
ovstack_nl_cmd_locator_weight_set (struct sk_buff * skb, 
				   struct genl_info * info)
{
	__be32 * addr;
	u8 app, ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * ownnode;
	struct ov_locator * loc;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	addr = NULL;
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		ai_family = AF_INET;
		addr = (__be32 *)&addr4;
		addr4.s_addr = nla_get_be32 
			(info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]);
	}
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		ai_family = AF_INET6;
		addr = (__be32 *)&addr6;
		nla_memcpy (&addr6, info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR],
			    sizeof (addr6));
	}
	if (addr == NULL) {
		pr_debug ("%s: ip address is not specified\n", __func__);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) {
		pr_debug ("%s: weight is not specified\n", __func__);
		return -EINVAL;
	}
	weight = nla_get_u8 (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);
	if (weight == 0) {
		pr_debug ("%s: weight must be larger than 0", __func__);
		return -EINVAL;
	}


	/* set locator weight */
	ovapp = OVSTACK_NET_APP (ovnet, app);
	ownnode = OVSTACK_APP_OWNNODE (ovapp);

	loc = find_ov_locator_by_addr (ownnode, addr, ai_family);
	if (loc == NULL) {
		pr_debug ("%s: locator does not exist\n", __func__);
		return -ENOENT;
	}
	ov_locator_weight_set (loc, weight);

	return 0;
}

static int
ovstack_nl_cmd_node_add (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr, node_id;
	u8 app, ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * node;
	struct ov_locator * loc;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_NODE_ID]) {
		pr_debug ("%s: node id is not specified\n", __func__);
		return -EINVAL;
	}
	node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NODE_ID]);

	addr = NULL;
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		ai_family = AF_INET;
		addr = (__be32 *)&addr4;
		addr4.s_addr = nla_get_be32 
			(info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]);
	}
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		ai_family = AF_INET6;
		addr = (__be32 *)&addr6;
		nla_memcpy (&addr6, info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR],
			    sizeof (addr6));
	}
	if (addr == NULL) {
		pr_debug ("%s: ip address is not specified\n", __func__);
		return -EINVAL;
	}

	if (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) {
		weight = nla_get_u8 (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);
		if (weight == 0) {
			pr_debug ("%s: weight must be lager than 0", __func__);
			return -EINVAL;
		}
	}

	/* add new locator to node */
	ovapp = OVSTACK_NET_APP (ovnet, app);
	node = find_ov_node_by_id (ovapp, node_id);
	if (node == NULL) {
		node = ov_node_create (node_id);
		ov_node_add (ovapp, node);
	}

	loc = find_ov_locator_by_addr (node, addr, ai_family);
	if (loc == NULL) {
		loc = kmalloc (sizeof (struct ov_locator), GFP_KERNEL);
		memset (loc, 0, sizeof (struct ov_locator));
		loc->node = node;
		loc->remote_ip_family = ai_family;
		loc->weight = weight;
		memcpy (&loc->remote_ip, addr, 
			(ai_family == AF_INET) ? sizeof (struct in_addr) :
			sizeof (struct in6_addr));
		ov_locator_add (node, loc);
	} else {
		pr_debug ("%s: locator exists in node id %pI4\n", 
			  __func__, addr);
		return -EEXIST;
	}

	return 0;
}

static int
ovstack_nl_cmd_node_delete (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr, node_id;
	u8 app, ai_family;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * node;
	struct ov_locator * loc;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_NODE_ID]) {
		pr_debug ("%s: node id is not specified\n", __func__);
		return -EINVAL;
	}
	node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NODE_ID]);

	addr = NULL;
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		ai_family = AF_INET;
		addr = (__be32 *)&addr4;
		addr4.s_addr = nla_get_be32 
			(info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]);
	}
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		ai_family = AF_INET6;
		addr = (__be32 *)&addr6;
		nla_memcpy (&addr6, info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR],
			    sizeof (addr6));
	}

	/* delete locator from node */
	ovapp = OVSTACK_NET_APP (ovnet, app);
	node = find_ov_node_by_id (ovapp, node_id);
	if (node == NULL) {
		pr_debug ("%s: node id %pI4 does not exist\n", __func__,
			  &node_id);
		return -ENOENT;
	}

	/* if locator is not specified, delete this node */
	if (addr == NULL) {
		ov_node_delete (node);
		goto out;
	}

	loc = find_ov_locator_by_addr (node, addr, ai_family);
	if (loc == NULL) {
		pr_debug ("%s: node id %pI4 does not have the locator\n",
			  __func__, &node_id);
		return -ENOENT;
	}

	ov_locator_delete (node, loc);
	kfree_rcu (loc, rcu);

out:
	return 0;
}

static int
ovstack_nl_cmd_node_weight_set (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr, node_id;
	u8 app, ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * node;
	struct ov_locator * loc;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified\n", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist\n", __func__, app);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_NODE_ID]) {
		pr_debug ("%s: node id is not specified\n", __func__);
		return -EINVAL;
	}
	node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NODE_ID]);

	addr = NULL;
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		ai_family = AF_INET;
		addr = (__be32 *)&addr4;
		addr4.s_addr = nla_get_be32 
			(info->attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]);
	}
	if (info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		ai_family = AF_INET6;
		addr = (__be32 *)&addr6;
		nla_memcpy (&addr6, info->attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR],
			    sizeof (addr6));
	}
	if (addr == NULL) {
		pr_debug ("%s: ip address is not specified\n", __func__);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) {
		pr_debug ("%s: weight is not specified\n", __func__);
		return -EINVAL;
	}
	weight = nla_get_u8 (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);
	if (weight == 0) {
		pr_debug ("%s: weight must be lager than 0", __func__);
		return -EINVAL;
	}
	

	/* set weight */
	ovapp = OVSTACK_NET_APP (ovnet, app);
	node = find_ov_node_by_id (ovapp, node_id);
	if (node == NULL) {
		pr_debug ("%s: node id %pI4 does not exist\n",
			  __func__, &node_id);
		return -ENOENT;
	}

	loc = find_ov_locator_by_addr (node, addr, ai_family);
	if (loc == NULL) {
		pr_debug ("%s: node id %pI4 does not have "
			  "specified locator\n", __func__, &node_id);
		return -ENOENT;
	}

	ov_locator_weight_set (loc, weight);

	return 0;
}

static int
ovstack_nl_app_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		     int cmd, struct ovstack_app * ovapp)
{
	void * hdr;
	struct ov_node * ownnode;
	
	if (!ovapp) 
		return -1;

	ownnode = OVSTACK_APP_OWNNODE (ovapp);
	hdr = genlmsg_put (skb, pid, seq, &ovstack_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	if (nla_put_u8 (skb, OVSTACK_ATTR_APP_ID, ovapp->ov_app) ||
	    nla_put_be32 (skb, OVSTACK_ATTR_NODE_ID, ownnode->node_id))
		goto err_out;

	return genlmsg_end (skb, hdr);

err_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}

static int
ovstack_nl_cmd_app_id_dump (struct sk_buff * skb,
			    struct netlink_callback * cb)
{
	u8 app;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	app = cb->args[1];

	if (!OVSTACK_NET_APP (ovnet, app))
		OVSTACK_APP_NEXTNUM (ovnet, app);

	if (app == OVSTACK_APP_MAX)
		goto out;

	ovapp = OVSTACK_NET_APP (ovnet, app);
	ovstack_nl_app_send (skb, NETLINK_CB (cb->skb).portid,
			     cb->nlh->nlmsg_seq, NLM_F_MULTI,
			     OVSTACK_CMD_APP_ID_GET, ovapp);

	cb->args[1] = app + 1;
out:
	return skb->len;
}

static int
ovstack_nl_cmd_node_id_dump (struct sk_buff * skb,
			    struct netlink_callback * cb)
{
	u8 app;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	app = cb->args[1];

	if (!OVSTACK_NET_APP (ovnet, app))
		OVSTACK_APP_NEXTNUM (ovnet, app);

	if (app == OVSTACK_APP_MAX)
		goto out;

	ovapp = OVSTACK_NET_APP (ovnet, app);
	ovstack_nl_app_send (skb, NETLINK_CB (cb->skb).portid,
			     cb->nlh->nlmsg_seq, NLM_F_MULTI,
			     OVSTACK_CMD_NODE_ID_GET, ovapp);

	cb->args[1] = app + 1;
out:
	return skb->len;
}


static int
ovstack_nl_locator_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
			 int cmd, u8 app, struct ov_locator * loc)
{
	void * hdr;
	struct ov_node * node;

	if (!skb || !loc) 
		return -1;

	node = loc->node;
	hdr = genlmsg_put (skb, pid, seq, &ovstack_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	if (nla_put_u8 (skb, OVSTACK_ATTR_APP_ID, app) ||
	    nla_put_be32 (skb, OVSTACK_ATTR_NODE_ID, node->node_id) ||
	    nla_put_u8 (skb, OVSTACK_ATTR_LOCATOR_WEIGHT, loc->weight))
		goto err_out;

	if (loc->remote_ip_family == AF_INET) {
		if (nla_put_be32 (skb, OVSTACK_ATTR_LOCATOR_IP4ADDR,
				  *(loc->remote_ip4))) 
			goto err_out;
	} else if (loc->remote_ip_family == AF_INET6) {
		if (nla_put (skb, OVSTACK_ATTR_LOCATOR_IP6ADDR,
			     sizeof (struct in6_addr), loc->remote_ip6))
			goto err_out;
	} else {
		pr_debug ("%s: invalid locator ip family %d, node %pI4\n",
			  __func__, loc->remote_ip_family, 
			  &(OV_LOCATOR_NODE_ID (loc)));
		goto err_out;
	}

	return genlmsg_end (skb, hdr);

err_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}


static int
ovstack_nl_node_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		      int cmd, u8 app, struct ov_node * node)
{
	struct ov_locator * loc;

	if (!node) 
		return 0;

	list_for_each_entry_rcu (loc, &(node->ipv4_locator_list), list) {
		ovstack_nl_locator_send (skb, pid, seq, flags, cmd, app, loc);
	}

	list_for_each_entry_rcu (loc, &(node->ipv6_locator_list), list) {
		ovstack_nl_locator_send (skb, pid, seq, flags, cmd, app, loc);
	}

	return 0;
}

static int
ovstack_nl_cmd_locator_dump (struct sk_buff * skb,
			     struct netlink_callback * cb)
{
	u8 app;
	int ret;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp = NULL;
	struct ov_node * ownnode = NULL;

	for (app = cb->args[1]; app < OVSTACK_APP_MAX; app++) {
		ovapp = OVSTACK_NET_APP (ovnet, app);
		if (!ovapp)
			continue;
		ownnode = OVSTACK_APP_OWNNODE (ovapp);

		if (ownnode->ipv4_locator_count || ownnode->ipv6_locator_count)
			break;
	}

	if (app == OVSTACK_APP_MAX)
		goto out;

	ret = ovstack_nl_node_send (skb, NETLINK_CB (cb->skb).portid,
				    cb->nlh->nlmsg_seq,  NLM_F_MULTI,
				    OVSTACK_CMD_LOCATOR_GET, app, ownnode);

	cb->args[1] = app + 1;
out:
	return skb->len;
}

static int
ovstack_nl_cmd_node_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	u8 app;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ov_node * node;

	for (app = cb->args[1]; app < OVSTACK_APP_MAX; app++) {
		ovapp = OVSTACK_NET_APP (ovnet, app);
		if (!ovapp)
			continue;
		if (OVSTACK_APP_FIRSTNODE (ovapp))
			break;
	}

	if (app == OVSTACK_APP_MAX)
		goto out;

	list_for_each_entry_rcu (node, &ovapp->node_chain, chain) {
		ovstack_nl_node_send (skb, NETLINK_CB (cb->skb).portid,
				      cb->nlh->nlmsg_seq, NLM_F_MULTI,
				      OVSTACK_CMD_NODE_GET, app, node);
	}

	cb->args[1] = app + 1;

out:
	return skb->len;
}

static int
ovstack_nl_cmd_route_add (struct sk_buff * skb, struct genl_info * info)
{
	int ret;
	u8 app;
	__be32 dst_node_id, nxt_node_id;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist", __func__, app);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_DST_NODE_ID]) {
		pr_debug ("%s: destiantion node is not specifed", __func__);
		return -EINVAL;
	}
	dst_node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_DST_NODE_ID]);

	if (!info->attrs[OVSTACK_ATTR_NXT_NODE_ID]) {
		pr_debug ("%s: destiantion node is not specifed", __func__);
		return -EINVAL;
	}
	nxt_node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NXT_NODE_ID]);
	
	ovapp = OVSTACK_NET_APP (ovnet, app);
	ret = ortable_add (ovapp, dst_node_id, nxt_node_id);
	
	if (!ret) 
		return ret;

	return 0;
}

static int
ovstack_nl_cmd_route_delete (struct sk_buff * skb, struct genl_info * info)
{
	int ret;
	u8 app;
	__be32 dst_node_id, nxt_node_id;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	if (!info->attrs[OVSTACK_ATTR_APP_ID]) {
		pr_debug ("%s: app id is not specified", __func__);
		return -EINVAL;
	}
	app = nla_get_u8 (info->attrs[OVSTACK_ATTR_APP_ID]);
	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: app id %d does not exist", __func__, app);
		return -EINVAL;
	}

	if (!info->attrs[OVSTACK_ATTR_DST_NODE_ID]) {
		pr_debug ("%s: destiantion node is not specifed", __func__);
		return -EINVAL;
	}
	dst_node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_DST_NODE_ID]);

	if (!info->attrs[OVSTACK_ATTR_NXT_NODE_ID]) {
		pr_debug ("%s: destiantion node is not specifed", __func__);
		return -EINVAL;
	}
	nxt_node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NXT_NODE_ID]);
	
	ovapp = OVSTACK_NET_APP (ovnet, app);
	ret = ortable_delete (ovapp, dst_node_id, nxt_node_id);
	
	if (!ret) 
		return ret;

	return 0;
}

static int
ovstack_nl_route_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		       int cmd, u8 app, struct ortable_nexthop * ortnxt)
{
	void * hdr;
	
	if (!skb || ! ortnxt)
		return -1;

	hdr = genlmsg_put (skb, pid, seq, &ovstack_nl_family, flags, cmd);
	
	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	if (nla_put_u8 (skb, OVSTACK_ATTR_APP_ID, app) ||
	    nla_put_be32 (skb, OVSTACK_ATTR_DST_NODE_ID, 
			  ortnxt->ort_nxt_dst) ||
	    nla_put_be32 (skb, OVSTACK_ATTR_NXT_NODE_ID, ortnxt->ort_nxt)) 
		goto err_out;

	return genlmsg_end (skb, hdr);

err_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}

static int
ovstack_nl_cmd_route_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	u8 app;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;
	struct ortable * ort;
	struct ortable_nexthop * ortnxt;

	for (app = cb->args[1]; app < OVSTACK_APP_MAX; app++) {
		ovapp = OVSTACK_NET_APP (ovnet, app);
		if (!ovapp)
			continue;
		if (OVSTACK_APP_FIRSTROUTE (ovapp))
			break;
	}

	if (app == OVSTACK_APP_MAX)
		goto out;

	list_for_each_entry_rcu (ort, &ovapp->ortable_chain, chain) {
		list_for_each_entry_rcu (ortnxt, &ort->ort_nxts, list) {
			ovstack_nl_route_send (skb, 
					       NETLINK_CB (cb->skb).portid,
					       cb->nlh->nlmsg_seq, NLM_F_MULTI,
					       OVSTACK_CMD_ROUTE_GET, app, 
					       ortnxt);
		}
	}

	cb->args[1] = app + 1;

out:
	return skb->len;
}


static struct nla_policy ovstack_nl_policy[OVSTACK_ATTR_MAX + 1] = {
	[OVSTACK_ATTR_NONE]		= { .type = NLA_UNSPEC, },
	[OVSTACK_ATTR_NODE_ID]		= { .type = NLA_U32, },
	[OVSTACK_ATTR_DST_NODE_ID]	= { .type = NLA_U32, },
	[OVSTACK_ATTR_NXT_NODE_ID]	= { .type = NLA_U32, },
	[OVSTACK_ATTR_APP_ID]		= { .type = NLA_U8 },
	[OVSTACK_ATTR_LOCATOR_IP4ADDR]	= { .type = NLA_U32, },
	[OVSTACK_ATTR_LOCATOR_IP6ADDR]	= { .type = NLA_BINARY,
					    .len = sizeof (struct in6_addr) },
	[OVSTACK_ATTR_LOCATOR_WEIGHT]	= { .type = NLA_U8, },
};

static struct genl_ops ovstack_nl_ops[] = {
	{
		.cmd = OVSTACK_CMD_NODE_ID_SET,
		.doit = ovstack_nl_cmd_node_id_set,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_LOCATOR_ADD,
		.doit = ovstack_nl_cmd_locator_add,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_LOCATOR_DELETE,
		.doit = ovstack_nl_cmd_locator_delete,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_LOCATOR_WEIGHT_SET,
		.doit = ovstack_nl_cmd_locator_weight_set,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_NODE_ADD,
		.doit = ovstack_nl_cmd_node_add,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_NODE_DELETE,
		.doit = ovstack_nl_cmd_node_delete,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_NODE_WEIGHT_SET,
		.doit = ovstack_nl_cmd_node_weight_set,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_APP_ID_GET,
		.dumpit = ovstack_nl_cmd_app_id_dump,
		.policy = ovstack_nl_policy,
	},
	{
		.cmd = OVSTACK_CMD_NODE_ID_GET,
		.dumpit = ovstack_nl_cmd_node_id_dump,
		.policy = ovstack_nl_policy,
	},
	{
		.cmd = OVSTACK_CMD_LOCATOR_GET,
		.dumpit = ovstack_nl_cmd_locator_dump,
		.policy = ovstack_nl_policy,
	},
	{
		.cmd = OVSTACK_CMD_NODE_GET,
		.dumpit = ovstack_nl_cmd_node_dump,
		.policy = ovstack_nl_policy,
	},
	{
		.cmd = OVSTACK_CMD_ROUTE_ADD,
		.doit = ovstack_nl_cmd_route_add,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_ROUTE_DELETE,
		.doit = ovstack_nl_cmd_route_delete,
		.policy = ovstack_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVSTACK_CMD_ROUTE_GET,
		.dumpit = ovstack_nl_cmd_route_dump,
		.policy = ovstack_nl_policy,
	},
};


/*****************************
 *	EXPORT SYMBOLS
 *****************************/

__be32
ovstack_own_node_id (struct net * net, u8 app)
{
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	ovapp = OVSTACK_NET_APP (ovnet, app);

	if (unlikely (!ovnet)) {
		pr_debug ("%s: net_generic failed\n", __func__);
		return 0;
	}
	if (unlikely (!ovapp)) {
		pr_debug ("%s: application %d does not exist", __func__, app);
		return 0;
	}
	
	return OVSTACK_APP_OWNNODE(ovapp)->node_id;
}
EXPORT_SYMBOL (ovstack_own_node_id);


int
ovstack_register_app_ops (struct net * net, int app, int (*app_recv_ops)
			  (struct sock * sk, struct sk_buff * skb))
{
	int n;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	if (app > OVSTACK_APP_MAX) 
		return -EINVAL;

	if (OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: application %d is already registered", 
			  __func__, app);
		return -EEXIST;
	}

	/* alloc new ov app instance */
	
	ovapp = kmalloc (sizeof (struct ovstack_app), GFP_KERNEL);
	memset (ovapp, 0, sizeof (struct ovstack_app));

	ovapp->ov_app = app;

	/* init LIB */
	for (n = 0; n < LIB_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&(ovapp->node_list[n]));
	INIT_LIST_HEAD (&(ovapp->node_chain));

	/* init overlay routing table */
	for (n = 0; n < ORT_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&(ovapp->ortable_list[n]));
	INIT_LIST_HEAD (&(ovapp->ortable_chain));

	/* init own node for the application */
	OVSTACK_APP_OWNNODE (ovapp) = ov_node_create (0);

	/* set packet recv callback */
	ovapp->app_recv_ops = app_recv_ops;
	
	OVSTACK_NET_APP (ovnet, app) = ovapp;

	printk (KERN_INFO "ovstack application (%d) is loaded\n", app);

	return 1;
}
EXPORT_SYMBOL (ovstack_register_app_ops);

int
ovstack_unregister_app_ops (struct net * net, int app)
{
	struct list_head * p, * tmp;
	struct ov_node * node;
	struct ortable * ort;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ovstack_app * ovapp;

	if (app > OVSTACK_APP_MAX) 
		return -EINVAL;

	if (!OVSTACK_NET_APP (ovnet, app)) {
		pr_debug ("%s: application %d does not exist",
			  __func__, app);
		return -EINVAL;
	}
	
	ovapp = OVSTACK_NET_APP (ovnet, app);

	/* destroy locator information base */
	list_for_each_safe (p, tmp, &ovapp->node_chain) {
		node = list_entry (p, struct ov_node, chain);
		ov_node_delete (node);
	}
	
	/* destroy overlay routing table */
	list_for_each_safe (p, tmp, &ovapp->ortable_chain) {
		ort = list_entry (p, struct ortable, chain);
		ortable_destroy (ort);
	}

	/* destroy own self */
	ov_node_destroy (OVSTACK_APP_OWNNODE (ovapp));

	kfree (ovapp);
	ovnet->apps[app] = NULL;

	printk (KERN_INFO "ovstack application (%d) is unloaded\n", app);

	return 1;
}
EXPORT_SYMBOL (ovstack_unregister_app_ops);



/*****************************
 *	init/exit module
 *****************************/

static int
__init ovstack_init_module (void)
{
	int rc;
	get_random_bytes (&ovstack_salt, sizeof (ovstack_salt));
	
	rc = register_pernet_subsys (&ovstack_net_ops);
	if (rc != 0)
		return rc;

	rc = genl_register_family_with_ops (&ovstack_nl_family,
					    ovstack_nl_ops,
					    ARRAY_SIZE (ovstack_nl_ops));
	if (rc != 0) {
		unregister_pernet_subsys (&ovstack_net_ops);
		return rc;
	}

	printk (KERN_INFO "overlay stack (version %s) is loaded\n", 
		OVSTACK_VERSION);

	return 0;
}
module_init (ovstack_init_module);

static void
__exit ovstack_exit_module (void)
{

	genl_unregister_family (&ovstack_nl_family);
	unregister_pernet_subsys (&ovstack_net_ops);

	printk (KERN_INFO "overlay stack (version %s) is unloaded\n",
		OVSTACK_VERSION);

	return;
}
module_exit (ovstack_exit_module);
