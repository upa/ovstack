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
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>

#include "ovstack.h"

#define OVSTACK_VERSION "0.0.1"
MODULE_VERSION (OVSTACK_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");


#define VNI_MAX		0x00FFFFFF
#define VNI_HASH_BITS	8
#define LIB_HASH_BITS	8

#define VNI_HASH_SIZE	(1 << VNI_HASH_BITS)
#define LIB_HASH_SIZE	(1 << LIB_HASH_BITS)

#define OVSTACK_DEFAULT_WEIGHT 50


static unsigned int ovstack_net_id;
static u32 ovstack_salt __read_mostly;

/* callback functions called when receive a packet. */
struct ovstack_recv_ops {
	int (* proto_recv_ops[OVSTACK_PROTO_MAX])
	(struct sock * sk, struct sk_buff * skb);
} ov_recv_ops;


/* Overlay Node */
struct ov_node {
	struct list_head	list;
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


/* per network namespace structure */
struct ovstack_net {
	struct ov_node own_node;			/* self */
	struct list_head node_list[LIB_HASH_SIZE];	/* node list hash */
	struct socket * sock;				/* udp encap socket */
};
#define OVSTACK_NET_OWNNODE(ovnet) (&(ovnet->own_node))


/********************
 * node and locator operation functions
 *********************/

static inline struct list_head *
node_head (struct ovstack_net * ovnet , __be32 node_id)
{
	return &(ovnet->node_list[hash_32 (node_id, LIB_HASH_BITS)]);
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
	
	return;
}

static inline void
ov_node_add (struct ovstack_net * ovnet, struct ov_node * node)
{
	list_add_rcu (&(node->list), node_head (ovnet, node->node_id));
	return;
}

static inline void
ov_node_delete (struct ov_node * node) 
{
	list_del_rcu (&(node->list));
	return;
}

static struct ov_node *
find_ov_node_by_id (struct ovstack_net * ovnet, __be32 node_id)
{
	struct ov_node * node;

	list_for_each_entry_rcu (node, node_head (ovnet, node_id), list) {
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
	if (ai_family == AF_INET) {
		li = &(node->ipv4_locator_list);
		hash %=	node->ipv4_locator_weight_sum;
	} else if (ai_family == AF_INET6) {
		li = &(node->ipv6_locator_list);
		hash %=	node->ipv6_locator_weight_sum;
	}
	
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
ov_locator_del (struct ov_node * node, struct ov_locator * loc)
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

	/* pop off outer UDP header */
	__skb_pull (skb, sizeof (struct udphdr));

	/* need ov and inner ether header to present */
	if (!pskb_may_pull (skb, sizeof (struct ovhdr))) {
		skb_push (skb, sizeof (struct udphdr));
		return 1;
	}

	/* call function per ov proto */
	ovh = (struct ovhdr *) skb->data;
	if (unlikely (ov_recv_ops.proto_recv_ops[ovh->ov_protocol] == NULL)) {
		pr_debug ("%s: unknwon protocol number %d\n", 
			  __func__, ovh->ov_protocol);
		return 0;
	}

	return ov_recv_ops.proto_recv_ops[ovh->ov_protocol] (sk, skb);
}



static __net_init int
ovstack_init_net (struct net * net)
{
	int rc, n;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * own = OVSTACK_NET_OWNNODE (ovnet);
	struct sock * sk;
	struct sockaddr_in6 ovstack_addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons (OVSTACK_PORT),
		.sin6_addr	= IN6ADDR_ANY_INIT,
	};
	
	/* init lib */
	for (n = 0; n < LIB_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&(ovnet->node_list[n]));

	/* self node*/
	memset (own, 0, sizeof (struct ov_node));
	INIT_LIST_HEAD (&(own->ipv4_locator_list));
	INIT_LIST_HEAD (&(own->ipv6_locator_list));
	own->update = jiffies;

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
	int n;
	struct list_head *p, *tmp;
	struct ov_node * node;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	/* destroy socket */
	if (ovnet->sock) {
		sk_release_kernel (ovnet->sock->sk);
		ovnet->sock = NULL;
	}

	/* destroy lib */
	for (n = 0; n < LIB_HASH_SIZE; n++) {
		list_for_each_safe (p, tmp, &(ovnet->node_list[n])) {
			node = list_entry (p, struct ov_node, list);
			list_del_rcu (p);
			ov_node_destroy (node);
			kfree_rcu (node, rcu);
		}
	}

	/* destroy my locator list */
	ov_node_destroy (OVSTACK_NET_OWNNODE (ovnet));

	return;
}


static struct pernet_operations ovstack_net_ops = {
	.init	= ovstack_init_net,
	.exit	= ovstack_exit_net,
	.id	= &ovstack_net_id,
	.size	= sizeof (struct ovstack_net),
};


/*****************************
 ****	genl_ops 
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
	__be32 node_id;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	if (!info->attrs[OVSTACK_ATTR_NODE_ID]) {
		pr_debug ("%s: node id is not specified\n", __func__);
		return -EINVAL;
	}
	node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NODE_ID]);

	OVSTACK_NET_OWNNODE (ovnet)->node_id = node_id;

	return 0;
}

static int
ovstack_nl_cmd_locator_add (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr;
	u8 ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * ownnode = OVSTACK_NET_OWNNODE (ovnet);
	struct ov_locator * loc;

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

	if (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) 
		weight = nla_get_u8 (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);

	/* add new locator */
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
	u8 ai_family;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * ownnode = OVSTACK_NET_OWNNODE (ovnet);
	struct ov_locator * loc;

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

	/* delete locator */
	loc = find_ov_locator_by_addr (ownnode, addr, ai_family);
	if (loc == NULL) {
		pr_debug ("%s: locator does not exist\n", __func__);
		return -ENOENT;
	}
	ov_locator_del (ownnode, loc);
	kfree_rcu (loc, rcu);

	return 0;
}

static int
ovstack_nl_cmd_locator_weight_set (struct sk_buff * skb, 
				   struct genl_info * info)
{
	__be32 * addr;
	u8 ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * ownnode = OVSTACK_NET_OWNNODE (ovnet);
	struct ov_locator * loc;

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

	/* set locator weight */
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
	u8 ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * node;
	struct ov_locator * loc;

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

	if (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) 
		weight = nla_get_u8 (info->attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);
	

	/* add new locator to node */
	node = find_ov_node_by_id (ovnet, node_id);
	if (node == NULL) {
		node = ov_node_create (node_id);
		ov_node_add (ovnet, node);
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
	u8 ai_family;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * node;
	struct ov_locator * loc;

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


	/* delete locator to node */
	node = find_ov_node_by_id (ovnet, node_id);
	if (node == NULL) {
		pr_debug ("%s: node id %pI4 does not exist\n", __func__,
			  &node_id);
		return -ENOENT;
	}

	loc = find_ov_locator_by_addr (node, addr, ai_family);
	if (loc == NULL) {
		pr_debug ("%s: node id %pI4 does not have locator\n",
			  __func__, &node_id);
		return -ENOENT;
	}

	ov_locator_del (node, loc);
	kfree_rcu (loc, rcu);

	return 0;
}

static int
ovstack_nl_cmd_node_weight_set (struct sk_buff * skb, struct genl_info * info)
{
	__be32 * addr, node_id;
	u8 ai_family, weight = OVSTACK_DEFAULT_WEIGHT;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * node;
	struct ov_locator * loc;

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
	

	/* set weight */
	node = find_ov_node_by_id (ovnet, node_id);
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
ovstack_nl_cmd_node_id_get (struct sk_buff * skb, struct genl_info * info)
{
	int ret = -ENOBUFS;
	void * hdr;
	struct sk_buff * msg;
	struct ovstack_net * ovnet;

	ovnet = net_generic (genl_info_net (info), ovstack_net_id);
	msg = nlmsg_new (NLMSG_GOODSIZE, GFP_KERNEL);
	if (msg)
		return -ENOMEM;
	
	hdr = genlmsg_put (msg, info->snd_pid, info->snd_seq,
			   &ovstack_nl_family, NLM_F_ACK,
			   OVSTACK_CMD_NODE_ID_GET);
	if (IS_ERR (hdr)) 
		PTR_ERR (hdr);

	if (nla_put_be32 (msg, OVSTACK_ATTR_NODE_ID, 
			  OVSTACK_NET_OWNNODE(ovnet)->node_id)) {
		genlmsg_cancel (msg, hdr);
		goto err_out;
	}

	ret = genlmsg_end (msg, hdr);
	if (ret < 0) 
		goto err_out;
	
	return genlmsg_unicast (genl_info_net (info), msg, info->snd_pid);

err_out:
	nlmsg_free (msg);
	return ret;
}

static int
ovstack_nl_locator_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
			 int cmd, struct ov_locator * loc)
{
	void * hdr;
	struct ov_node * node;

	node = loc->node;
	hdr = genlmsg_put (skb, pid, seq, &ovstack_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	if (nla_put_be32 (skb, OVSTACK_ATTR_NODE_ID, node->node_id) ||
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
			 int cmd, struct ov_node * node)
{
	struct ov_locator * loc;

	list_for_each_entry_rcu (loc, &(node->ipv4_locator_list), list) 
		ovstack_nl_locator_send (skb, pid, seq, flags, cmd, loc);

	list_for_each_entry_rcu (loc, &(node->ipv6_locator_list), list) 
		ovstack_nl_locator_send (skb, pid, seq, flags, cmd, loc);

	return 0;
}

static int
ovstack_nl_cmd_locator_get (struct sk_buff * skb, struct genl_info * info)
{
	int ret;
	u8 ai_family;
	__be32 * addr = NULL;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct sk_buff * msg;
	struct net * net;
	struct ovstack_net * ovnet;
	struct ov_locator * loc;

	
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


	net = genl_info_net (info);
	ovnet = net_generic (net, ovstack_net_id);
	loc = find_ov_locator_by_addr (OVSTACK_NET_OWNNODE (ovnet),
				       addr, ai_family);
	if (loc == NULL) 
		return -ENOENT;

	msg = nlmsg_new (NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) 
		return -ENOMEM;

	ret = ovstack_nl_locator_send (msg, info->snd_pid, info->snd_seq,
				       NLM_F_ACK, OVSTACK_CMD_LOCATOR_GET,
				       loc);
	if (ret < 0) {
		nlmsg_free (msg);
		return ret;
	}

	return genlmsg_unicast (net, msg, info->snd_pid);
}

static int
ovstack_nl_cmd_locator_dump (struct sk_buff * skb,
			     struct netlink_callback * cb)
{
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * node = OVSTACK_NET_OWNNODE (ovnet);

	for (;;) {
		if (ovstack_nl_node_send (skb, NETLINK_CB (cb->skb).pid,
					  cb->nlh->nlmsg_seq, NLM_F_MULTI,
					  OVSTACK_CMD_NODE_GET, node) <= 0)
			goto out;
	}

out:
	cb->args[0] = node->node_id;
	return skb->len;
}


static int
ovstack_nl_cmd_node_get (struct sk_buff * skb, struct genl_info * info)
{
	int ret;
	__be32 node_id;
	struct net * net;
	struct ovstack_net * ovnet;
	struct ov_node * node;
	struct sk_buff * msg;

	if (!info->attrs[OVSTACK_ATTR_NODE_ID]) {
		pr_debug ("%s: node id is not specified\n", __func__);
		return -EINVAL;
	}
	node_id = nla_get_be32 (info->attrs[OVSTACK_ATTR_NODE_ID]);

	net = genl_info_net (info);
	ovnet = net_generic (net, ovstack_net_id);

	node = find_ov_node_by_id (ovnet, node_id);
	if (node == NULL) 
		return -ENOENT;

	msg = nlmsg_new (NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = ovstack_nl_node_send (msg, info->snd_pid, info->snd_seq, 
				    NLM_F_ACK, OVSTACK_CMD_NODE_GET, node);

	if (ret < 0) {
		nlmsg_free (msg);
		return ret;
	}

	return genlmsg_unicast (net, msg, info->snd_pid);
}

static int
ovstack_nl_cmd_node_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	struct net * net = sock_net (skb->sk);
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);
	struct ov_node * node = NULL;
	__be32 node_id = cb->args[0];

	for (;;) {
		if (node == NULL) {
			node = find_ov_node_by_id (ovnet, node_id);
			if (node == NULL)
				goto out;
		}
		if (ovstack_nl_node_send (skb, NETLINK_CB (cb->skb).pid,
					  cb->nlh->nlmsg_seq, NLM_F_MULTI,
					  OVSTACK_CMD_NODE_GET, node) <= 0)
			goto out;
	}

out:
	cb->args[0] = node_id;
	return skb->len;
}

static struct nla_policy ovstack_nl_policy[OVSTACK_ATTR_MAX + 1] = {
	[OVSTACK_ATTR_NONE]		= { .type = NLA_UNSPEC, },
	[OVSTACK_ATTR_NODE_ID]		= { .type = NLA_U32, },
	[OVSTACK_ATTR_LOCATOR_IP4ADDR]	= { .type = NLA_U32, },
	[OVSTACK_ATTR_LOCATOR_IP6ADDR]	= { .type = NLA_BINARY,
					    .len = sizeof (struct in6_addr)},
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
		.cmd = OVSTACK_CMD_NODE_ID_GET,
		.doit = ovstack_nl_cmd_node_id_get,
		.policy = ovstack_nl_policy,
	},
	{
		.cmd = OVSTACK_CMD_LOCATOR_GET,
		.doit = ovstack_nl_cmd_locator_get,
		.dumpit = ovstack_nl_cmd_locator_dump,
		.policy = ovstack_nl_policy,
	},
	{
		.cmd = OVSTACK_CMD_NODE_GET,
		.doit = ovstack_nl_cmd_node_get,
		.dumpit = ovstack_nl_cmd_node_dump,
		.policy = ovstack_nl_policy,
	},
};


/*****************************
 *	EXPORT SYMBOLS
 *****************************/

__be32
ovstack_own_node_id (struct net * net)
{
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	if (unlikely(!ovnet)) {
		pr_debug ("%s: net_generic failed\n", __func__);
		return 0;
	}
	
	return OVSTACK_NET_OWNNODE(ovnet)->node_id;
}
EXPORT_SYMBOL (ovstack_own_node_id);

int
ovstack_ipv4_src_loc (struct in_addr * addr, struct net * net, u32 hash)
{
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	if (unlikely(!ovnet)) {
		pr_debug ("%s: net_generic failed\n", __func__);
		return 0;
	}

	loc = find_ov_locator_by_hash (OVSTACK_NET_OWNNODE (ovnet),
				    hash, AF_INET);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip4, sizeof (struct in_addr));

	return 1;
}
EXPORT_SYMBOL (ovstack_ipv4_src_loc);

int
ovstack_ipv4_dst_loc (struct in_addr * addr, 
		      struct net * net, __be32 node_id, u32 hash)
{
	struct ov_node * node;
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	node = find_ov_node_by_id (ovnet, node_id);
	if (unlikely (!node)) {
		pr_debug ("%s: node id %pI4 does not exist\n", 
			  __func__,  &node_id);
		return 0;
	}

	loc = find_ov_locator_by_hash (node, hash, AF_INET);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip4, sizeof (struct in_addr));

	return 1;
}
EXPORT_SYMBOL (ovstack_ipv4_dst_loc);

int
ovstack_ipv6_src_loc (struct in6_addr * addr, struct net * net, u32 hash)
{
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	if (unlikely(!ovnet)) {
		pr_debug ("%s: net_generic failed\n", __func__);
		return 0;
	}

	loc = find_ov_locator_by_hash (OVSTACK_NET_OWNNODE (ovnet),
				    hash, AF_INET6);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip6, sizeof (struct in6_addr));

	return 1;
}
EXPORT_SYMBOL (ovstack_ipv6_src_loc);

int
ovstack_ipv6_dst_loc (struct in6_addr * addr, 
		      struct net * net, __be32 node_id, u32 hash)
{
	struct ov_node * node;
	struct ov_locator * loc;
	struct ovstack_net * ovnet = net_generic (net, ovstack_net_id);

	node = find_ov_node_by_id (ovnet, node_id);
	if (unlikely (!node)) {
		pr_debug ("%s: node id %pI4 does not exist\n", 
			  __func__, &node_id);
		return 0;
	}

	loc = find_ov_locator_by_hash (node, hash, AF_INET6);
	if (loc == NULL)
		return 0;
	memcpy (addr, loc->remote_ip6, sizeof (struct in6_addr));

	return 1;
}
EXPORT_SYMBOL (ovstack_ipv6_dst_loc);

int
ovstack_register_recv_ops (int protocol, int (*proto_recv_ops)
			   (struct sock * sk, struct sk_buff * skb))
{
	if (protocol - 1> OVSTACK_PROTO_MAX) 
		return -EINVAL;

	if (ov_recv_ops.proto_recv_ops[protocol] != NULL) {
		pr_debug ("%s: protocol %d recv func is already registered", 
			  __func__, protocol);
		return -EEXIST;
	}

	ov_recv_ops.proto_recv_ops[protocol] = proto_recv_ops;
	return 1;
}
EXPORT_SYMBOL (ovstack_register_recv_ops);

int
ovstack_unregister_recv_ops (int protocol)
{
	if (protocol - 1 > OVSTACK_PROTO_MAX) 
		return -EINVAL;

	ov_recv_ops.proto_recv_ops[protocol] = NULL;
	return 1;
}
EXPORT_SYMBOL (ovstack_unregister_recv_ops);



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

	memset (&ov_recv_ops, 0, sizeof (ov_recv_ops));

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
