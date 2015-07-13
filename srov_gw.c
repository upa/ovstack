/*
 * Session Routing in Overlay Network.
 */

#ifndef DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <uapi/linux/netfilter_ipv6.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>


#include "ovstack.h"
#include "srov_session.h"


#define SROVGW_VERSION	"0.0.1"
MODULE_VERSION (SROVGW_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");




/* - node pool for one prefix.
 * and operations for pool. node pool is used by only gateway.
 */
struct srov_node_pool {

	rwlock_t	lock;

#define MAX_POOL_SIZE	128
	__be32	nodelist[MAX_POOL_SIZE];

	int count;
	int tail;
};


/* route table for prefix */
struct srov_route_table {
	struct hlist_head route_list[SROV_HASH_SIZE];
	rwlock_t lock;
};

struct srov_route {
	struct hlist_node	hlist;	/* private: used by route_table */
	struct rcu_head		rcu;
	
	__be32	dst;	/* IP address */
	struct srov_node_pool pool;
};


/* per net_netmaspace instance */
static unsigned int srovgw_net_id;
struct srovgw_net {
	/* hashtable for struct srov_session */
	struct srov_session_table session_table;

	/* hashtable for struct srov_route */
	struct srov_route_table route_table;
};



static void
srov_node_pool_add (struct srov_node_pool * pool, __be32 node_id)
{
	if (pool->count > MAX_POOL_SIZE) {
		printk (KERN_ERR "srovgw:%s: max node, %pI4\n",
			__func__, &node_id);
		return;
	}

	WRITE_LOCK (pool);
	pool->nodelist[pool->tail++] = node_id;
	pool->count++;
	WRITE_UNLOCK (pool);

	return;
}

static void
srov_node_pool_delete (struct srov_node_pool * pool, __be32 node_id)
{
	int p;

	if (node_id == 0) {
		printk (KERN_ERR "srovgw:%s: invalid delete node id %pI4\n",
			__func__, &node_id);
	}

	WRITE_LOCK (pool);
	for (p = 0; p < MAX_POOL_SIZE; p++) {
		if (pool->nodelist[p] == node_id) {
			pool->nodelist[p] = 0;
			pool->nodelist[p] = pool->nodelist[pool->tail - 1];
			pool->nodelist[pool->tail] = 0;
			pool->count--;
			pool->tail--;
			break;
		}
	}
	WRITE_UNLOCK (pool);
}

static __be32
srov_node_pool_get (struct srov_node_pool * pool, unsigned int key)
{
	__be32 dst;

	if (pool->count == 0)
		return 0;

	READ_LOCK (pool);
	read_lock_bh (&pool->lock);
	dst = pool->nodelist[key % pool->count];
	READ_UNLOCK (pool);

	return dst;
}


static inline struct hlist_head *
srov_srt_head (struct srov_route_table * srt, unsigned int key)
{
	return &srt->route_list[hash_32 (key, SROV_HASH_BITS)];
}

static struct srov_route *
srov_route_find (struct srov_route_table * srt, __be32 dst)
{
	struct srov_route * sr;

	READ_LOCK (srt);
	hlist_for_each_entry_rcu (sr, srov_srt_head (srt, dst), hlist) {
		if (sr->dst == dst) {
			READ_UNLOCK (srt);
			return sr;
		}
	}
	READ_UNLOCK (srt);

	return NULL;
}

static struct srov_route *
srov_route_create (__be32 dst)
{
	int f = GFP_KERNEL;
	struct srov_route * sr;

	sr = (struct srov_route *) kmalloc (sizeof (struct srov_route), f);

	memset (sr, 0, sizeof (struct srov_route));
	sr->dst = dst;

	return sr;
}

static void
srov_route_add (struct srov_route_table * srt, struct srov_route * sr)
{
	hlist_add_head_rcu (&sr->hlist, srov_srt_head (srt, sr->dst));
}

static inline void
srov_route_destroy (struct srov_route * sr)
{
	hlist_del_rcu (&sr->hlist);
	kfree_rcu (sr, rcu);
}

static inline void
srov_route_table_destroy (struct srov_route_table * srt)
{
	unsigned int h;
	struct srov_route * sr;

	for (h = 0; h < SROV_HASH_SIZE; h++) {
		struct hlist_node * p, * n;
		hlist_for_each_safe (p, n, &srt->route_list[h]) {
			sr = container_of (p, struct srov_route, hlist);
			srov_route_destroy (sr);
		}
	}
}



/* - nf nook ops.
 * packets are NF_INET_FORWARDis hoooked, and if it is specified port session,
 * the flow is encapsulated in ovstack.
 */

static unsigned int
nf_ovsrgw_forward (const struct nf_hook_ops * ops,
		   struct sk_buff * skb,
		   const struct net_device * in,
		   const struct net_device * out,
		   int (*okfn) (struct sk_buff *))
{

	/* 1.
	 * Find flow,
	 * if found, create flow, and assign destination from node pool
	 * send to the destination.
	 */

	int rc;
	u8 protocol;
	u16 sport, dport;
	__be32 saddr, daddr;
	unsigned int key;
	struct iphdr * ip;
	struct tcphdr * tcp;
	struct udphdr * udp;
	struct ovhdr * ovh;
	struct srov_route * sr;
	struct srov_session * ss;
	struct srovgw_net * sgnet;

	sgnet = net_generic (dev_net (skb->dev), srovgw_net_id);


	ip = (struct iphdr *) skb_network_header (skb);
	protocol = ip->protocol;
	saddr = ip->saddr;
	daddr = ip->daddr;

	if (protocol == IPPROTO_TCP) {
		tcp = (struct tcphdr *) skb_transport_header (skb);
		sport = tcp->source;
		dport = tcp->dest;
	} else if (protocol == IPPROTO_UDP) {
		udp = (struct udphdr *) skb_transport_header (skb);
		sport = udp->source;
		dport = udp->dest;
	} else
		return NF_ACCEPT;
	
	key = SROV_FLOW_KEY (protocol, saddr, daddr, sport, dport);

	/* find or create session */
	sr = NULL;
	ss = srov_session_find (&sgnet->session_table, protocol,
				saddr, daddr, sport, dport);
	if (!ss) {
		sr = srov_route_find (&sgnet->route_table, daddr);
		if (!sr) {
			/* not proxyed packet */
			return NF_ACCEPT;
		}

		WRITE_LOCK (&sgnet->session_table);
		ss = srov_session_create (protocol, saddr, daddr,
					  sport, dport, GFP_ATOMIC);
		if (!ss) {
			WRITE_UNLOCK (&sgnet->session_table);
			return NF_DROP;
		}

		srov_session_add (&sgnet->session_table, ss);

		WRITE_UNLOCK (&sgnet->session_table);
	}

	if (ss->dst == 0) {
		/* reassign destination from node pool */
		sr = srov_route_find (&sgnet->route_table, daddr);
		ss->dst = srov_node_pool_get (&sr->pool, key);
	}

	/* encap it ! remove iphdr, and add ovhdr */
	if (skb_cow_head (skb, sizeof (struct ovhdr) - (ip->ihl << 2))) {
		pr_debug ("srovgw:%s: failed to alloc skb_cow_head", __func__);
	}

	ovh = (struct ovhdr *)
		__skb_push (skb, sizeof (struct ovhdr) - (ip->ihl << 2));
	
	ovh->ov_version	= OVSTACK_HEADER_VERSION;
	ovh->ov_ttl	= OVSTACK_TTL;
	ovh->ov_app	= OVAPP_SROV;
	ovh->ov_flags	= 0;
	ovh->ov_vni	= htonl (protocol << 8);
	ovh->ov_hash	= key;
	ovh->ov_dst	= ss->dst;
	ovh->ov_src	= ovstack_own_node_id (dev_net (skb->dev), OVAPP_SROV);


	rc = ovstack_xmit (skb, skb->dev);

	if (net_xmit_eval (rc) == 0) {
		/* XXX: update packet counter of dev ? */
		ss->pkt_count++;
		ss->byte_count += skb->len;
		ss->update = jiffies;
	}

	return NF_STOLEN;
}


static struct nf_hook_ops nf_srovgw_ops[] __read_mostly = {
	{
		.hook		= nf_ovsrgw_forward,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_FIRST,
	},
};


/* - ovstack receive ops.
 * received ovstack packet is decapsulated, and original TCP/UDP header is
 * constructed by using hash value as the key.
 */

static int
ovstack_srovgw_recv (struct sk_buff * skb)
{
	return 0;
}


/* - initalize and terminate hooks
 * init/exit net_namespace
 * init/exit module
 */

static __net_init int
srovgw_init_net (struct net * net)
{
	int rc;
	struct srovgw_net * sgnet = net_generic (net, srovgw_net_id);

	memset (sgnet, 0, sizeof (struct srovgw_net));

	rc = ovstack_register_app_ops (net, OVAPP_SROV, ovstack_srovgw_recv);
	if (!rc) {
		printk (KERN_ERR "srov_gw: failed to register ovstack app\n");
		return -1;
	}

	return 0;
}

static __net_exit void
srovgw_exit_net (struct net * net)
{
	int rc;
	struct srovgw_net * sgnet = net_generic (net, srovgw_net_id);

	rc = ovstack_unregister_app_ops (net, OVAPP_SROV);
	if (!rc) {
		printk (KERN_ERR
			"srov_gw: failed to unregister ovstack app\n");
	}

	srov_session_table_destroy (&sgnet->session_table);
	srov_route_table_destroy (&sgnet->route_table);

	return;
}

static struct pernet_operations srovgw_net_ops = {
	.init	= srovgw_init_net,
	.exit	= srovgw_exit_net,
	.id	= &srovgw_net_id,
	.size	= sizeof (struct srovgw_net),
};


static int
__init srovgw_init_module (void)
{
	int rc;

	rc = register_pernet_device (&srovgw_net_ops);
	if (rc != 0)
		goto net_err;

	rc = nf_register_hooks (nf_srovgw_ops, ARRAY_SIZE (nf_srovgw_ops));
	if (rc != 0)
		goto nf_err;

	printk (KERN_INFO "srov gateway (version %s) is loaded\n",
		SROVGW_VERSION);

	return rc;

nf_err:
	unregister_pernet_device (&srovgw_net_ops);
net_err:
	return rc;
}
module_init (srovgw_init_module);


static void
__exit srovgw_exit_module (void)
{
	unregister_pernet_device (&srovgw_net_ops);
	nf_unregister_hooks (nf_srovgw_ops, ARRAY_SIZE (nf_srovgw_ops));

	printk (KERN_INFO "srov gateway (version %s) is unloaded\n",
		SROVGW_VERSION);
	return;
}
module_exit (srovgw_exit_module);
