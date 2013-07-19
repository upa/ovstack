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
#include <linux/byteorder/generic.h>
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
#include "oveth.h"

#define OVETH_VERSION "0.0.2"

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

/* OVHDR + Ethernet */
#define OVETH_HEADROOM (16 + 14)

static u32 oveth_salt __read_mostly;


struct oveth_fdb_node {
	struct list_head	list;
	struct rcu_head		rcu;
	__be32			node_id;
	struct oveth_fdb	* fdb;		/* parent */
};

struct oveth_fdb {
	struct list_head	list;
	struct list_head	chain;
	struct rcu_head		rcu;

        unsigned long		update;

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
	struct list_head vni_chain;			/* oveth_dev chain */
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
	struct list_head	chain;
	struct net_device	* dev;
	struct oveth_stats	__percpu * stats;

	__u32			vni;
	struct list_head	fdb_head[FDB_HASH_SIZE];
	struct list_head	fdb_chain;
};


/* utils */
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
	list_add_rcu (&(f->list), oveth_fdb_head (oveth, f->eth_addr));
	list_add_rcu (&(f->chain), &(oveth->fdb_chain));
	return;
}

static void
oveth_fdb_del (struct oveth_fdb * f)
{
	struct list_head *p, *tmp;
	struct oveth_fdb_node * fn;

	/* destroy node id list */
	list_for_each_safe (p, tmp, &(f->node_id_list)) {
		fn = list_entry_rcu (p, struct oveth_fdb_node, list);
		list_del_rcu (&(fn->list));
		kfree_rcu (fn, rcu);
	}

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
	fn->fdb = f;
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
	fn->fdb = NULL;
	list_del_rcu (&(fn->list));
	f->node_id_count--;
	return;
}


/*************************************
 *	net_device_ops related
 *************************************/

static netdev_tx_t
oveth_xmit (struct sk_buff * skb, struct net_device * dev)
{
	int rc;
	u32 hash;
	struct sk_buff * mskb;
	struct ovhdr * ovh;
	struct ethhdr * eth;
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;
	struct oveth_dev * oveth = netdev_priv (dev);

	skb_reset_mac_header (skb);
	eth = eth_hdr (skb);
	f = find_oveth_fdb_by_mac (oveth, eth->h_dest);
	if (f == NULL) {
		pr_debug ("%s: dst fdb entry does not exist. "
			  "%02x:%02x:%02x:%02x:%02x:%02x", __func__,
			  eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
			  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
		return NETDEV_TX_OK;
	}

	hash = eth_hash (eth->h_dest);

	/* setup ovly header */
	if (skb_cow_head (skb, OVETH_HEADROOM)) {
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}

	ovh = (struct ovhdr *) __skb_push (skb, sizeof (struct ovhdr));
	ovh->ov_version	= OVSTACK_HEADER_VERSION;
	ovh->ov_ttl	= OVSTACK_TTL;
	ovh->ov_app	= OVAPP_ETHERNET;
	ovh->ov_flags	= 0;
	ovh->ov_vni	= htonl (oveth->vni << 8);
	ovh->ov_hash	= htonl (hash);
	ovh->ov_dst	= 0;
	ovh->ov_src	= ovstack_own_node_id (dev_net (dev), OVAPP_ETHERNET);

	list_for_each_entry_rcu (fn, &f->node_id_list, list) {

		mskb = skb_clone (skb, GFP_ATOMIC);

		if (unlikely (!mskb)) {
			dev->stats.tx_errors++;
			dev->stats.tx_aborted_errors++;
			printk (KERN_ERR "oveth: failed to alloc skb\n");
			goto skip;
		}

		ovh = (struct ovhdr *) mskb->data;
		ovh->ov_dst = fn->node_id;
		rc = ovstack_xmit (mskb, dev);

		if (net_xmit_eval (rc) == 0) {
			struct oveth_stats * stats = 
				this_cpu_ptr (oveth->stats);
			u64_stats_update_begin (&stats->syncp);
			stats->tx_packets++;
			stats->tx_bytes += mskb->len;
			u64_stats_update_end (&stats->syncp);
		} else {
			dev->stats.tx_errors++;
			dev->stats.tx_aborted_errors++;
		}
	skip:;
	}

	dev_kfree_skb (skb);

	return NETDEV_TX_OK;
}

static int
oveth_udp_encap_recv (struct sock * sk, struct sk_buff * skb)
{
	__u32 vni;
	__be32 node_id;
	struct ovhdr * ovh;
	struct iphdr * oip;
	struct net * net;
	struct oveth_dev * oveth;
	struct oveth_stats * stats;

	/* outer udp header is already removed by ovstack */

	ovh = (struct ovhdr *) skb->data;
	vni = ntohl (ovh->ov_vni) >> 8;
	net = sock_net (sk);
	oveth = find_oveth_by_vni (net, vni);

	/* vni check */
	if (!oveth) {
		netdev_dbg (skb->dev, "unknown vni %d\n", vni);
		kfree_skb (skb);
		return 0;
	}
        if (!pskb_may_pull (skb, ETH_HLEN)) {
		oveth->dev->stats.rx_length_errors++;
		oveth->dev->stats.rx_errors++;
		kfree_skb(skb);
		return 0;
	}

	/* if destination node is not my node id, packet is forwarded.
	   This process ought to be done in ovstack layer.
	 */
	node_id = ovstack_own_node_id (net, OVAPP_ETHERNET);
	if (ovh->ov_dst != node_id) {
		pr_debug ("%s: packet is not for me !", __func__);
		goto not_rx;
	}
	
	/* put off outer headers, and put packet up to upper layer */
        __skb_pull (skb, sizeof (struct ovhdr));
	skb_reset_mac_header (skb);
	oip = ip_hdr (skb);
	skb->protocol = eth_type_trans (skb, oveth->dev);

	/* loop ? */
	if (compare_ether_addr (eth_hdr(skb)->h_source,
				oveth->dev->dev_addr) == 0) {
		kfree_skb(skb);
		return 0;
	}

	__skb_tunnel_rx (skb, oveth->dev);
	skb_reset_network_header (skb);

	if (skb->ip_summed != CHECKSUM_UNNECESSARY ||
	    !(oveth->dev->features & NETIF_F_RXCSUM))
		skb->ip_summed = CHECKSUM_NONE;

	stats = this_cpu_ptr(oveth->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);

	return 0;

not_rx:
	stats = this_cpu_ptr(oveth->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	return 0;
}

static int
oveth_init (struct net_device * dev)
{
	struct oveth_dev * oveth = netdev_priv (dev);

	oveth->stats = alloc_percpu (struct oveth_stats);
	if (!oveth->stats)
		return -ENOMEM;

	return 0;
}

static int
oveth_open (struct net_device * dev)
{
	/* nothing to do (?) */

	return 0;
}

static int
oveth_stop (struct net_device * dev)
{
	/* nothing to do (?) */
	return 0;
}

static struct rtnl_link_stats64 *
oveth_stats64 (struct net_device * dev, struct rtnl_link_stats64 * stats)
{
	unsigned int cpu;
	struct oveth_dev * oveth = netdev_priv (dev);
	struct oveth_stats tmp, sum = { 0 };

	for_each_possible_cpu (cpu) {
		unsigned int start;
		const struct oveth_stats * stats
			= per_cpu_ptr (oveth->stats, cpu);
		
		do {
			start = u64_stats_fetch_begin_bh (&stats->syncp);
			memcpy (&tmp, stats, sizeof (tmp));
		} while (u64_stats_fetch_retry_bh (&stats->syncp, start));
		
		sum.tx_bytes   += tmp.tx_bytes;
		sum.tx_packets += tmp.tx_packets;
		sum.rx_bytes   += tmp.rx_bytes;
		sum.rx_packets += tmp.rx_packets;
	}

	stats->tx_bytes   = sum.tx_bytes;
	stats->tx_packets = sum.tx_packets;
	stats->rx_bytes   = sum.rx_bytes;
	stats->rx_packets = sum.rx_packets;

	stats->multicast = dev->stats.multicast;
	stats->rx_length_errors = dev->stats.rx_length_errors;
	stats->rx_frame_errors = dev->stats.rx_frame_errors;
	stats->rx_errors = dev->stats.rx_errors;

	stats->tx_dropped = dev->stats.tx_dropped;
	stats->tx_carrier_errors  = dev->stats.tx_carrier_errors;
	stats->tx_aborted_errors  = dev->stats.tx_aborted_errors;
	stats->collisions  = dev->stats.collisions;
	stats->tx_errors = dev->stats.tx_errors;

	return stats;
}


/* Add static entry via netlink */

static int
oveth_ndo_fdb_add (struct ndmsg * ndm, struct nlattr * tb[], 
		   struct net_device * dev, 
		   const unsigned char * addr, u16 flags)
{
	__be32 node_id;
	struct oveth_dev * oveth = netdev_priv (dev);
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;

	if (!(ndm->ndm_state & (NUD_PERMANENT | NUD_REACHABLE))) {
		pr_info ("RTM_NEWNEIGH with invalid state %#x\n",
			 ndm->ndm_state);
		return -EINVAL;
	}

	if (tb[NDA_DST] == NULL) {
		pr_debug ("%s: destination node is not specified\n", __func__);
		return -EINVAL;
	}

	if (nla_len (tb[NDA_DST]) != sizeof (__be32))
		return -EAFNOSUPPORT;

	node_id = nla_get_be32 (tb[NDA_DST]);

	f = find_oveth_fdb_by_mac (oveth, addr);
	if (f == NULL) {
		f = create_oveth_fdb ((u8 *)addr);
		oveth_fdb_add (oveth, f);
	}

	fn = oveth_fdb_find_node (f, node_id);
	if (fn == NULL) 
		oveth_fdb_add_node (f, node_id);
	else 
		return -EEXIST;

	return 0;
}

/* Delete entry via netlink */
static int
oveth_ndo_fdb_delete (struct ndmsg * ndm, struct net_device * dev,
		      const unsigned char * addr)
{
	struct oveth_fdb * f;
	struct oveth_dev * oveth = netdev_priv (dev);

	if (!(ndm->ndm_state & (NUD_PERMANENT | NUD_REACHABLE))) {
		pr_info ("RTM_NEWNEIGH with invalid state %#x\n",
			 ndm->ndm_state);
		return -EINVAL;
	}

	f = find_oveth_fdb_by_mac (oveth, addr);
	if (f == NULL)
		return -ENOENT;

	oveth_fdb_del (f);
	kfree_rcu (f, rcu);

	return 0;
}

static int
oveth_fdb_info (struct sk_buff * skb, struct oveth_dev * oveth,
		const struct oveth_fdb_node * fn, 
		u32 portid, u32 seq, int type, unsigned int flags)
{
	//unsigned long now = jiffies;
	struct nda_cacheinfo ci;
	struct nlmsghdr * nlh;
	struct ndmsg * ndm;
	bool send_ip, send_eth;

	nlh = nlmsg_put (skb, portid, seq, type, sizeof (*ndm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndm = nlmsg_data (nlh);
	memset (ndm, 0, sizeof (*ndm));

	send_eth = send_ip = true;

	if (type == RTM_GETNEIGH) {
		ndm->ndm_family = AF_INET;
		send_ip = fn->node_id != 0;
		send_eth = !is_zero_ether_addr (fn->fdb->eth_addr);
	} else
		ndm->ndm_family = AF_BRIDGE;

	/* fake state ... */
	ndm->ndm_state = (NUD_PERMANENT | NUD_REACHABLE);
	ndm->ndm_ifindex = oveth->dev->ifindex;
	ndm->ndm_flags = NTF_SELF;
	ndm->ndm_type = NDA_DST;

	if (send_eth && nla_put (skb, NDA_LLADDR, ETH_ALEN, 
				 &fn->fdb->eth_addr))
		goto nla_put_failure;
	
	if (send_ip && nla_put_be32 (skb, NDA_DST, fn->node_id))
		goto nla_put_failure;

	/*
	ci.ndm_used		= jiffies_to_clock_t (now - fn->used);
	ci.ndm_updated		= jiffies_to_clock_t (now - fn->updated);
	*/
	ci.ndm_confirmed	= 0;
	ci.ndm_refcnt		= 0;

	if (nla_put (skb, NDA_CACHEINFO, sizeof (ci), &ci))
		goto nla_put_failure;
	
	return nlmsg_end (skb, nlh);

nla_put_failure:
	nlmsg_cancel (skb, nlh);
	return -EMSGSIZE;

}


static int
oveth_ndo_fdb_dump (struct sk_buff * skb, struct netlink_callback * cb,
		    struct net_device * dev, int idx)
{
	int err;
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;
	struct oveth_dev * oveth = netdev_priv (dev);

	list_for_each_entry_rcu (f, &oveth->fdb_chain, chain) {
		if (idx < cb->args[0])
			goto skip;

		list_for_each_entry_rcu (fn, &f->node_id_list, list) {
			err = oveth_fdb_info (skb, oveth, fn,
					      NETLINK_CB (cb->skb).portid,
					      cb->nlh->nlmsg_seq,
					      RTM_NEWNEIGH, NLM_F_MULTI);
			if (err < 0)
				break;
		}
	skip:
		idx++;
	}

	return idx;
}

static const struct net_device_ops oveth_netdev_ops = {
	.ndo_init		= oveth_init,
	.ndo_open		= oveth_open,
	.ndo_stop		= oveth_stop,
	.ndo_start_xmit		= oveth_xmit,
	.ndo_get_stats64	= oveth_stats64,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_fdb_add		= oveth_ndo_fdb_add,
	.ndo_fdb_del		= oveth_ndo_fdb_delete,
	.ndo_fdb_dump		= oveth_ndo_fdb_dump,
};



/*************************************
 *	rtnl_link_ops related
 *************************************/

static struct device_type oveth_type = {
	.name = "oveth",
};

static void
oveth_free (struct net_device * dev)
{
	struct oveth_dev * oveth = netdev_priv (dev);

	free_percpu (oveth->stats);
	free_netdev (dev);

	return;
}

static void
oveth_setup (struct net_device * dev)
{
	struct oveth_dev * oveth = netdev_priv (dev);

	eth_hw_addr_random (dev);
	ether_setup (dev);
	dev->hard_header_len = ETH_HLEN + OVETH_IPV6_HEADROOM;

	dev->netdev_ops = &oveth_netdev_ops;
	dev->destructor = &oveth_free;
	SET_NETDEV_DEVTYPE (dev, &oveth_type);

	dev->tx_queue_len = 0;
	dev->features   |= NETIF_F_LLTX;
	dev->features   |= NETIF_F_NETNS_LOCAL;
	dev->features   |= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features   |= NETIF_F_RXCSUM;

	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;

	oveth->dev = dev;

	return;
}

static int
oveth_validate (struct nlattr * tb[], struct nlattr * data[])
{
	if (tb[IFLA_OVETH_VNI]) {
		__u32 vni = nla_get_u32 (data[IFLA_OVETH_VNI]);
		if (vni >= VNI_MAX)
			return -ERANGE;
	}

	return 0;
}

static int
oveth_newlink (struct net * net, struct net_device * dev,
	       struct nlattr * tb[], struct nlattr * data[])
{
	int n, rc;
	__u32 vni;
	struct oveth_dev * oveth = netdev_priv (dev);
	struct oveth_net * ovnet = net_generic (net, oveth_net_id);

	if (!data) {
		pr_debug ("%s: nlattr data is null\n", __func__);
		return -EINVAL;
	}
	if (!data[IFLA_OVETH_VNI]) {
		pr_debug ("%s: nlatter data OVETH_VNI is null\n", __func__);
		return -EINVAL;
	}

	vni = nla_get_u32 (data[IFLA_OVETH_VNI]);
	if (find_oveth_by_vni (net, vni)) {
		pr_info ("duplicate vni %u\n", vni);
		return -EEXIST;
	}

	oveth->vni = vni;
	INIT_LIST_HEAD (&(oveth->fdb_chain));
	for (n = 0; n < FDB_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&(oveth->fdb_head[n]));

	rc = register_netdevice (dev);
	if (rc == 0) {
		list_add_rcu (&(oveth->list), vni_head (net, oveth->vni));
		list_add_rcu (&(oveth->chain), &(ovnet->vni_chain));
	}

	return rc;
}

static void
oveth_dellink (struct net_device * dev, struct list_head * head)
{
	struct oveth_fdb * f;
	struct list_head * p, * tmp;
	struct oveth_dev * oveth = netdev_priv (dev);
	
	/* destroy fdb */
	list_for_each_safe (p, tmp, &(oveth->fdb_chain)) {
		f = list_entry (p, struct oveth_fdb, chain);
		oveth_fdb_del (f);
	}

	unregister_netdevice_queue (dev, head);

	return;
}

static size_t
oveth_get_size (const struct net_device * dev)
{
	return nla_total_size (sizeof (__u32)) +	/* IFLA_OVETH_VNI */
		nla_total_size (sizeof (__u8)) + 	/* IFLA_OVETH_TTL */
		0;
}


static const struct nla_policy oveth_policy[IFLA_OVETH_MAX + 1] = {
	[IFLA_OVETH_VNI]	= { .type = NLA_U32, },
	[IFLA_OVETH_TTL]	= { .type = NLA_U8, },
};

static struct rtnl_link_ops oveth_link_ops __read_mostly = {
	.kind		= "oveth",
	.maxtype	= IFLA_OVETH_MAX,
	.policy		= oveth_policy,
	.priv_size	= sizeof (struct oveth_dev),
	.setup		= oveth_setup,
	.validate	= oveth_validate,
	.newlink	= oveth_newlink,
	.dellink	= oveth_dellink,
	.get_size	= oveth_get_size,
};



/*************************************
 *	generic netlink operations
 *************************************/


static struct genl_family oveth_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= OVETH_GENL_NAME,
	.version	= OVETH_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= OVETH_ATTR_MAX,
};

static struct nla_policy oveth_nl_policy[OVETH_ATTR_MAX + 1] = {
	[OVETH_ATTR_IFINDEX]	= { .type = NLA_U32, },
	[OVETH_ATTR_NODE_ID]	= { .type = NLA_U32, },
	[OVETH_ATTR_VNI]	= { .type = NLA_U32, },
	[OVETH_ATTR_MACADDR]	= { .type = NLA_BINARY,
				    .len = sizeof (struct in6_addr) },
};


static int
oveth_nl_cmd_fdb_add (struct sk_buff * skb, struct genl_info * info)
{
	__u32 vni;
	__be32 node_id;
	u8 mac[ETH_ALEN];
	struct net * net = genl_info_net (info);
	struct oveth_dev * oveth;
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;

	if (!info->attrs[OVETH_ATTR_VNI] ||
	    !info->attrs[OVETH_ATTR_NODE_ID] || 
	    !info->attrs[OVETH_ATTR_MACADDR] ) {
		return -EINVAL;
	}
	vni = nla_get_u32 (info->attrs[OVETH_ATTR_VNI]);
	node_id = nla_get_be32 (info->attrs[OVETH_ATTR_NODE_ID]);
	nla_memcpy (mac, info->attrs[OVETH_ATTR_MACADDR], ETH_ALEN);

	/* find device, and add entry */
	oveth = find_oveth_by_vni (net, vni);
	if (oveth == NULL) {
		pr_debug ("vni %u does not exists\n", vni);
		return -ENODEV;
	}

	f = find_oveth_fdb_by_mac (oveth, mac);
	if (f == NULL) {
		f = create_oveth_fdb (mac);
		oveth_fdb_add (oveth, f);
	}
	
	fn = oveth_fdb_find_node (f, node_id);
	if (fn == NULL) {
		oveth_fdb_add_node (f, node_id);
	} else {
		return -EEXIST;
	}

	return 0;
}

static int
oveth_nl_cmd_fdb_delete (struct sk_buff * skb, struct genl_info * info)
{
	__u32 vni;
	__be32 node_id;
	u8 mac[ETH_ALEN];
	struct net * net = genl_info_net (info);
	struct oveth_dev * oveth;
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;

	if (!info->attrs[OVETH_ATTR_VNI] ||
	    !info->attrs[OVETH_ATTR_NODE_ID] || 
	    !info->attrs[OVETH_ATTR_MACADDR] ) {
		return -EINVAL;
	}
	vni = nla_get_u32 (info->attrs[OVETH_ATTR_VNI]);
	node_id = nla_get_be32 (info->attrs[OVETH_ATTR_NODE_ID]);
	nla_memcpy (mac, info->attrs[OVETH_ATTR_MACADDR], ETH_ALEN);

	/* find device, and add entry */
	oveth = find_oveth_by_vni (net, vni);
	if (oveth == NULL) {
		pr_debug ("vni %u does not exists\n", vni);
		return -ENODEV;
	}

	if ((f = find_oveth_fdb_by_mac (oveth, mac)) == NULL) 
		return -ENOENT;
	
	if ((fn = oveth_fdb_find_node (f, node_id)) == NULL) 
		return -ENOENT;
	 else 
		oveth_fdb_del_node (f, node_id);

	return 0;
}

static int
oveth_nl_fdb_node_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
			  int cmd, u32 vni, struct oveth_fdb_node * fn)
{
	void * hdr;
	
	if (!skb || !fn)
		return -1;

	hdr = genlmsg_put (skb, pid, seq, &oveth_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	if (nla_put_u32 (skb, OVETH_ATTR_VNI, vni) ||
	    nla_put_be32 (skb, OVETH_ATTR_NODE_ID, fn->node_id) ||
	    nla_put (skb, OVETH_ATTR_MACADDR, ETH_ALEN, fn->fdb->eth_addr)) {
		goto err_out;
	}

	return genlmsg_end (skb, hdr);

err_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}

static int
oveth_nl_cmd_fdb_get (struct sk_buff * skb, struct genl_info * info)
{
	return 0;
}


static int
oveth_nl_cmd_fdb_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	int idx = 0;
	__u32 vni;
	struct net * net = sock_net (skb->sk);
	struct oveth_net * ovnet = net_generic (net, oveth_net_id);
	struct oveth_dev * oveth, * oveth_next;
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;

	/*
	 * cb->args[0] = VNI, cb->args[1] = number of fdb
	 */

	vni = cb->args[0];
	if (vni == 0xFFFFFFFF) 
		goto out;
	
	oveth = find_oveth_by_vni (net, vni);
	if (oveth == NULL)
		goto out;
	
	list_for_each_entry_rcu (f, &(oveth->fdb_chain), chain) {
		if (idx != cb->args[1]) 
			goto skip;

		list_for_each_entry_rcu (fn, &(f->node_id_list), list) {
			oveth_nl_fdb_node_send (skb, 
						NETLINK_CB (cb->skb).portid,
						cb->nlh->nlmsg_seq,
						NLM_F_MULTI,
						OVETH_CMD_FDB_GET,
						vni, fn);
		}
		break;
skip:
		idx++;
	}

	/* set next vni to cb->args[0] */
	if (idx != cb->args[1]) {
		if (oveth->chain.next == &(ovnet->vni_chain)) 
			cb->args[0] = 0xFFFFFFFF;
		else {
			oveth_next = list_entry (oveth->chain.next, 
						 struct oveth_dev, chain);
			cb->args[0] = oveth_next->vni;
		}	
	}

	cb->args[1] = idx + 1;

out:
	return skb->len;
}

static struct genl_ops oveth_nl_ops[] = {
	{
		.cmd = OVETH_CMD_FDB_ADD,
		.doit = oveth_nl_cmd_fdb_add,
		.policy = oveth_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVETH_CMD_FDB_DELETE,
		.doit = oveth_nl_cmd_fdb_delete,
		.policy = oveth_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVETH_CMD_FDB_GET,
		.doit = oveth_nl_cmd_fdb_get,
		.dumpit = oveth_nl_cmd_fdb_dump,
		.policy = oveth_nl_policy,
		/* anyone can show fdb entries  */
	},
};


/*************************************
 *	network name space operations
 *************************************/

static __net_init int
oveth_init_net (struct net * net)
{
	int rc, n;
	struct oveth_net * ovnet = net_generic (net, oveth_net_id);

	memset (ovnet, 0, sizeof (struct oveth_net));

	/* init vni list */
	for (n = 0; n < VNI_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&(ovnet->vni_list[n]));
	INIT_LIST_HEAD (&(ovnet->vni_chain));

	/* register ovstack callback */
	rc = ovstack_register_app_ops (net, OVAPP_ETHERNET,
				       oveth_udp_encap_recv);
	if (!rc) {
		printk (KERN_ERR "failed to register as ovstack app\n");
		return -1;
	}

	return 0;
}


static __net_exit void
oveth_exit_net (struct net * net)
{
	int rc;

	rc = ovstack_unregister_app_ops (net, OVAPP_ETHERNET);
	if (!rc) {
		printk (KERN_ERR "failed to unregister as ovstack app\n");
		return;
	}

	return;
}

static struct pernet_operations oveth_net_ops = {
	.init	= oveth_init_net,
	.exit	= oveth_exit_net,
	.id	= &oveth_net_id,
	.size	= sizeof (struct oveth_net),
};




/*************************************
 *	module init and exit
 *************************************/

static int
__init oveth_init_module (void)
{
	int rc;

	get_random_bytes (&oveth_salt, sizeof (oveth_salt));

	rc = register_pernet_device (&oveth_net_ops);
	if (rc != 0)
		return rc;

	rc = rtnl_link_register (&oveth_link_ops);
	if (rc != 0) {
		unregister_pernet_device (&oveth_net_ops);
		return rc;
	}

	rc = genl_register_family_with_ops (&oveth_nl_family,
					    oveth_nl_ops,
					    ARRAY_SIZE (oveth_nl_ops));
	if (rc != 0) {
		unregister_pernet_device (&oveth_net_ops);
		rtnl_link_unregister (&oveth_link_ops);
		return rc;
	}

	/* set OV_PROTO_ETHER recv ops */

	printk (KERN_INFO "overlay ethernet deriver (version %s) is loaded\n",
		OVETH_VERSION);

	return 0;
}
module_init (oveth_init_module);


static void
__exit oveth_exit_module (void)
{
	genl_unregister_family (&oveth_nl_family);
	rtnl_link_unregister (&oveth_link_ops);
	unregister_pernet_device (&oveth_net_ops);

	printk (KERN_INFO "overlay ethernet driver "
		"(version %s) is unloaded)\n", OVETH_VERSION);

	return;
}
module_exit (oveth_exit_module);
