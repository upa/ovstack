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

#if 0
static void
oveth_sock_free (struct sk_buff * skb)
{
	sock_put (skb->sk);
	return;
}

static void
oveth_set_owner (struct net_device * dev, struct sk_buff * skb)
{
	struct oveth_net * ovnet = net_generic (dev_net (dev), oveth_net_id);
	struct sock * sk = ovnet->sock->sk;

	skb_orphan (skb);
	sock_hold (sk);
	skb->sk = sk;
	skb->destructor = oveth_sock_free;

	return;
}
#endif

static inline netdev_tx_t
oveth_xmit_ipv4_loc (struct sk_buff * skb, struct net_device * dev,
		     struct in_addr * saddr, struct in_addr * daddr, 
		     __be32 node_id, u8 ttl)
{
	int rc;
	struct iphdr * iph;
	struct udphdr * uh;
	struct ovhdr * ovh;
	struct flowi4 fl4;
	struct rtable * rt;
	struct oveth_dev * oveth = netdev_priv (dev);
	unsigned int pkt_len = skb->len;

	memset (&fl4, 0, sizeof (fl4));
	fl4.flowi4_oif = 0;
	fl4.flowi4_tos = 0;
	fl4.saddr = *((__be32 *)(saddr));
	fl4.daddr = *((__be32 *)(daddr));

	rt = ip_route_output_key (dev_net (dev), &fl4);
	if (IS_ERR (rt)) {
		netdev_dbg (dev, "no route to %pI4\n", daddr);
		dev->stats.tx_carrier_errors++;
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}

	if (rt->dst.dev == dev)  {
		netdev_dbg (dev, "circular route to %pI4\n", daddr);
		ip_rt_put (rt);
		dev->stats.collisions++;
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}

	memset (&(IPCB (skb)->opt), 0, sizeof (IPCB (skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);

	skb_dst_drop (skb);
	skb_dst_set (skb, &rt->dst);

	/* setup ovly header, udp header, ip header */
	if (skb_cow_head (skb, OVETH_IPV4_HEADROOM)) {
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}

	ovh = (struct ovhdr *) __skb_push (skb, sizeof (struct ovhdr));
	ovh->ov_version		= OVSTACK_HEADER_VERSION;
	ovh->ov_protocol	= OVSTACK_PROTO_ETHER;
	ovh->ov_ttl		= ttl;
	ovh->ov_flags		= 0;
	ovh->ov_vni		= htonl (oveth->vni << 8);
	ovh->ov_dst		= node_id;
	ovh->ov_src		= ovstack_own_node_id (dev_net (dev));

	__skb_push (skb, sizeof (struct udphdr));
	skb_reset_transport_header (skb);
	uh		= udp_hdr (skb);
	uh->dest	= htons (OVSTACK_PORT);
	uh->source     	= htons (OVSTACK_PORT);
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

	if (net_xmit_eval (rc) == 0) {
		struct oveth_stats * stats = this_cpu_ptr (oveth->stats);
		u64_stats_update_begin (&stats->syncp);
		stats->tx_packets++;
		stats->tx_bytes += pkt_len;
		u64_stats_update_end (&stats->syncp);
	} else {
		dev->stats.tx_errors++;
		dev->stats.tx_aborted_errors++;
	}

	return NETDEV_TX_OK;
}

static inline netdev_tx_t
oveth_xmit_ipv6_loc (struct sk_buff * skb, struct net_device * dev,
		     struct in6_addr * saddr, struct in6_addr * daddr, 
		     __be32 node_id, u8 ttl)
{
	int rc;
	struct ipv6hdr * ip6h;
	struct udphdr * uh;
	struct ovhdr * ovh;
	struct flowi6 fl6;
	struct dst_entry * dst;
	struct oveth_dev * oveth = netdev_priv (dev);
	unsigned int pkt_len = skb->len;

	memset (&fl6, 0, sizeof (fl6));
	fl6.saddr = *saddr;
	fl6.daddr = *daddr;

	dst = ip6_route_output (dev_net (dev), skb->sk, &fl6);
	if (dst->error) {
		netdev_dbg (dev, "no route to %pI6\n", daddr);
		dev->stats.tx_carrier_errors++;
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}

	if (dst->dev == dev) {
		netdev_dbg (dev, "circular route to %pI6\n", daddr);
		dst_free (dst);
		dev->stats.collisions++;
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}


	memset (&(IPCB (skb)->opt), 0, sizeof (IPCB (skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);

	skb_dst_drop (skb);
	skb_dst_set (skb, dst);

	/* setup ovly header, udp header, ip6 header */
	if (skb_cow_head (skb, OVETH_IPV6_HEADROOM)) {
		dev->stats.tx_dropped++;
		dev_kfree_skb (skb);
		return NETDEV_TX_OK;
	}


	ovh = (struct ovhdr *) __skb_push (skb, sizeof (struct ovhdr));
	ovh->ov_version		= OVSTACK_HEADER_VERSION;
	ovh->ov_protocol	= OVSTACK_PROTO_ETHER;
	ovh->ov_ttl		= ttl;
	ovh->ov_flags		= 0;
	ovh->ov_vni		= htonl (oveth->vni << 8);
	ovh->ov_dst		= node_id;
	ovh->ov_src		= ovstack_own_node_id (dev_net (dev));

	__skb_push (skb, sizeof (struct udphdr));
	skb_reset_transport_header (skb);
	uh		= udp_hdr (skb);
	uh->dest	= htons (OVSTACK_PORT);
	uh->source     	= htons (OVSTACK_PORT);
	uh->len		= htons (skb->len);
	uh->check	= 0;

	__skb_push (skb, sizeof (struct ipv6hdr));
        skb_reset_network_header (skb);
	ip6h                    = ipv6_hdr (skb);
	ip6h->version           = 6;
	ip6h->priority          = 0;
	ip6h->flow_lbl[0]       = 0;
	ip6h->flow_lbl[1]       = 0;
	ip6h->flow_lbl[2]       = 0;
	ip6h->payload_len       = htons (skb->len);
	ip6h->nexthdr           = IPPROTO_UDP;
	ip6h->daddr             = *daddr;
	ip6h->saddr             = *saddr;
	ip6h->hop_limit         = 16;


	ovstack_set_owner (dev_net (dev), skb);

	skb->pkt_type = PACKET_HOST;

	rc = ip6_local_out (skb);

	if (net_xmit_eval (rc) == 0) {
		struct oveth_stats * stats = this_cpu_ptr (oveth->stats);
		u64_stats_update_begin (&stats->syncp);
		stats->tx_packets++;
		stats->tx_bytes += pkt_len;
		u64_stats_update_end (&stats->syncp);
	} else {
		dev->stats.tx_errors++;
		dev->stats.tx_aborted_errors++;
	}

	return NETDEV_TX_OK;
}

static inline netdev_tx_t
__oveth_xmit_to_node (struct sk_buff * skb, struct net_device * dev,
			__be32 node_id, u8 ttl)
{
	int ret;
	u32 hash;
	u8 loc4count = 0, loc6count = 0, ai_family = 0;
	struct net * net = dev_net (dev);
	struct ethhdr * eth;

	union addr {
		struct in_addr addr4;
		struct in6_addr addr6;
	} src_addr, dst_addr;

	eth = eth_hdr (skb);
	hash = eth_hash (eth->h_dest);
	loc4count = ovstack_ipv4_loc_count (net);
	loc6count = ovstack_ipv6_loc_count (net);

	/* src locator address */
	if (loc4count && loc6count) 
		ai_family = ovstack_src_loc (&src_addr, net, hash);
	else if (loc4count) 
		ai_family = ovstack_ipv4_src_loc (&src_addr, net, hash);
	else if (loc6count)
		ai_family = ovstack_ipv6_src_loc (&src_addr, net, hash);
	else 
		goto error_drop;

	/* dst locator address */
	if (ai_family == AF_INET) {
		ret = ovstack_ipv4_dst_loc (&dst_addr, net, node_id, hash);
		if (!ret)
			goto error_drop;
		oveth_xmit_ipv4_loc (skb, dev, &src_addr.addr4, 
				     &dst_addr.addr4, node_id, ttl);
	} else if (ai_family == AF_INET6) {
		ret = ovstack_ipv6_dst_loc (&dst_addr, net, node_id, hash);
		if (!ret)
			goto error_drop;
		oveth_xmit_ipv6_loc (skb, dev, &src_addr.addr6,
				     &dst_addr.addr6, node_id, ttl);
	}


	return NETDEV_TX_OK;

error_drop:
	dev->stats.tx_errors++;
	dev->stats.tx_aborted_errors++;
	return NETDEV_TX_OK;
}

static inline netdev_tx_t
__oveth_xmit (struct sk_buff * skb, struct net_device * dev, u8 ttl)
{
	struct sk_buff * mskb;
	struct ethhdr * eth;
	struct oveth_fdb * f;
	struct oveth_fdb_node * fn;
	struct oveth_dev * oveth = netdev_priv (dev);

	if (ttl == 0) {
		return NETDEV_TX_OK;
	}

	skb_reset_mac_header (skb);
	eth = eth_hdr (skb);
	f = find_oveth_fdb_by_mac (oveth, eth->h_dest);
	if (f == NULL) {
		pr_debug ("%s: dst fdb entry does not exist\n", __func__);
		return NETDEV_TX_OK;
	}

	list_for_each_entry_rcu (fn, &(f->node_id_list), list) {
		mskb = skb_clone (skb, GFP_ATOMIC);
		if (likely (mskb))
			__oveth_xmit_to_node (mskb, dev, fn->node_id, ttl);
		else {
			dev->stats.tx_errors++;
			dev->stats.tx_aborted_errors++;
		}
	}
	dev_kfree_skb (skb);

	return NETDEV_TX_OK;
}

static netdev_tx_t
oveth_xmit (struct sk_buff * skb, struct net_device * dev)
{
	return __oveth_xmit (skb, dev, OVSTACK_TTL);
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
	vni = ntohl (ovh->ov_vni) >> 9;
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

	/* destination node check. routing */
	node_id = ovstack_own_node_id (net);
	if (ovh->ov_dst != node_id) {
		__oveth_xmit (skb, oveth->dev, ovh->ov_ttl - 1);
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




static const struct net_device_ops oveth_netdev_ops = {
	.ndo_init		= oveth_init,
	.ndo_open		= oveth_open,
	.ndo_stop		= oveth_stop,
	.ndo_start_xmit		= oveth_xmit,
	.ndo_get_stats64	= oveth_stats64,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
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

	pr_debug ("newlink, vni is %u\n", vni);

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
oveth_nl_cmd_route_add (struct sk_buff * skb, struct genl_info * info)
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
oveth_nl_cmd_route_delete (struct sk_buff * skb, struct genl_info * info)
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
ovstack_nl_fdb_node_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
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
			ovstack_nl_fdb_node_send (skb, 
						  NETLINK_CB (cb->skb).pid,
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
		.cmd = OVETH_CMD_ROUTE_ADD,
		.doit = oveth_nl_cmd_route_add,
		.policy = oveth_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = OVETH_CMD_ROUTE_DELETE,
		.doit = oveth_nl_cmd_route_delete,
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
	int n;
	struct oveth_net * ovnet = net_generic (net, oveth_net_id);

	memset (ovnet, 0, sizeof (struct oveth_net));

	/* init vni list */
	for (n = 0; n < VNI_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&(ovnet->vni_list[n]));
	INIT_LIST_HEAD (&(ovnet->vni_chain));

	return 0;
}


static __net_exit void
oveth_exit_net (struct net * net)
{
	/* nothing to do (?) */
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
	ovstack_register_recv_ops (OVSTACK_PROTO_ETHER, oveth_udp_encap_recv);


	printk (KERN_INFO "overlay ethernet deriver (version %s) is loaded\n",
		OVETH_VERSION);

	return 0;
}
module_init (oveth_init_module);


static void
__exit oveth_exit_module (void)
{
	ovstack_unregister_recv_ops (OVSTACK_PROTO_ETHER);
	genl_unregister_family (&oveth_nl_family);
	rtnl_link_unregister (&oveth_link_ops);
	unregister_pernet_device (&oveth_net_ops);

	printk (KERN_INFO "overlay ethernet driver "
		"(version %s) is unloaded)\n", OVETH_VERSION);

	return;
}
module_exit (oveth_exit_module);
