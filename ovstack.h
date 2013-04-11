/*
 * Overlay Routing Stack
 */

#ifndef _LINUX_OVSTACK_
#define _LINUX_OVSTACK_

#define OVSTACK_PROTO_IP        4
#define OVSTACK_PROTO_IPV6      6
#define OVSTACK_PROTO_ETHER     7
#define OVSTACK_PROTO_MAX       255

#define OVSTACK_TTL		128
#define OVSTACK_PORT            60002


/* overlay header */
struct ovhdr {
	__u8    ov_version;
	__u8    ov_protocol;    /* Next Protocol (Ehter or IP )*/
	__u8    ov_ttl;         /* 1 ~ 255 */
	__u8    ov_flags;       /* OV_FLAG_MULTICAST | OV_FLAG_UNICAST */
	__be32  ov_vni;         /* Virtual Network Identifier */
	__be32  ov_dst;
	__be32  ov_src;
};



/*
 * EXPORT SYMBOLS
 */

__be32 ovstack_own_node_id (struct net * net);


int ovstack_ipv4_loc_count (struct net * net);
int ovstack_ipv6_loc_count (struct net * net);

/* return value : 
 * AF_INET = ipv4 address, AF_INET6 = ipv6 address, 0 = failed 
 */
int ovstack_src_loc (__be32 * addr, struct net * net, u32 hash);
int ovstack_dst_loc (__be32 * addr, struct net * net, 
		     __be32 node_id, u32 hash);

int ovstack_ipv4_src_loc (struct in_addr * addr, struct net * net, u32 hash);
int ovstack_ipv4_dst_loc (struct in_addr * addr, struct net * net, 
			  __be32 node_id, u32 hash);

int ovstack_ipv6_src_loc (struct in6_addr * addr, struct net * net, u32 hash);
int ovstack_ipv6_dst_loc (struct in6_addr * addr, struct net * net, 
			  __be32 node_id, u32 hash);


int ovstack_register_recv_ops (int protocol, int (* proto_recv_ops)
			       (struct sock * sk, struct sk_buff * skb));
int ovstack_unregister_recv_ops (int protocol);





#endif /* _LINUX_OVSTACK_ */
