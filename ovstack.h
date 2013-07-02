/*
 * Overlay Routing Stack
 */

#ifndef _LINUX_OVSTACK_
#define _LINUX_OVSTACK_

#define OVSTACK_APP_IP        4
#define OVSTACK_APP_IPV6      6
#define OVSTACK_APP_ETHER     7
#define OVSTACK_APP_MAX       255

#define OVSTACK_TTL		128
#define OVSTACK_PORT            60002
#define OVSTACK_HEADER_VERSION	1


/* overlay header */
/*
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    version    |      app      |      TTL      |     Flags     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                VXLAN Network Identifier (VNI) |      rsv      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                              Hash                             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  overlay destination node address             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    overlay source node address                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ovhdr {
	__u8    ov_version;
	__u8    ov_ttl;         /* 1 ~ 255 */
	__u8 	ov_app;   	/* Next Application */
	__u8 	ov_flags;   	/* Flags */
	__be32  ov_vni;         /* Virtual Network Identifier + hash	*/
	__be32  ov_hash;
	__be32  ov_dst;
	__be32  ov_src;
};
#define ovh_rsv(h) (ntohl ((h)->ov_vni) & 0x000000FF)
#define ovh_vni(h) (ntohl ((h)->ov_vni) >> 8)



/*
 * EXPORT SYMBOLS
 */

__be32 ovstack_own_node_id (struct net * net, u8 app);


int ovstack_ipv4_loc_count (struct net * net, u8 app);
int ovstack_ipv6_loc_count (struct net * net, u8 app);

/* return value : 
 * AF_INET = ipv4 address, AF_INET6 = ipv6 address, 0 = failed 
 */
int ovstack_src_loc (void * addr, struct net * net, u8 app, u32 hash);
int ovstack_dst_loc (void * addr, struct net * net, u8 app,
		     __be32 node_id, u32 hash);

int ovstack_ipv4_src_loc (void * addr, struct net * net, u8 app, u32 hash);
int ovstack_ipv4_dst_loc (void * addr, struct net * net, u8 app,
			  __be32 node_id, u32 hash);

int ovstack_ipv6_src_loc (void * addr, struct net * net, u8 app, u32 hash);
int ovstack_ipv6_dst_loc (void * addr, struct net * net, u8 app,
			  __be32 node_id, u32 hash);


int ovstack_register_app_ops (struct net * net, int app, int (* proto_recv_ops)
			      (struct sock * sk, struct sk_buff * skb));
int ovstack_unregister_app_ops (struct net * net, int app);

void ovstack_set_owner (struct net * net, struct sk_buff * skb);

int ovstack_output (struct sk_buff * skb, __be32 hash);


#endif /* _LINUX_OVSTACK_ */
