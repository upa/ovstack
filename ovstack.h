/*
 * Overlay Routing Stack 
 */

#ifndef _LINUX_OVSTACK_H_
#define _LINUX_OVSTACK_H_

#define OVSTACK_PROTO_IP	4
#define OVSTACK_PROTO_IPV6	6
#define OVSTACK_PROTO_ETHER	7
#define OVSTACK_PROTO_MAX	255

#define OVSTACK_PORT		60002

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
 * 	NETLINK_GENERIC netlink family related.
 */

#define OVSTACK_GENL_NAME	"ovstack"
#define OVSTACK_GENL_VERSION	0x01

/*
 * NODE_ID_SET		- node_id : set my node id 
 * LOCATOR_ADD		- remote_ip, weight : add my new locator 
 * LOCATOR_DELETE	- remote_ip : delete my locator 
 * LOCATOR_WEIGHT_SET	- remote_ip, weight : set my locator weight
 * NODE_ADD		- node_id, remote_ip, weight : add new node 
 * NODE_DELETE		- node_id, rempte_ip : delete node (or it's locator)
 * NODE_WEIGHT_SET	- node_id, remote_ip, weight : set weight
 * NODE_ID_GET		- node_id : my node id info
 * LOCATOR_GET		- remote_ip, weight : my locator info
 * NODE_GET		- node_id, or dump : get (or dump) node
 */

enum {
	OVSTACK_CMD_NODE_ID_SET,
	OVSTACK_CMD_LOCATOR_ADD,
	OVSTACK_CMD_LOCATOR_DELETE,
	OVSTACK_CMD_LOCATOR_WEIGHT_SET,
	OVSTACK_CMD_NODE_ADD,
	OVSTACK_CMD_NODE_DELETE,
	OVSTACK_CMD_NODE_WEIGHT_SET,
	OVSTACK_CMD_NODE_ID_GET,
	OVSTACK_CMD_LOCATOR_GET,
	OVSTACK_CMD_NODE_GET,
	__OVSTACK_CMD_MAX,
};

#define OVSTACK_CMD_MAX	(__OVSTACK_CMD_MAX - 1)

/* ATTR types */
enum {
	OVSTACK_ATTR_NONE,		/* no data */
	OVSTACK_ATTR_NODE_ID,		/* 32bit node id */
	OVSTACK_ATTR_LOCATOR_IP4ADDR,	/* ipv4 address */
	OVSTACK_ATTR_LOCATOR_IP6ADDR,	/* ipv6 address */
	OVSTACK_ATTR_LOCATOR_WEIGHT,	/* 8bit weight */
	__OVSTACK_ATTR_MAX,
};
#define OVSTACK_ATTR_MAX	(__OVSTACK_ATTR_MAX - 1)



/*
 * EXPORT SYMBOLS
 */

__be32 ovstack_own_node_id (struct net * net);

int ovstack_ipv4_src_loc (struct in_addr * addr, struct net * net, u32 hash);
int ovstack_ipv4_dst_loc (struct in_addr * addr,
			  struct net * net, __be32 node_id, u32 hash);

int ovstack_ipv6_src_loc (struct in6_addr * addr, struct net * net, u32 hash);
int ovstack_ipv6_dst_loc (struct in6_addr * addr, 
			  struct net * net, __be32 node_id, u32 hash);

int ovstack_register_recv_ops (int protocol, int (* proto_recv_ops)
			       (struct sock * sk, struct sk_buff * skb));
int ovstack_unregister_recv_ops (int protocol);


#endif /* _LINUX_OVSTACK_ */
