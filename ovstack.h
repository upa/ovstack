/*
 * Overlay Routing Stack
 */

#ifndef _LINUX_OVSTACK_
#define _LINUX_OVSTACK_

#include <linux/netdevice.h>
#include <net/net_namespace.h>

#define OVSTACK_APP_IP        4
#define OVSTACK_APP_IPV6      6
#define OVSTACK_APP_ETHER     7
#define OVSTACK_APP_MAX       255

#define OVSTACK_TTL		128
#define OVSTACK_PORT            60002
#define OVSTACK_HEADER_VERSION	1

#define IPPROTO_OVSTACK		253

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
int ovstack_register_app_ops (struct net * net, int app,
			      int (*app_recv_ops) (struct sk_buff * skb));
int ovstack_unregister_app_ops (struct net * net, int app);

netdev_tx_t ovstack_xmit (struct sk_buff * skb, struct net_device * dev);



/*
 * ovstack applications
 */

#define OVAPP_DUMMY	0
#define OVAPP_DUMMY2	1
#define OVAPP_IP	4
#define OVAPP_IPV6	6
#define	OVAPP_ETHERNET	7



#endif /* _LINUX_OVSTACK_ */
