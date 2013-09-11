/*
 * Overlay Routing Stack Netlink Definitions
 */

#ifndef _LINUX_OVSTACK_NETLINK_H_
#define _LINUX_OVSTACK_NETLINK_H_

/*
 * 	NETLINK_GENERIC netlink family related.
 */

#define OVSTACK_GENL_NAME	"ovstack"
#define OVSTACK_GENL_VERSION	0x01
#define OVSTACK_GENL_MC_GROUP	"ovstack"

/*
 * NODE_ID_SET		- app_id, node_id : set my node id 
 * LOCATOR_ADD		- app_id, remote_ip, weight : add my new locator 
 * LOCATOR_DELETE	- app_id, remote_ip : delete my locator 
 * LOCATOR_WEIGHT_SET	- app_id, remote_ip, weight : set my locator weight
 * NODE_ADD		- app_id, node_id, remote_ip, weight : add new node 
 * NODE_DELETE		- app_id, node_id, rempte_ip : delete node 
 * NODE_WEIGHT_SET	- app_id, node_id, remote_ip, weight : set weight
 * NODE_ID_GET		- app_id, ret node_id : my node id info
 * LOCATOR_GET		- app_id, ret remote_ip, weight : my locator info
 * NODE_GET		- app_id, ret node_id, or dump : get (or dump) node

 * ROUTE_ADD		- app_id, dst_node_id, nxt_node_id
 * ROUTE_DEL		- app_id, dst_node_id, nxt_node_id
 * ROUTE_GET		- app_id, ret dst_node_id, nxt_node_id

 */

enum {
	OVSTACK_CMD_NODE_ID_SET,
	OVSTACK_CMD_LOCATOR_ADD,
	OVSTACK_CMD_LOCATOR_DELETE,
	OVSTACK_CMD_LOCATOR_WEIGHT_SET,
	OVSTACK_CMD_NODE_ADD,
	OVSTACK_CMD_NODE_DELETE,
	OVSTACK_CMD_NODE_WEIGHT_SET,

	OVSTACK_CMD_APP_ID_GET,
	OVSTACK_CMD_NODE_ID_GET,
	OVSTACK_CMD_LOCATOR_GET,
	OVSTACK_CMD_NODE_GET,

	OVSTACK_CMD_ROUTE_ADD,
	OVSTACK_CMD_ROUTE_DELETE,
	OVSTACK_CMD_ROUTE_GET,

	OVSTACK_CMD_EVENT,
	__OVSTACK_CMD_MAX,
};

#define OVSTACK_CMD_MAX	(__OVSTACK_CMD_MAX - 1)

/* ATTR types */
enum {
	OVSTACK_ATTR_NONE,		/* no data */
	OVSTACK_ATTR_NODE_ID,		/* 32bit node id */
	OVSTACK_ATTR_DST_NODE_ID,	/* 32bit node id */
	OVSTACK_ATTR_NXT_NODE_ID,	/* 32bit node id */
	OVSTACK_ATTR_APP_ID,		/* 8bit app id */
	OVSTACK_ATTR_LOCATOR_IP4ADDR,	/* ipv4 address */
	OVSTACK_ATTR_LOCATOR_IP6ADDR,	/* ipv6 address */
	OVSTACK_ATTR_LOCATOR_WEIGHT,	/* 8bit weight */
	OVSTACK_ATTR_EVENT,		/* ovstack_genl_event_* */
	__OVSTACK_ATTR_MAX,
};
#define OVSTACK_ATTR_MAX	(__OVSTACK_ATTR_MAX - 1)


/*
  notify operations.
  change node id, add locator, delete locator
 */


#define OVSTACK_GENL_EVENT_NAME		"ovstack"
#define OVSTACK_GENL_EVENT_VERSION	0x01
#define OVSTACK_GENL_EVENT_MC_GROUP	"ovstack_mc_group"


enum {
	OVSTACK_EVENT_NODE_ID_SET,
	OVSTACK_EVENT_LOCATOR_ADD,
	OVSTACK_EVENT_LOCATOR_DELETE,
	OVSTACK_EVENT_LOCATOR_UPDATE,
	__OVSTACK_EVENT_MAX
};

#ifdef MODULE
/* for ovstack kernel module internal */
struct ovstack_genl_event {
	__u8	app;
	__u8	type;

	__u8	weight;
	__u8	family;
	__be32	node_id;

	union {
		__be32	__loc_addr4[1];
		__be32	__loc_addr6[4];
	} remote_ip;
};

#else
/* for userland applications */
#include <sys/types.h>
#include <netinet/in.h>

struct ovstack_genl_event {
	u_int8_t	app;
	u_int8_t	type;

	u_int8_t	weight;
	u_int8_t	family;
	struct in_addr	node_id;
	
	union {
		struct in_addr	remote_ip4;
		struct in6_addr	remote_ip6;
	} remote_ip;
};

#endif


#endif /* _LINUX_OVSTACK_NETLINK_ */
