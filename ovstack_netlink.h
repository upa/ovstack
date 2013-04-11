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

/*
 * NODE_ID_SET		- node_id : set my node id 
 * LOCATOR_ADD		- remote_ip, weight : add my new locator 
 * LOCATOR_DELETE	- remote_ip : delete my locator 
 * LOCATOR_WEIGHT_SET	- remote_ip, weight : set my locator weight
 * NODE_ADD		- node_id, remote_ip, weight : add new node 
 * NODE_DELETE		- node_id, rempte_ip : delete node (or it's locator)
 * NODE_WEIGHT_SET	- node_id, remote_ip, weight : set weight
 * NODE_ID_GET		- ret node_id : my node id info
 * LOCATOR_GET		- ret remote_ip, weight : my locator info
 * NODE_GET		- ret node_id, or dump : get (or dump) node
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


#endif /* _LINUX_OVSTACK_NETLINK_ */
