/*
 *	IFLA definitions for oveth are here
 *
 */
#ifndef _LINUX_OVETH_H_
#define _LINUX_OVETH_H_


/* overlay ethernet section */
enum {
	IFLA_OVETH_VNI,		/* 32bit number	(24bit)	*/
	__IFLA_OVETH_MAX
};

#define IFLA_OVETH_MAX (__IFLA_OVETH_MAX - 1)



/*
 * NETLINK_GENERIC netlink family related.
 */

/*
 * Commands
 *
 * ROUTE_ADD			- ifindex, mac, node_id
 * ROUTE_DELETE			- ifindex, mac
 * OVETH_CMD_FDB_GET		- ifindex
 * OVETH_CMD_LIB_GET		-
 * OVETH_CMD_LOCATOR_GET	-
 *
 */

enum {
	OVETH_CMD_ROUTE_ADD,
	OVETH_CMD_ROUTE_DELETE,
	OVETH_CMD_FDB_GET,
	OVETH_CMD_LIB_GET,
	OVETH_CMD_LOCATOR_GET,
	__OVETH_CMD_MAX,
};

#define OVETH_CMD_MAX	(__OVETH_CMD_MAX - 1)

/*
 * ATTR types defined for OVETH
 */
enum {
	OVETH_ATTR_NONE,		/* no data */
	OVETH_ATTR_IFINDEX,		/* 32bit interface index */
	OVETH_ATTR_NODE_ID,		/* 32bit node id */
	OVETH_ATTR_VNI,			/* 32bit vni  */
	OVETH_ATTR_LOCATOR_IP4ADDR,	/* ipv4 address */
	OVETH_ATTR_LOCATOR_IP6ADDR,	/* ipv6 address */
	OVETH_ATTR_LOCATOR_WEIGHT,	/* 8bit weight */
	OVETH_ATTR_MACADDR,		/* 48bit mac address */
	OVETH_ATTR_END,			/* 8bit */
	__OVETH_ATTR_MAX,
};

#define OVETH_ATTR_MAX	(__OVETH_ATTR_MAX - 1)

/*
 * NETLINK_GENERIC related info
 */
#define OVETH_GENL_NAME		"oveth"
#define OVETH_GENL_VERSION	0x01

#endif
