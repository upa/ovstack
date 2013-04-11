/*
 *	IFLA definitions for oveth are here
 *
 */
#ifndef _LINUX_OVETH_H_
#define _LINUX_OVETH_H_


/* overlay ethernet section */
enum {
	IFLA_OVETH_UNSPEC,
	IFLA_OVETH_VNI,		/* 32bit number	(24bit)	*/
	IFLA_OVETH_ID,		/* 32bit node id	*/
	__IFLA_OVETH_MAX
};

#define IFLA_OVETH_MAX (__IFLA_OVETH_MAX - 1)


/*
 * NETLINK_GENERIC netlink family related.
 */

/*
 * Commands
 *
 * NODE_ID_SET 			- node_id
 * MY_LOCATOR_ADD		- remote_ip, weight
 * MY_LCOATOR_DELETE		- remote_ip,
 * MY_LCOATOR_SET_WEIGHT	- remote_ip, weight
 * LOCATOR_ADD			- node_id, remote_ip, weigth
 * LOCATOR_DELETE		- node_id, remote_ip
 * LOCATOR_SET_WEIGHT		- node_id, remote_ip, weight
 * ROUTE_ADD			- ifindex, mac, node_id
 * ROUTE_DELETE			- ifindex, mac
 * OVETH_CMD_FDB_GET		- ifindex
 * OVETH_CMD_LIB_GET		-
 * OVETH_CMD_LOCATOR_GET	-
 *
 */

enum {
	OVETH_CMD_NODE_ID_SET,
	OVETH_CMD_MY_LOCATOR_ADD,
	OVETH_CMD_MY_LOCATOR_DELETE,
	OVETH_CMD_MY_LOCATOR_SET_WEIGHT,
	OVETH_CMD_LOCATOR_ADD,
	OVETH_CMD_LOCATOR_DELETE,
	OVETH_CMD_LOCATOR_SET_WEIGHT,
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
	OVETH_ATTR_LOCATOR_IP4ADDR,	/* ipv4 address */
	OVETH_ATTR_LOCATOR_IP6ADDR,	/* ipv6 address */
	OVETH_ATTR_LOCATOR_WEIGHT,	/* 8bit weight */
	OVETH_ATTR_MACADDR,		/* 48bit mac address */
	__OVETH_ATTR_MAX,
};

#define OVETH_ATTR_MAX	(__OVETH_ATTR_MAX - 1)

/*
 * NETLINK_GENERIC related info
 */
#define OVETH_GENL_NAME		"oveth"
#define OVETH_GENL_VERSION	0x01

#endif
