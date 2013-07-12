/*
 *	IFLA definitions for oveth are here
 *
 */
#ifndef _LINUX_OVETH_H_
#define _LINUX_OVETH_H_


/* overlay ethernet section */
enum {
	IFLA_OVETH_UNSEPC,	
	IFLA_OVETH_VNI,		/* 32bit number	(24bit)	*/
	IFLA_OVETH_TTL,		/* 8bit ttl	*/
	__IFLA_OVETH_MAX
};

#define IFLA_OVETH_MAX (__IFLA_OVETH_MAX - 1)



/*
 * NETLINK_GENERIC netlink family related.
 */

/*
 * Commands
 *
 * FDB_ADD			- vni, mac, node_id
 * FDB_DELETE			- vni, mac, node_id
 * OVETH_CMD_FDB_GET		- (vni?)
 *
 */

enum {
	OVETH_CMD_FDB_ADD,		/* mac, vni, node_id */
	OVETH_CMD_FDB_DELETE,		/* mac, vni, node_id */
	OVETH_CMD_FDB_GET,		/* none : vni, mac, node_id */
	__OVETH_CMD_MAX,
};

#define OVETH_CMD_MAX	(__OVETH_CMD_MAX - 1)

/*
 * ATTR types defined for OVETH
 */
enum {
	OVETH_ATTR_IFINDEX,		/* 32bit interface index */
	OVETH_ATTR_NODE_ID,		/* 32bit node id */
	OVETH_ATTR_VNI,			/* 32bit vni  */
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
