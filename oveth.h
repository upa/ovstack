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
	OVETH_CMD_EVENT,		/* event (which is kicked by kmod) */
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
	OVETH_ATTR_EVENT,		/* oveth_genl_event */
	__OVETH_ATTR_MAX,
};

#define OVETH_ATTR_MAX	(__OVETH_ATTR_MAX - 1)

/*
 * NETLINK_GENERIC related info
 */
#define OVETH_GENL_NAME		"oveth"
#define OVETH_GENL_VERSION	0x01
#define OVETH_GENL_MC_GROUP	"oveth_mc_group"



/* notify unknown dst mac packet has come
 *  via netlink, NETLINK_GENERIC, OVETH_GENL_MC_GROUP
 */

enum {
	OVETH_EVENT_UNKNOWN_MAC,	/* destination mac is unknown */
	OVETH_EVENT_UNDER_MAC,		/* new source mac */
};

#ifdef MODULE
/* for oveth  */
struct oveth_genl_event {
	__u8	type;
	__u8	app;
	__be32	vni;
	u8	mac[ETH_ALEN];
};
#else
#include <sys/types.h>

/* for userland application */
struct oveth_genl_event {
	u_int8_t        type;
	u_int8_t        app;
	u_int16_t	pad;
	u_int32_t       vni;
	u_int8_t        mac[ETH_ALEN];
};

#endif

#endif
