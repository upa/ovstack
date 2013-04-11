/*
 * ipoveth.c
 */

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/genetlink.h>

#include "oveth.h"
#include "utils.h"
#include "ip_common.h"
#include "rt_names.h"
#include "libgenl.h"


/* netlink socket */
static struct rtnl_handle genl_rth;
static int genl_family = -1;



struct oveth_param {
	__u32 node_id;
	int ai_family;
	__u32 addr4;
	struct in6_addr addr6;
	u_int8_t weight;
	char mac[ETH_ALEN];
	char dev[IFNAMSIZ];

	int node_id_flag;
	int addr_flag;
	int weight_flag;
	int mac_flag;
	int dev_flag;
};


static void usage (void) __attribute((noreturn));



static int
parse_args (int argc, char ** argv, struct oveth_param * p)
{
	memset (p, 0, sizeof (struct oveth_param));

	if (argc == 0)
		usage ();

	while (argc > 0) {
		if (strcmp (*argv, "id")) {
			NEXT_ARG ();
			p->node_id = get_addr32 (*argv);
			p->node_id_flag = 1;
		}

		if (strcmp (*argv, "addr")) {
			NEXT_ARG ();
			if (inet_pton (AF_INET, *argv, &(p->addr4)) > 0)
				p->ai_family = AF_INET;
			else if (inet_pton (AF_INET6, *argv, &(p->addr6)) > 0)
				p->ai_family = AF_INET6;
			else {
				invarg ("invalid address\n", *argv);
				exit (-1);
			}
			p->addr_flag = 1;
		} else if (strcmp (*argv, "weight")) {
			NEXT_ARG ();
			if (get_u8 (&(p->weight), *argv,0 ))
				invarg ("invalid weight\n", *argv);
			p->weight_flag = 1;
		} else if (strcmp (*argv, "to")) {
			NEXT_ARG();
			int len = ll_addr_a2n(p->mac, ETH_ALEN, *argv);
			if (len < 0) {
				invarg ("invalid mac address\n", *argv);
				exit (-1);
			}
			p->mac_flag = 1;
		} else if (strcmp (*argv, "via")) {
			NEXT_ARG ();
			p->node_id = get_addr32 (*argv);
			p->node_id_flag = 1;
		} else if (strcmp (*argv, "dev")) {
			NEXT_ARG ();
			strncpy (p->dev, *argv, IFNAMSIZ);
			if (if_nametoindex (p->dev) == 0) {
				invarg ("invalid device name\n", *argv);
				exit (-1);
			}
			p->dev_flag = 1;
		}
		
		argc--; 
		argv++;
	}

	return 0;
}


static int
do_add_locator (int argc, char **argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.addr_flag | !p.node_id_flag) {
		return -1;
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_LOCATOR_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVETH_ATTR_NODE_ID, p.node_id);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVETH_ATTR_LOCATOR_IP4ADDR, p.addr4);
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVETH_ATTR_LOCATOR_IP6ADDR, 
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		return -1;
	}

	if (p.weight_flag) 
		addattr8 (&req.n, 1024, OVETH_ATTR_LOCATOR_WEIGHT, p.weight);


	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_add_mylocator (int argc, char **argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.addr_flag) 
		return -1;

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_MY_LOCATOR_ADD, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVETH_ATTR_LOCATOR_IP4ADDR, p.addr4);
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVETH_ATTR_LOCATOR_IP6ADDR, 
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		return -1;
	}

	if (p.weight_flag) 
		addattr8 (&req.n, 1024, OVETH_ATTR_LOCATOR_WEIGHT, p.weight);


	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_add (int argc, char ** argv)
{
	if (strcmp (*argv, "locator") == 0) 
		return do_add_locator (argc - 1, argv + 1);
	else if (strcmp (*argv, "mylocator") == 0) 
		return do_add_mylocator (argc - 1, argv + 1);

	usage ();
	return -1;
}

static int
do_del_locator (int argc, char **argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.addr_flag | !p.node_id_flag) 
		return -1;

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_LOCATOR_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVETH_ATTR_NODE_ID, p.node_id);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVETH_ATTR_LOCATOR_IP4ADDR, p.addr4);
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVETH_ATTR_LOCATOR_IP6ADDR, 
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		return -1;
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_del_mylocator (int argc, char **argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.addr_flag) 
		return -1;

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_MY_LOCATOR_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVETH_ATTR_LOCATOR_IP4ADDR, p.addr4);
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVETH_ATTR_LOCATOR_IP6ADDR, 
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		return -1;
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_del (int argc, char ** argv)
{
	if (strcmp (*argv, "locator") == 0)
		return do_del_locator (argc - 1, argv + 1);
	else if (strcmp (*argv, "mylocator") == 0)
		return do_del_mylocator (argc - 1, argv + 1);

	usage ();
	return -1;
}

static int
do_set_mylocator (int argc, char ** argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.addr_flag | !p.weight_flag) 
		return -1;

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_LOCATOR_SET_WEIGHT, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVETH_ATTR_LOCATOR_IP4ADDR, p.addr4);
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVETH_ATTR_LOCATOR_IP6ADDR, 
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		return -1;
	}

	addattr8 (&req.n, 1024, OVETH_ATTR_LOCATOR_WEIGHT, p.weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set_id (int argc, char ** argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.node_id) 
		return -1;

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_NODE_ID_SET, NLM_F_REQUEST | NLM_F_ACK);
	
	addattr32 (&req.n, 1024, OVETH_ATTR_NODE_ID, p.node_id);
	
	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;
	
	return 0;
}

static int
do_set (int argc, char ** argv)
{

	if (strcmp (*argv, "mylocator") == 0) 
		return do_set_mylocator (argc - 1, argv + 1);
	else
		return do_set_id (argc, argv);


	return -1;
}

static int
do_show_fdb (int argc, char ** argv)
{
	return 0;
}

static int
do_show_lib (void)
{
	return 0;
}

static int
do_show_locator (void)
{
	return 0;
}

static int
do_show (int argc, char ** argv)
{
	if (strcmp (*argv, "fdb") == 0)
		return do_show_fdb (argc - 1, argv + 1);
	else if (strcmp (*argv, "lib") == 0)
		return do_show_lib ();
	else if (strcmp (*argv, "locator") == 0)
		return do_show_locator ();

	return -1;
}

static int
do_route (int argc, char ** argv)
{
	return -1;
}


static void 
usage (void)
{
	fprintf (stderr, 
		 "Usage: ip oveth add mylocator\n"
		 "		[ addr ADDRESS]\n"
		 "		[ weight WEIGHT]\n"
		 "	 ip oveth add locator\n"
		 "		[ id NODEID ]\n"	
		 "		[ addr ADDRESS ]\n"
		 "		[ weight WEIGHT]\n"
		 "\n"
		 "	 ip oveth delete mylocator addr ADDRESS\n"
		 "	 ip oveth delete locator\n"
		 "		[ id NODEID ]\n"
		 "		[ addr ADDRESS ]\n"
		 "\n"
		 "	 ip oveth set id NODEID\n"
		 "	 ip oveth set mylocator\n"
		 "		[ addr ADDRESS ]\n"
		 "		[ weight WEIGHT]\n"
		 "\n"
		 "	 ip oveth show { fdb dev DEVICE | lib | locator }\n"
		 "\n"
		 "	 ip oveth route { add | del }\n"
		 "		[ to MACADDRESS ]\n"
		 "		[ via NODEID ]\n"
		);

	exit (-1);
}

int
do_ipoveth (int argc, char **argv)
{
	if (genl_family < 0) {
		if (rtnl_open_byproto (&genl_rth, 0, NETLINK_GENERIC) < 0) {
			fprintf (stderr, "Can't open genetlink socket\n");
			exit (1);
		}
		genl_family = genl_resolve_family (&genl_rth, OVETH_GENL_NAME);
		if (genl_family < 0)
			exit (1);
	}

	if (argc < 1)
		usage ();

	if (matches (*argv, "add") == 0)
		return do_add (argc - 1, argv + 1);

	if (matches (*argv, "del") == 0 || matches (*argv, "delete") == 0)
		return do_del (argc - 1, argv + 1);

	if (matches (*argv, "set") == 0)
		return do_set (argc - 1, argv + 1);

	if (matches (*argv, "show") == 0)
		return do_show (argc - 1, argv + 1);

	if (matches (*argv, "route") == 0)
		return do_route (argc - 1, argv + 1);

	if (matches (*argv, "help") == 0)
		usage ();

	fprintf (stderr,
		 "Command \"%s\" is unknown, try \"ip oveth help\".\n",
		 *argv);
	exit (-1);
}
