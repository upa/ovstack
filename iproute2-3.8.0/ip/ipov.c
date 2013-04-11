/*
 * ipov.c ovstack ip command extension
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/genetlink.h>
#include "../../ovstack_netlink.h"
#include "utils.h"
#include "ip_common.h"
#include "rt_names.h"
#include "libgenl.h"

/* netlink socket */
static struct rtnl_handle genl_rth;
static int genl_family = -1;

struct ovstack_param {
	__u32 node_id;
	int ai_family;
	struct in_addr addr4;
	struct in6_addr addr6;
	u_int8_t weight;
	
	int node_id_flag;
	int addr_flag;
	int weight_flag;

};

static void usage (void) __attribute ((noreturn));


static int
parse_args (int argc, char ** argv, struct ovstack_param * p)
{
	if (argc < 1)
		usage ();

	memset (p, 0, sizeof (struct ovstack_param));

	while (argc > 0) {
		if (strcmp (*argv, "id") == 0) {
			NEXT_ARG ();
			p->node_id = get_addr32 (*argv);
			p->node_id_flag = 1;
                } else if (strcmp (*argv, "addr") == 0) {
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
		} else if (strcmp (*argv, "weight") == 0) {
			NEXT_ARG ();
			if (get_u8 (&(p->weight), *argv,0 )) {
				invarg ("invalid weight\n", *argv);
				exit (-1);
			}
			p->weight_flag = 1;
		} 

		argc--;
		argv++;
	}
	
	return 0;
}


static void
usage (void)
{
	fprintf (stderr,
		 "\n"
		 "Usage:  ip ov [ { add | del } ] [ locator | node ]\n"
		 "		[ id NODEID ]\n"
		 "		[ addr ADDRESS ]\n"
		 "		[ weight WEIGHT ]\n"
		 "\n"
		 "	ip ov set { id | locator | node }\n"
		 "		[ id NODEID ]\n"
		 "		[ addr ADDRESS ]\n"
		 "		[ weight WEIGHT ]\n"
		 "\n"
		 "	ip ov show { id | locator | node }\n"
		 "		[ id NODEID ]\n"
		 "		[ addr ADDRESS ]\n"
		 "\n"
		);

	exit (-1);
}


static int 
do_add_locator (int argc, char **argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_LOCATOR_ADD, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP4ADDR,
			   *((__u32 *)&p.addr4));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP6ADDR,
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid ip address\n");
		return -1;
	}

	if (p.weight_flag)
		addattr8 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_WEIGHT, p.weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;


	return 0;
}

static int 
do_add_node (int argc, char **argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}
	if (p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}


	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVSTACK_ATTR_NODE_ID, p.node_id);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP4ADDR,
			   *((__u32 *)&p.addr4));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP6ADDR,
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid ip address\n");
		return -1;
	}

	if (p.weight_flag)
		addattr8 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_WEIGHT, p.weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_add (int argc, char ** argv)
{
	if (argc < 2) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}
	if (strcmp (*argv, "locator") == 0)
		return do_add_locator (argc - 1, argv + 1);
	if (strcmp (*argv, "node") == 0)
		return do_add_node (argc - 1, argv + 1);
	else {
		fprintf (stderr, "\"add\" can be follow by "
			 "\"locator\" or \"node\"");
		return -1;
	}

	return 0;
}


static int 
do_del_locator (int argc, char **argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_LOCATOR_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP4ADDR,
			   *((__u32 *)&p.addr4));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP6ADDR,
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid ip address\n");
		return -1;
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;


	return 0;
}

static int 
do_del_node (int argc, char **argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}
	if (p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVSTACK_ATTR_NODE_ID, p.node_id);

	switch (p.ai_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP4ADDR,
			   *((__u32 *)&p.addr4));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, OVSTACK_ATTR_LOCATOR_IP6ADDR,
			   &(p.addr6), sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid ip address\n");
		return -1;
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_del (int argc, char ** argv)
{
	if (argc < 2) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}
	if (strcmp (*argv, "locator") == 0)
		return do_del_locator (argc - 1, argv + 1);
	if (strcmp (*argv, "node") == 0)
		return do_del_node (argc - 1, argv + 1);
	else {
		fprintf (stderr, "\"del\" can be follow by "
			 "\"locator\" or \"node\"");
		return -1;
	}

	return 0;
}

static int
do_set_id (int)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_ID_SET, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVSTACK_ATTR_NODE_ID, p.node_id);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set_locator (argc - 1, argv + 1)
{
	return 0
}


static int
do_set_node (argc - 1, argv + 1)
{
	return 0
}

static int
do_set (int argc, char ** argv)
{
	if (argc < 2) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "id") == 0)
		return do _set_id (argc - 1, argv + 1);
	if (strcmp (*argv, "locator")) 
		return do_set_locator (argc - 1, argv + 1);
	if (strcmp (*argv, "node") == 0) 
		return do_set_node (argc - 1, argv + 1);

	return 0;
}

static int
do_show (int argc, char ** argv)
{
	return 0;
}



int
do_ipov (int argc, char **argv)
{
	if (genl_family < 0) {
		if (rtnl_open_byproto (&genl_rth, 0, NETLINK_GENERIC) < 0) {
			fprintf (stderr, "Can't open genetlink socket\n");
			exit (1);
		}
		genl_family = genl_resolve_family (&genl_rth, 
						   OVSTACK_GENL_NAME);
		if (genl_family < 0)
			exit (1);
	}

	if (argc < 1)
		usage ();

	if (matches (*argv, "add") == 0)
		return do_add (argc - 1, argv + 1);

	if (matches (*argv, "del") == 0)
		return do_del (argc - 1, argv + 1);

	if (matches (*argv, "delete") == 0)
		return do_del (argc - 1, argv + 1);

	if (matches (*argv, "set") == 0)
		return do_set (argc - 1, argv + 1);

	if (matches (*argv, "show") == 0)
		return do_show (argc - 1, argv + 1);

	if (matches (*argv, "help") == 0)
		usage ();

	fprintf (stderr,
		 "Command \"%s\" is unknown, try \"ip ov help\".\n", *argv);

	return -1;
}
