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



#define NODE_ID_OFFSET 18
#define ADDRESS_OFFSET 42
	

/* netlink socket */
static struct rtnl_handle genl_rth;
static int genl_family = -1;

struct ovstack_param {
	__u8 app_id;
	__u32 node_id;
	__u32 dst_node_id;
	__u32 nxt_node_id;
	int ai_family;
	struct in_addr addr4;
	struct in6_addr addr6;
	u_int8_t weight;
	
	int app_id_flag;
	int node_id_flag;
	int dst_node_id_flag;
	int nxt_node_id_flag;
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
		if (strcmp (*argv, "app") == 0) {
			NEXT_ARG ();
			if (get_u8 (&p->app_id, *argv, 0)) {
				invarg ("invalid application\n", * argv);
				exit (-1);
			}
			p->app_id_flag = 1;
		} else if (strcmp (*argv, "id") == 0) {
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
			if (get_u8 (&(p->weight), *argv, 0)) {
				invarg ("invalid weight\n", *argv);
				exit (-1);
			}
			p->weight_flag = 1;
		} else if (strcmp (*argv, "to") == 0) {
			NEXT_ARG ();
			p->dst_node_id = get_addr32 (*argv);
			p->dst_node_id_flag = 1;
		} else if (strcmp (*argv, "via") == 0) {
			NEXT_ARG ();
			p->nxt_node_id = get_addr32 (*argv);
			p->nxt_node_id_flag = 1;
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
		 "      ip ov route { add | del }\n"
		 "              [ app APPID ]"
		 "              [ to NODEID ]\n"
		 "              [ via NODEID ]\n"
		 "\n"
		 "	ip ov show { id | locator | node | route }\n"
		 "              [ app APPID ]"
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

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		exit (-1);
	}
	if (!p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_LOCATOR_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);

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

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		exit (-1);
	}
	if (!p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}
	if (!p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);
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

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		exit (-1);
	}
	if (!p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_LOCATOR_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);

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

	if (!p.app_id_flag) {
		fprintf (stderr, "aplication is not specified\n");
		exit (-1);
	}
	if (!p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		exit (-1);
	}
	if (!p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);
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
do_set_id (int argc, char ** argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	
	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		exit (-1);
	}
	if (!p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_ID_SET, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);
	addattr32 (&req.n, 1024, OVSTACK_ATTR_NODE_ID, p.node_id);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set_locator (int argc, char ** argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		return -1;
	}
	if (!p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		return -1;
	}
	if (!p.weight) {
		fprintf (stderr, "weight is not specified\n");
		return -1;
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_LOCATOR_WEIGHT_SET, 
		      NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);

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

	addattr8 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_WEIGHT, p.weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_set_node (int argc, char ** argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		return -1;
	}
	if (!p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		return -1;
	}
	if (!p.addr_flag) {
		fprintf (stderr, "address is not specified\n");
		return -1;
	}
	if (!p.weight) {
		fprintf (stderr, "weight is not specified\n");
		return -1;
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_WEIGHT_SET, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);
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

	addattr8 (&req.n, 1024, OVSTACK_ATTR_LOCATOR_WEIGHT, p.weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set (int argc, char ** argv)
{
	if (argc < 2) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "id") == 0)
		return do_set_id (argc, argv);
	if (strcmp (*argv, "locator") == 0) 
		return do_set_locator (argc - 1, argv + 1);
	if (strcmp (*argv, "node") == 0) 
		return do_set_node (argc - 1, argv + 1);
	else {
		fprintf (stderr, "invalid command \"%s\"", *argv);
		exit (1);
	}

	return 0;
}

static void
print_offset (char * param, int offset)
{
	int n;
	for (n = 0; n < offset - strlen (param); n++) {
		printf (" ");
	}

	return;
}

static int
locator_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len, ai_family = 0;
	__u8 app_id, weight;
	__u32 node_id;
	__u32 addr[4];
	char addrbuf4[16], addrbuf6[64];
	struct genlmsghdr * ghdr;
	struct rtattr *attrs[OVSTACK_ATTR_MAX + 1];

	if (n->nlmsg_type == NLMSG_ERROR) {
		fprintf (stderr, "%s: nlmsg_error\n", __func__);
		return -EBADMSG;
	}

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0) {
		fprintf (stderr, "%s: nlmsg length error\n", __func__);
		return -1;
	}

	parse_rtattr (attrs, OVSTACK_ATTR_MAX, 
		      (void *)ghdr + GENL_HDRLEN, len);

	if (!attrs[OVSTACK_ATTR_APP_ID]) {
		fprintf (stderr, "%s: empty app id\n", __func__);
		return -1;
	}
	if (!attrs[OVSTACK_ATTR_NODE_ID]) {
		fprintf (stderr, "%s: empty node id\n", __func__);
		return -1;
	}
	if (!attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]) {
		fprintf (stderr, "%s: empty weight\n", __func__);
		return -1;
	}
	if (attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]) {
		memcpy (addr, RTA_DATA (attrs[OVSTACK_ATTR_LOCATOR_IP4ADDR]),
			sizeof (struct in_addr));
		ai_family = AF_INET;
	}
	if (attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]) {
		memcpy (addr, RTA_DATA (attrs[OVSTACK_ATTR_LOCATOR_IP6ADDR]),
			sizeof (struct in6_addr));
		ai_family = AF_INET6;
	}
	if (ai_family == 0) {
		fprintf (stderr, "%s: ip address is not defined\n", __func__);
		return -2;
	}
		
	app_id = rta_getattr_u8 (attrs[OVSTACK_ATTR_APP_ID]);

	node_id = rta_getattr_u32 (attrs[OVSTACK_ATTR_NODE_ID]);

	weight = rta_getattr_u8 (attrs[OVSTACK_ATTR_LOCATOR_WEIGHT]);
	inet_ntop (AF_INET, &node_id, addrbuf4, sizeof (addrbuf4));
	inet_ntop (ai_family, addr, addrbuf6, sizeof (addrbuf6));

	printf ("4%d", app_id);
	printf ("%s", addrbuf4);
	print_offset (addrbuf4, NODE_ID_OFFSET);
	printf ("%s", addrbuf6);
	print_offset (addrbuf6, ADDRESS_OFFSET);
	printf ("%d\n", weight);

	return 0;
}

static int
id_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len;
	__u8 app_id;
	__u32 node_id;
	char addrbuf4[16];
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[OVSTACK_ATTR_MAX + 1];

	if (n->nlmsg_type == NLMSG_ERROR) {
		fprintf (stderr, "%s: nlmsg_error\n", __func__);
		return -EBADMSG;
	}

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0) {
		fprintf (stderr, "%s: nlmsg length error\n", __func__);
		return -1;
	}

	parse_rtattr (attrs, OVSTACK_ATTR_MAX, 
		      (void *) ghdr + GENL_HDRLEN, len);

	if (!attrs[OVSTACK_ATTR_APP_ID]) {
		fprintf (stderr, "%s: empty app id\n", __func__);
		return -1;
	}
	if (!attrs[OVSTACK_ATTR_NODE_ID]) {
		fprintf (stderr, "%s: empty node id\n", __func__);
		return -1;
	}

	app_id = rta_getattr_u8 (attrs[OVSTACK_ATTR_APP_ID]);
	node_id = rta_getattr_u32 (attrs[OVSTACK_ATTR_NODE_ID]);
	inet_ntop (AF_INET, &node_id, addrbuf4, sizeof (addrbuf4));

	printf ("%4d %s\n", app_id, addrbuf4);

	return 0;
}

static int
route_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len;
	char addrbuf4[16];
	__u8 app_id;
	__u32 dst_node_id, nxt_node_id;
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[OVSTACK_ATTR_MAX + 1];


	if (n->nlmsg_type == NLMSG_ERROR) {
		fprintf (stderr, "%s: nlmsg_error\n", __func__);
		return -EBADMSG;
	}

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0) {
		fprintf (stderr, "%s: nlmsg length error\n", __func__);
		return -1;
	}

	parse_rtattr (attrs, OVSTACK_ATTR_MAX, 
		      (void *) ghdr + GENL_HDRLEN, len);

	if (!attrs[OVSTACK_ATTR_APP_ID]) {
		fprintf (stderr, "%s: emptu app id\n", __func__);
		return -1;
	}
	if (!attrs[OVSTACK_ATTR_DST_NODE_ID]) {
		fprintf (stderr, "%s: empty destination node id\n", __func__);
		return -1;
	}
	if (!attrs[OVSTACK_ATTR_NXT_NODE_ID]) {
		fprintf (stderr, "%s: empty next hop node id\n", __func__);
		return -1;
	}
	
	app_id = rta_getattr_u8 (attrs[OVSTACK_ATTR_APP_ID]);
	dst_node_id = rta_getattr_u32 (attrs[OVSTACK_ATTR_DST_NODE_ID]);
	nxt_node_id = rta_getattr_u32 (attrs[OVSTACK_ATTR_NXT_NODE_ID]);

	printf ("%4d ", app_id);
	inet_ntop (AF_INET, &dst_node_id, addrbuf4, sizeof (addrbuf4));
	print_offset (addrbuf4, ADDRESS_OFFSET);
	printf (" via ");
	inet_ntop (AF_INET, &nxt_node_id, addrbuf4, sizeof (addrbuf4));
	print_offset (addrbuf4, ADDRESS_OFFSET);
	printf ("\n");
	
	return 0;
}

static int
do_show_id (int argc, char ** argv)
{
	int ret;

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_ID_GET, NLM_F_REQUEST | NLM_F_ROOT);

	if ((ret = rtnl_send (&genl_rth, &req.n, req.n.nlmsg_len)) < 0) {
		printf ("%d\n", ret);
		return -2;
	}
	
	if (rtnl_dump_filter (&genl_rth, id_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

static int
do_show_locator (int argc, char ** argv)
{
	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_LOCATOR_GET, 
		      NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if (rtnl_send (&genl_rth, &req, req.n.nlmsg_len) < 0)	
		return -2;

	printf ("Node id");
	print_offset ("Node id", NODE_ID_OFFSET);
	printf ("Locator address");
	print_offset ("Locator address", ADDRESS_OFFSET);
	printf ("Weight\n");

	if (rtnl_dump_filter (&genl_rth, locator_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

static int
do_show_node (int argc, char ** argv)
{
	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_NODE_GET, 
		      NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if (rtnl_send (&genl_rth, &req, req.n.nlmsg_len) < 0)	
		return -2;

	printf ("Node id");
	print_offset ("Node id", NODE_ID_OFFSET);
	printf ("Locator address");
	print_offset ("Locator address", ADDRESS_OFFSET);
	printf ("Weight\n");

	if (rtnl_dump_filter (&genl_rth, locator_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		return -1;
	}

	return 0;
}


static int
do_show_route (int argc, char ** argv)
{
	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_ROUTE_GET,
		      NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if (rtnl_send (&genl_rth, &req, req.n.nlmsg_len) < 0)
		return -2;

	if (rtnl_dump_filter (&genl_rth, route_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		return -1;
	}

	return 0;
}

static int
do_show (int argc, char ** argv)
{
	if (argc < 1) {
		printf ("invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "id") == 0)
		return do_show_id (argc - 1, argv + 1);
	if (strcmp (*argv, "locator") == 0)
		return do_show_locator (argc - 1, argv + 1);
	if (strcmp (*argv, "node") == 0) 
		return do_show_node (argc - 1, argv + 1);
	if (strcmp (*argv, "route") == 0)
		return do_show_route (argc - 1, argv + 1);
	else {
		fprintf (stderr, "unknwon command \"%s\".\n", *argv);
		return -1;
	}

	return 0;
}

static int
do_route_add (int argc, char ** argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		exit (-1);
	}
	if (!p.dst_node_id_flag) {
		fprintf (stderr, "destination node id is not specified\n");
		exit (-1);
	}
	if (!p.nxt_node_id_flag) {
		fprintf (stderr, "next hop node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_ROUTE_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);
	addattr32 (&req.n, 1024, OVSTACK_ATTR_DST_NODE_ID, p.dst_node_id);
	addattr32 (&req.n, 1024, OVSTACK_ATTR_NXT_NODE_ID, p.nxt_node_id);
	
	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_route_del (int argc, char ** argv)
{
	struct ovstack_param p;

	parse_args (argc, argv, &p);

	if (!p.app_id_flag) {
		fprintf (stderr, "application is not specified\n");
		exit (-1);
	}
	if (!p.dst_node_id_flag) {
		fprintf (stderr, "destination node id is not specified\n");
		exit (-1);
	}
	if (!p.nxt_node_id_flag) {
		fprintf (stderr, "next hop node id is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVSTACK_GENL_VERSION,
		      OVSTACK_CMD_ROUTE_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, 1024, OVSTACK_ATTR_APP_ID, p.app_id);
	addattr32 (&req.n, 1024, OVSTACK_ATTR_DST_NODE_ID, p.dst_node_id);
	addattr32 (&req.n, 1024, OVSTACK_ATTR_NXT_NODE_ID, p.nxt_node_id);
	
	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_route (int argc, char ** argv)
{
	if (argc < 1) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "add") == 0)
		return do_route_add (argc - 1, argv + 1);
	if (strcmp (*argv, "del") == 0) 
		return do_route_del (argc - 1, argv + 1);
	if (strcmp (*argv, "delete") == 0) 
		return do_route_del (argc - 1, argv + 1);
	else {
		fprintf (stderr, "unknown command \"%s\".\n", *argv);
		return -1;
	}

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

	if (matches (*argv, "route") == 0)
		return do_route (argc -1, argv + 1);

	if (matches (*argv, "help") == 0)
		usage ();

	fprintf (stderr,
		 "Command \"%s\" is unknown, try \"ip ov help\".\n", *argv);

	return -1;
}
