/*
 * ipoveth.c overlayed ethernet, ip command extensio
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/genetlink.h>
#include "../../oveth.h"
#include "utils.h"
#include "rt_names.h"
#include "ip_common.h"
#include "libgenl.h"


/* netlink socket */
static struct rtnl_handle genl_rth;
static int genl_family = -1;

struct oveth_param {
	__u32 vni;
	__u32 node_id;
	char mac[ETH_ALEN];

	int vni_flag;
	int node_id_flag;
	int mac_flag;
};

static void usage (void) __attribute ((noreturn));


static int
parse_args (int argc, char ** argv, struct oveth_param * p)
{
	memset (p, 0, sizeof (struct oveth_param));

	if (argc == 0) 
		usage ();

	while (argc > 0) {
		if (!strcmp (*argv, "vni")) {
			NEXT_ARG ();
                        if (get_u32 (&p->vni, *argv, 0) ||
			    p->vni >= 1u << 24)
				invarg ("invalid vni", *argv);
			p->vni_flag++;
		}
		if (!strcmp (*argv, "id") ||
		    !strcmp (*argv, "via")) {
			NEXT_ARG ();
			p->node_id = get_addr32 (*argv);
			p->node_id_flag++;
		}
		if (!strcmp (*argv, "mac") ||
		    !strcmp (*argv, "to")) {
			NEXT_ARG ();
			int len = ll_addr_a2n (p->mac, ETH_ALEN, *argv);
			if (len < 0) 
				invarg ("invalid mac address\n", *argv);
			p->mac_flag++;
		}
		argc--, argv++;
	}

	return 0;
}


static int
do_route_add (int argc, char ** argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.vni_flag) {
		fprintf (stderr, "vni is not specified\n");
		exit (-1);
	}
	if (!p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}
	if (!p.mac_flag) {
		fprintf (stderr, "mac address is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_ROUTE_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVETH_ATTR_VNI, p.vni);
	addattr32 (&req.n, 1024, OVETH_ATTR_NODE_ID, p.node_id);
	addattr_l (&req.n, 1024, OVETH_ATTR_MACADDR, p.mac, ETH_ALEN);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_route_del (int argc, char **argv)
{
	struct oveth_param p;

	parse_args (argc, argv, &p);

	if (!p.vni_flag) {
		fprintf (stderr, "vni is not specified\n");
		exit (-1);
	}
	if (!p.node_id_flag) {
		fprintf (stderr, "node id is not specified\n");
		exit (-1);
	}
	if (!p.mac_flag) {
		fprintf (stderr, "mac address is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_ROUTE_DELETE, NLM_F_REQUEST | NLM_F_ACK);

	addattr32 (&req.n, 1024, OVETH_ATTR_VNI, p.vni);
	addattr32 (&req.n, 1024, OVETH_ATTR_NODE_ID, p.node_id);
	addattr_l (&req.n, 1024, OVETH_ATTR_MACADDR, p.mac, ETH_ALEN);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_route (int argc, char ** argv)
{
	if (!matches (*argv, "add")) 
		return do_route_add (argc - 1, argv + 1);

	if (!matches (*argv, "delete") || !matches (*argv, "del"))
		return do_route_del (argc -1, argv + 1);
	else 
		fprintf (stderr, "unkwnon command \"%s\".\n", *argv);

	exit (-1);
}

static void
print_offset (char * param, int offset)
{
	int n;
	for (n = 0; n < offset - strlen (param); n++) 
		printf (" ");

	return;
}


static int
fdb_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len;
	__u8 mac[ETH_ALEN];
	__u32 vni, node_id;
	char addrbuf4[16], vnibuf[16];
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[OVETH_ATTR_MAX + 1];

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0) {
		fprintf (stderr, "%s: nlmsg length error\n", __func__);
		exit (-1);
	}

	parse_rtattr (attrs, OVETH_ATTR_MAX,
		      (void *) ghdr + GENL_HDRLEN, len);

	if (!attrs[OVETH_ATTR_VNI]) {
		fprintf (stderr, "%s: empty vni\n", __func__);
		exit (-1);
	}
	if (!attrs[OVETH_ATTR_NODE_ID]) {
		fprintf (stderr, "%s: empty node id\n", __func__);
		exit (-1);
	}
	if (!attrs[OVETH_ATTR_MACADDR]) {
		fprintf (stderr, "%s: empty mac address\n", __func__);
		exit (-1);
	}

#define VNI_OFFSET 16
#define MAC_OFFSET 20
#define NODE_ID_OFFSET 42

	vni = rta_getattr_u32 (attrs[OVETH_ATTR_VNI]);
	node_id = rta_getattr_u32 (attrs[OVETH_ATTR_NODE_ID]);
	memcpy (mac, RTA_DATA (attrs[OVETH_ATTR_MACADDR]), ETH_ALEN);

	inet_ntop (AF_INET, &node_id, addrbuf4, sizeof (addrbuf4));
	snprintf (vnibuf, sizeof (vnibuf), "%u", vni);

	printf ("%s", vnibuf);
	print_offset (vnibuf, VNI_OFFSET);
	printf ("%02x:%02x:%02x:%02x:%02x:%02x", 
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	print_offset ("xx:xx:xx:xx:xx:xx", MAC_OFFSET);
	printf ("%s\n", addrbuf4);


	return 0;
}

static int
do_show_fdb (int argc, char ** argv)
{
	GENL_REQUEST (req, 1024, genl_family, 0, OVETH_GENL_VERSION,
		      OVETH_CMD_FDB_GET,
		      NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if (rtnl_send (&genl_rth, &req, req.n.nlmsg_len) < 0)
		return -2;


	printf ("vni");
	print_offset ("vni", VNI_OFFSET);
	printf ("Mac Address");
	print_offset ("Mac Address", MAC_OFFSET);
	printf ("Node id\n");

	if (rtnl_dump_filter (&genl_rth, fdb_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (-1);
	}

	return 0;
}

static int
do_show (int argc, char ** argv)
{
	if (!matches (*argv, "fdb"))
		return do_show_fdb (argc - 1, argv + 1);
	else
		fprintf (stderr, "unkwnon command \"%s\".\n", *argv);

	exit (-1);
}

static void
usage (void)
{
	fprintf (stderr, 
		"Usage : ip oveth route { add | del }\n"
		 "		[ vni VNI ]\n"
		 "		[ to MACADDR ]\n"
		 "		[ via NODEID ]\n"
		 "\n"
		 "	 ip oveth show { fdb }\n"
		 "\n"
		);

	exit (-1);
}

int
do_ipoveth (int argc, char ** argv)
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

	if (!matches (*argv, "route"))
		return do_route (argc - 1, argv + 1);

	if (!matches (*argv, "show"))
		return do_show (argc - 1, argv + 1);

	if (!matches (*argv, "help"))
		usage ();

	fprintf (stderr,
		 "Command \"%s\" is unknown, try \"ip oveth help\".\n", 
		 *argv);

	exit (-1);
}
