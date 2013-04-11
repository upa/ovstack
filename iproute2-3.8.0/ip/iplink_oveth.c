
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "oveth.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... oveth\n");
}

static int oveth_parse_opt (struct link_util * lu, int argc, char ** argv,
			  struct nlmsghdr * n)
{

	__u32 id = 0, vni = 0;

	while (argc > 0) {
		if (!matches (*argv, "help")) {
			explain ();
			return -1;
		} else if (!matches (*argv, "id")) {
			NEXT_ARG ();
			id = get_addr32 (*argv);
		} else if (!matches (*argv, "vni")) {
			NEXT_ARG ();
			get_u32 (&vni, *argv, 0);
		} else {
			fprintf (stderr, "oveth: unkown command \"%s\"\n",
				 *argv);
			explain ();
			return -1;
		}

		argc--, argv++;
	}

	addattr32 (n, 1024, IFLA_OVETH_ID, id);
	addattr32 (n, 1024, IFLA_OVETH_VNI, vni);

	return 0;
}

static void
oveth_print_opt (struct link_util * lu, FILE * f, struct rtattr * tb[])
{
	return;
}

struct link_util oveth_link_util = {
	.id		= "oveth",
	.maxattr	= IFLA_OVETH_MAX,
	.parse_opt	= oveth_parse_opt,
	.print_opt	= oveth_print_opt,
};
