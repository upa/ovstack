/*
 * iplink_oveth.c
 *	overlayed ethernet driver
 *
 */

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
#include "../../oveth.h"


static void explain (void)
{
	fprintf (stderr,
		 "Usage: ... oveth vni VNI\n"
		 "routing settings are configured by "
		 "\"ip ov\" and \"ipv oveth\".\n"
		);
}

static int 
oveth_parse_opt (struct link_util * lu, int argc, char ** argv,
		 struct nlmsghdr * n)
{
	__u32 vni;
	int vni_flag = 0;


	while (argc > 0) {
		if (!matches (*argv, "help")) {
			explain ();
			exit (-1);
		} else if (!matches (*argv, "vni")) {
			NEXT_ARG ();
			if (get_u32 (&vni, *argv, 0) ||
			    vni >= 1u << 24)
				invarg ("invalid vni", *argv);
			vni_flag++;
		} else {
			fprintf (stderr, "oveth: unknown command \"%s\"\n",
				 *argv);
			exit (-1);
		}

		argc--, argv++;
	}

	if (vni_flag == 0) {
		fprintf (stderr, "vni is not specified\n");
		exit (-1);
	}

	addattr32 (n, 1024, IFLA_OVETH_VNI, vni);

	return 0;
}


static void
oveth_print_opt (struct link_util * lu, FILE * f, struct rtattr *tb[])
{
	return;
}

struct link_util oveth_link_util = {
	.id		= "oveth",
	.maxattr	= IFLA_OVETH_MAX,
	.parse_opt	= oveth_parse_opt,
	.print_opt	= oveth_print_opt,
};
