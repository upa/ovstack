
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

static void explain(void)
{
	fprintf(stderr, "Usage: ... emp\n");
}

static int emp_parse_opt (struct link_util * lu, int argc, char ** argv,
			  struct nlmsghdr * n)
{

	__u32 id = 0;
	__u32 saddr = 0;
	__u32 daddr = 0;

	while (argc > 0) {
		if (!matches (*argv, "help")) {
			explain ();
			return -1;
		} else if (!matches (*argv, "id")) {
			NEXT_ARG ();
			get_u32 (&id, *argv, 0);
		} else if (!matches (*argv, "src")) {
			NEXT_ARG ();
			saddr = get_addr32 (*argv);
		} else if (!matches (*argv, "dst")) {
			NEXT_ARG ();
			daddr = get_addr32 (*argv);
		} else {
			fprintf (stderr, "emp: unkown command \"%s\"\n",
				 *argv);
			explain ();
			return -1;
		}

		argc--, argv++;
	}

	addattr32 (n, 1024, IFLA_EMP_ID, id);
	addattr_l (n, 1024, IFLA_EMP_SRC, &saddr, 4);
	addattr_l (n, 1024, IFLA_EMP_DST, &daddr, 4);

	return 0;
}

static void
emp_print_opt (struct link_util * lu, FILE * f, struct rtattr * tb[])
{
	return;
}

struct link_util emp_link_util = {
	.id		= "emp",
	.maxattr	= IFLA_EMP_MAX,
	.parse_opt	= emp_parse_opt,
	.print_opt	= emp_print_opt,
};
