/*
 * Get/set/delete fdb table with netlink
 *
 * TODO: merge/replace this with ip neighbour
 *
 * Authors:	Stephen Hemminger <shemminger@vyatta.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <string.h>

#include "libnetlink.h"
#include "br_common.h"
#include "rt_names.h"
#include "utils.h"

int filter_index;

static void usage(void)
{
	fprintf(stderr, "Usage: bridge fdb { add | del } ADDR dev DEV {self|master} [ temp ] [ dst IPADDR]\n");
	fprintf(stderr, "       bridge fdb {show} [ dev DEV ]\n");
	exit(-1);
}

static const char *state_n2a(unsigned s)
{
	static char buf[32];

	if (s & NUD_PERMANENT)
		return "permanent";

	if (s & NUD_NOARP)
		return "static";

	if (s & NUD_STALE)
		return "stale";

	if (s & NUD_REACHABLE)
		return "";

	sprintf(buf, "state=%#x", s);
	return buf;
}

int print_fdb(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[NDA_MAX+1];

	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		fprintf(stderr, "Not RTM_NEWNEIGH: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);

		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (r->ndm_family != AF_BRIDGE)
		return 0;

	if (filter_index && filter_index != r->ndm_ifindex)
		return 0;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (n->nlmsg_type == RTM_DELNEIGH)
		fprintf(fp, "Deleted ");

	if (tb[NDA_LLADDR]) {
		SPRINT_BUF(b1);
		fprintf(fp, "%s ",
			ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
				    RTA_PAYLOAD(tb[NDA_LLADDR]),
				    ll_index_to_type(r->ndm_ifindex),
				    b1, sizeof(b1)));
	}

	if (!filter_index && r->ndm_ifindex)
		fprintf(fp, "dev %s ", ll_index_to_name(r->ndm_ifindex));

	if (tb[NDA_DST]) {
		SPRINT_BUF(abuf);
		fprintf(fp, "dst %s ",
			format_host(AF_INET,
				    RTA_PAYLOAD(tb[NDA_DST]),
				    RTA_DATA(tb[NDA_DST]),
				    abuf, sizeof(abuf)));
	}

	if (show_stats && tb[NDA_CACHEINFO]) {
		struct nda_cacheinfo *ci = RTA_DATA(tb[NDA_CACHEINFO]);
		int hz = get_user_hz();

		fprintf(fp, " used %d/%d", ci->ndm_used/hz,
		       ci->ndm_updated/hz);
	}
	if (r->ndm_flags & NTF_SELF)
		fprintf(fp, "self ");
	if (r->ndm_flags & NTF_MASTER)
		fprintf(fp, "master ");

	fprintf(fp, "%s\n", state_n2a(r->ndm_state));
	return 0;
}

static int fdb_show(int argc, char **argv)
{
	char *filter_dev = NULL;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (filter_dev)
				duparg("dev", *argv);
			filter_dev = *argv;
		}
		argc--; argv++;
	}

	if (filter_dev) {
		filter_index = if_nametoindex(filter_dev);
		if (filter_index == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n",
				filter_dev);
			return -1;
		}
	}

	if (rtnl_wilddump_request(&rth, PF_BRIDGE, RTM_GETNEIGH) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, print_fdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

static int fdb_modify(int cmd, int flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			buf[256];
	} req;
	char *addr = NULL;
	char *d = NULL;
	char abuf[ETH_ALEN];
	int dst_ok = 0;
	inet_prefix dst;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;
	req.ndm.ndm_family = PF_BRIDGE;
	req.ndm.ndm_state = NUD_NOARP;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();
			if (dst_ok)
				duparg2("dst", *argv);
			get_addr(&dst, *argv, preferred_family);
			dst_ok = 1;
		} else if (strcmp(*argv, "self") == 0) {
			req.ndm.ndm_flags |= NTF_SELF;
		} else if (matches(*argv, "master") == 0) {
			req.ndm.ndm_flags |= NTF_MASTER;
		} else if (matches(*argv, "local") == 0||
			   matches(*argv, "permanent") == 0) {
			req.ndm.ndm_state |= NUD_PERMANENT;
		} else if (matches(*argv, "temp") == 0) {
			req.ndm.ndm_state |= NUD_REACHABLE;
		} else {
			if (strcmp(*argv, "to") == 0) {
				NEXT_ARG();
			}
			if (matches(*argv, "help") == 0)
				usage();
			if (addr)
				duparg2("to", *argv);
			addr = *argv;
		}
		argc--; argv++;
	}

	if (d == NULL || addr == NULL) {
		fprintf(stderr, "Device and address are required arguments.\n");
		exit(-1);
	}

	/* Assume self */
	if (!(req.ndm.ndm_flags&(NTF_SELF|NTF_MASTER)))
		req.ndm.ndm_flags |= NTF_SELF;

	/* Assume permanent */
	if (!(req.ndm.ndm_state&(NUD_PERMANENT|NUD_REACHABLE)))
		req.ndm.ndm_state |= NUD_PERMANENT;

	if (sscanf(addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   abuf, abuf+1, abuf+2,
		   abuf+3, abuf+4, abuf+5) != 6) {
		fprintf(stderr, "Invalid mac address %s\n", addr);
		exit(-1);
	}

	addattr_l(&req.n, sizeof(req), NDA_LLADDR, abuf, ETH_ALEN);
	if (dst_ok)
		addattr_l(&req.n, sizeof(req), NDA_DST, &dst.data, dst.bytelen);

	req.ndm.ndm_ifindex = ll_name_to_index(d);
	if (req.ndm.ndm_ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", d);
		return -1;
	}

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL) < 0)
		exit(2);

	return 0;
}

int do_fdb(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return fdb_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_EXCL, argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return fdb_modify(RTM_DELNEIGH, 0, argc-1, argv+1);
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return fdb_show(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return fdb_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge fdb help\".\n", *argv);
	exit(-1);
}
