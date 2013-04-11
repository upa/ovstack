/*
 * tcp_metrics.c	"ip tcp_metrics/tcpmetrics"
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		version 2 as published by the Free Software Foundation;
 *
 * Authors:	Julian Anastasov <ja@ssi.bg>, August 2012
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include <linux/genetlink.h>
#include <linux/tcp_metrics.h>

#include "utils.h"
#include "ip_common.h"
#include "libgenl.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ip tcp_metrics/tcpmetrics { COMMAND | help }\n");
	fprintf(stderr, "       ip tcp_metrics { show | flush } SELECTOR\n");
	fprintf(stderr, "       ip tcp_metrics delete [ address ] ADDRESS\n");
	fprintf(stderr, "SELECTOR := [ [ address ] PREFIX ]\n");
	exit(-1);
}

/* netlink socket */
static struct rtnl_handle grth = { .fd = -1 };
static int genl_family = -1;

#define TCPM_REQUEST(_req, _bufsiz, _cmd, _flags) \
	GENL_REQUEST(_req, _bufsiz, genl_family, 0, \
		     TCP_METRICS_GENL_VERSION, _cmd, _flags)

#define CMD_LIST	0x0001	/* list, lst, show		*/
#define CMD_DEL		0x0002	/* delete, remove		*/
#define CMD_FLUSH	0x0004	/* flush			*/

static struct {
	char	*name;
	int	code;
} cmds[] = {
	{	"list",		CMD_LIST	},
	{	"lst",		CMD_LIST	},
	{	"show",		CMD_LIST	},
	{	"delete",	CMD_DEL		},
	{	"remove",	CMD_DEL		},
	{	"flush",	CMD_FLUSH	},
};

static char *metric_name[TCP_METRIC_MAX + 1] = {
	[TCP_METRIC_RTT]		= "rtt",
	[TCP_METRIC_RTTVAR]		= "rttvar",
	[TCP_METRIC_SSTHRESH]		= "ssthresh",
	[TCP_METRIC_CWND]		= "cwnd",
	[TCP_METRIC_REORDERING]		= "reordering",
};

static struct
{
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int cmd;
	inet_prefix addr;
} f;

static int flush_update(void)
{
	if (rtnl_send_check(&grth, f.flushb, f.flushp) < 0) {
		perror("Failed to send flush request\n");
		return -1;
	}
	f.flushp = 0;
	return 0;
}

static int process_msg(const struct sockaddr_nl *who, struct nlmsghdr *n,
		       void *arg)
{
	FILE *fp = (FILE *) arg;
	struct genlmsghdr *ghdr;
	struct rtattr *attrs[TCP_METRICS_ATTR_MAX + 1], *a;
	int len = n->nlmsg_len;
	char abuf[256];
	inet_prefix addr;
	int family, i, atype;

	if (n->nlmsg_type != genl_family)
		return -1;

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		return -1;

	ghdr = NLMSG_DATA(n);
	if (ghdr->cmd != TCP_METRICS_CMD_GET)
		return 0;

	parse_rtattr(attrs, TCP_METRICS_ATTR_MAX, (void *) ghdr + GENL_HDRLEN,
		     len);

	a = attrs[TCP_METRICS_ATTR_ADDR_IPV4];
	if (a) {
		if (f.addr.family && f.addr.family != AF_INET)
			return 0;
		memcpy(&addr.data, RTA_DATA(a), 4);
		addr.bytelen = 4;
		family = AF_INET;
		atype = TCP_METRICS_ATTR_ADDR_IPV4;
	} else {
		a = attrs[TCP_METRICS_ATTR_ADDR_IPV6];
		if (a) {
			if (f.addr.family && f.addr.family != AF_INET6)
				return 0;
			memcpy(&addr.data, RTA_DATA(a), 16);
			addr.bytelen = 16;
			family = AF_INET6;
			atype = TCP_METRICS_ATTR_ADDR_IPV6;
		} else
			return 0;
	}

	if (f.addr.family && f.addr.bitlen >= 0 &&
	    inet_addr_match(&addr, &f.addr, f.addr.bitlen))
		return 0;

	if (f.flushb) {
		struct nlmsghdr *fn;
		TCPM_REQUEST(req2, 128, TCP_METRICS_CMD_DEL, NLM_F_REQUEST);

		addattr_l(&req2.n, sizeof(req2), atype, &addr.data,
			  addr.bytelen);

		if (NLMSG_ALIGN(f.flushp) + req2.n.nlmsg_len > f.flushe) {
			if (flush_update())
				return -1;
		}
		fn = (struct nlmsghdr *) (f.flushb + NLMSG_ALIGN(f.flushp));
		memcpy(fn, &req2.n, req2.n.nlmsg_len);
		fn->nlmsg_seq = ++grth.seq;
		f.flushp = (((char *) fn) + req2.n.nlmsg_len) - f.flushb;
		f.flushed++;
		if (show_stats < 2)
			return 0;
	}

	if (f.cmd & (CMD_DEL | CMD_FLUSH))
		fprintf(fp, "Deleted ");

	fprintf(fp, "%s",
		format_host(family, RTA_PAYLOAD(a), &addr.data,
			    abuf, sizeof(abuf)));

	a = attrs[TCP_METRICS_ATTR_AGE];
	if (a) {
		__u64 val = rta_getattr_u64(a);

		fprintf(fp, " age %llu.%03llusec",
			val / 1000, val % 1000);
	}

	a = attrs[TCP_METRICS_ATTR_TW_TS_STAMP];
	if (a) {
		__s32 val = (__s32) rta_getattr_u32(a);
		__u32 tsval;

		a = attrs[TCP_METRICS_ATTR_TW_TSVAL];
		tsval = a ? rta_getattr_u32(a) : 0;
		fprintf(fp, " tw_ts %u/%dsec ago", tsval, val);
	}

	a = attrs[TCP_METRICS_ATTR_VALS];
	if (a) {
		struct rtattr *m[TCP_METRIC_MAX + 1 + 1];

		parse_rtattr_nested(m, TCP_METRIC_MAX + 1, a);

		for (i = 0; i < TCP_METRIC_MAX + 1; i++) {
			__u32 val;

			a = m[i + 1];
			if (!a)
				continue;
			if (metric_name[i])
				fprintf(fp, " %s ", metric_name[i]);
			else
				fprintf(fp, " metric_%d ", i);
			val = rta_getattr_u32(a);
			switch (i) {
			case TCP_METRIC_RTT:
				fprintf(fp, "%lluus", (val * 1000ULL) >> 3);
				break;
			case TCP_METRIC_RTTVAR:
				fprintf(fp, "%lluus", (val * 1000ULL) >> 2);
				break;
			case TCP_METRIC_SSTHRESH:
			case TCP_METRIC_CWND:
			case TCP_METRIC_REORDERING:
			default:
				fprintf(fp, "%u", val);
				break;
			}
		}
	}

	a = attrs[TCP_METRICS_ATTR_FOPEN_MSS];
	if (a)
		fprintf(fp, " fo_mss %u", rta_getattr_u16(a));

	a = attrs[TCP_METRICS_ATTR_FOPEN_SYN_DROPS];
	if (a) {
		__u16 syn_loss = rta_getattr_u16(a);
		__u64 ts;

		a = attrs[TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS];
		ts = a ? rta_getattr_u64(a) : 0;

		fprintf(fp, " fo_syn_drops %u/%llu.%03llusec ago",
			syn_loss, ts / 1000, ts % 1000);
	}

	a = attrs[TCP_METRICS_ATTR_FOPEN_COOKIE];
	if (a) {
		char cookie[32 + 1];
		unsigned char *ptr = RTA_DATA(a);
		int i, max = RTA_PAYLOAD(a);

		if (max > 16)
			max = 16;
		cookie[0] = 0;
		for (i = 0; i < max; i++)
			sprintf(cookie + i + i, "%02x", ptr[i]);
		fprintf(fp, " fo_cookie %s", cookie);
	}

	fprintf(fp, "\n");

	fflush(fp);
	return 0;
}

static int tcpm_do_cmd(int cmd, int argc, char **argv)
{
	TCPM_REQUEST(req, 1024, TCP_METRICS_CMD_GET, NLM_F_REQUEST);
	int atype = -1;
	int ack;

	memset(&f, 0, sizeof(f));
	f.addr.bitlen = -1;
	f.addr.family = preferred_family;

	switch (preferred_family) {
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
		break;
	default:
		fprintf(stderr, "Unsupported protocol family: %d\n", preferred_family);
		return -1;
	}

	for (; argc > 0; argc--, argv++) {
		char *who = "address";

		if (strcmp(*argv, "addr") == 0 ||
		    strcmp(*argv, "address") == 0) {
			who = *argv;
			NEXT_ARG();
		}
		if (matches(*argv, "help") == 0)
			usage();
		if (f.addr.bitlen >= 0)
			duparg2(who, *argv);

		get_prefix(&f.addr, *argv, preferred_family);
		if (f.addr.bytelen && f.addr.bytelen * 8 == f.addr.bitlen) {
			if (f.addr.family == AF_INET)
				atype = TCP_METRICS_ATTR_ADDR_IPV4;
			else if (f.addr.family == AF_INET6)
				atype = TCP_METRICS_ATTR_ADDR_IPV6;
		}
		if ((CMD_DEL & cmd) && atype < 0) {
			fprintf(stderr, "Error: a specific IP address is expected rather than \"%s\"\n",
				*argv);
			return -1;
		}

		argc--; argv++;
	}

	if (cmd == CMD_DEL && atype < 0)
		missarg("address");

	/* flush for exact address ? Single del */
	if (cmd == CMD_FLUSH && atype >= 0)
		cmd = CMD_DEL;

	/* flush for all addresses ? Single del without address */
	if (cmd == CMD_FLUSH && f.addr.bitlen <= 0 &&
	    preferred_family == AF_UNSPEC) {
		cmd = CMD_DEL;
		req.g.cmd = TCP_METRICS_CMD_DEL;
		ack = 1;
	} else if (cmd == CMD_DEL) {
		req.g.cmd = TCP_METRICS_CMD_DEL;
		ack = 1;
	} else {	/* CMD_FLUSH, CMD_LIST */
		ack = 0;
	}

	if (genl_family < 0) {
		if (rtnl_open_byproto(&grth, 0, NETLINK_GENERIC) < 0) {
			fprintf(stderr, "Cannot open generic netlink socket\n");
			exit(1);
		}
		genl_family = genl_resolve_family(&grth,
						  TCP_METRICS_GENL_NAME);
		if (genl_family < 0)
			exit(1);
		req.n.nlmsg_type = genl_family;
	}

	if (!(cmd & CMD_FLUSH) && (atype >= 0 || (cmd & CMD_DEL))) {
		if (ack)
			req.n.nlmsg_flags |= NLM_F_ACK;
		if (atype >= 0)
			addattr_l(&req.n, sizeof(req), atype, &f.addr.data,
				  f.addr.bytelen);
	} else {
		req.n.nlmsg_flags |= NLM_F_DUMP;
	}

	f.cmd = cmd;
	if (cmd & CMD_FLUSH) {
		int round = 0;
		char flushb[4096-512];

		f.flushb = flushb;
		f.flushp = 0;
		f.flushe = sizeof(flushb);

		for (;;) {
			req.n.nlmsg_seq = grth.dump = ++grth.seq;
			if (rtnl_send(&grth, &req, req.n.nlmsg_len) < 0) {
				perror("Failed to send flush request");
				exit(1);
			}
			f.flushed = 0;
			if (rtnl_dump_filter(&grth, process_msg, stdout) < 0) {
				fprintf(stderr, "Flush terminated\n");
				exit(1);
			}
			if (f.flushed == 0) {
				if (round == 0) {
					fprintf(stderr, "Nothing to flush.\n");
				} else if (show_stats)
					printf("*** Flush is complete after %d round%s ***\n",
					       round, round > 1 ? "s" : "");
				fflush(stdout);
				return 0;
			}
			round++;
			if (flush_update() < 0)
				exit(1);
			if (show_stats) {
				printf("\n*** Round %d, deleting %d entries ***\n",
				       round, f.flushed);
				fflush(stdout);
			}
		}
		return 0;
	}

	if (ack) {
		if (rtnl_talk(&grth, &req.n, 0, 0, NULL) < 0)
			return -2;
	} else if (atype >= 0) {
		if (rtnl_talk(&grth, &req.n, 0, 0, &req.n) < 0)
			return -2;
		if (process_msg(NULL, &req.n, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
	} else {
		req.n.nlmsg_seq = grth.dump = ++grth.seq;
		if (rtnl_send(&grth, &req, req.n.nlmsg_len) < 0) {
			perror("Failed to send dump request");
			exit(1);
		}

		if (rtnl_dump_filter(&grth, process_msg, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
	}
	return 0;
}

int do_tcp_metrics(int argc, char **argv)
{
	int i;

	if (argc < 1)
		return tcpm_do_cmd(CMD_LIST, 0, NULL);
	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (matches(argv[0], cmds[i].name) == 0)
			return tcpm_do_cmd(cmds[i].code, argc-1, argv+1);
	}
	if (matches(argv[0], "help") == 0)
		usage();

	fprintf(stderr, "Command \"%s\" is unknown, "
			"try \"ip tcp_metrics help\".\n", *argv);
	exit(-1);
}

