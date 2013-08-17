/*
 * netlink test
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "../oveth.h"

struct oveth_event {
	u_int8_t	type;
	u_int8_t	app;
	u_int32_t	vni;
	u_int8_t	mac[ETH_ALEN];
};


void
genlmsghdr_dump (struct genlmsghdr * gnlh)
{
	printf ("GENL MSG HEADER\n");
	printf ("cmd : %u\n", gnlh->cmd);
	printf ("version : %u\n", gnlh->version);
	printf ("reserved : %u\n", gnlh->reserved);

	return;
}

void
nlmsghdr_dump (struct nlmsghdr * nlh)
{
	printf ("NLMSG HEADER\n");
	printf ("length : %d\n", nlh->nlmsg_len);
	printf ("type   : %d\n", nlh->nlmsg_type);
	printf ("flags  : %x\n", nlh->nlmsg_flags);
	printf ("seq    : %d\n", nlh->nlmsg_seq);
	printf ("pid    : %d\n", nlh->nlmsg_pid);

	return;
}

int
main (int argc, char * argv[])
{
	int n;
	struct nl_sock * sk;
	int oveth_family, oveth_group;

	sk = nl_socket_alloc ();
	if (genl_connect (sk) < 0) {
		printf ("genl connect failed\n");
		return -1;
	}
	
	oveth_family = genl_ctrl_resolve (sk, OVETH_GENL_NAME);
	oveth_group = genl_ctrl_resolve_grp (sk, OVETH_GENL_NAME, 
					     OVETH_GENL_MC_GROUP);
	
	printf ("family = %d, group = %d\n", oveth_family, oveth_group);

	nl_socket_free (sk);


	int fd;
	struct sockaddr_nl local;

	fd = socket (AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

	if (fd < 0) {
		perror ("socket");
		return -1;
	}

	memset (&local, 0, sizeof (local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = oveth_group;
	if (bind (fd, (struct sockaddr *) &local, sizeof (local)) < 0) {
		perror ("bind");
		return -1;
	}

	if (setsockopt(fd, 270, NETLINK_ADD_MEMBERSHIP,
		       &oveth_group, sizeof (oveth_group)) < 0) {
		perror ("setsockopt");
		return -1;
	}


	struct nlmsghdr * nlh;
	struct genlmsghdr * gnlh;
	struct oveth_event * event;
	char buf[1024];


	while (1) {
		memset (&buf, 0, sizeof (buf));
		n = recv (fd, &buf, sizeof (buf), 0);
		printf ("received length is %d\n", n);
		
		nlh = (struct nlmsghdr *) buf;
		if (!NLMSG_OK (nlh, n)) {
			printf ("invalid nlmsg length\n");
		}

		gnlh = (struct genlmsghdr *) NLMSG_DATA (nlh);
		event = (struct oveth_event *) (buf 
						+ sizeof (struct nlmsghdr) 
						+ sizeof (struct genlmsghdr)
						+ 4);

		nlmsghdr_dump (nlh);
		genlmsghdr_dump (gnlh);

		if (event->type == OVETH_EVENT_UNKNOWN_MAC) 
			printf ("type : Unknwon Destination MAC\n");
		else if (event->type == OVETH_EVENT_UNDER_MAC) 
			printf ("type : New Accommodated MAC\n");
		else 
			printf ("type : unknown %d\n", event->type);
		
		printf ("app  : %d\n", event->app);
		printf ("vni  : %d\n", event->vni);
		printf ("mac  : %02x:%02x:%02x:%02x:%02x:%02x\n",
			event->mac[0], event->mac[1], event->mac[2],
			event->mac[3], event->mac[4], event->mac[5]);

		printf ("\n");
	}



	return 0;
}

