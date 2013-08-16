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


struct nl_cb {
	int a;
};

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
	
	int acpi_group;
	acpi_group = genl_ctrl_resolve_grp (sk, "acpi_event", "acpi_mc_group");

	int vport_group;
	vport_group = genl_ctrl_resolve_grp (sk, "ovs_vport", "ovs_vport");

	printf ("family = %d, group = %d, vport_group = %d\n", 
		oveth_family, oveth_group, vport_group);

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

	char buf[1024];

	printf ("recv\n");
	while (1) {
		recv (fd, buf, sizeof (buf), 0);
		printf ("uketotta !!! \n");
	}






#if 0
	/*
	sk = nl_socket_alloc ();
	nl_join_groups (sk, 1);
	if (nl_connect (sk, 17) != 0) {
		printf ("nl_connect to NETLINK 17 failed\n");
		return -1;
	}

	struct sockaddr_nl peer;
	unsigned char *buf;

	while (1) {
		printf ("before nl recv\n");
		nl_recv (sk, &peer, &buf, NULL);
		printf ("aftre nl recv\n");
	}

	*/
	int fd;
	struct sockaddr_nl sa;

	fd = socket (AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	memset (&sa, 0, sizeof (sa));
	sa.nl_pid = 0;
	sa.nl_family = AF_NETLINK;
//	sa.nl_family = oveth_family;
	sa.nl_groups = oveth_group;
//	sa.nl_groups = 1;

	if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) != 0) {
		perror ("bind");
		return -1;
	}

	struct {
		struct nlmsghdr		n;
		struct genlmsghdr	g;
		char buf[1024];
	} req;

	while (1) {
		n = recv (fd, &req, sizeof (req), 0);
		printf ("recv!\n");
		if (n < 0) {
			perror ("recv");
			return -1;
		}

	}

#endif
	return 0;
}

