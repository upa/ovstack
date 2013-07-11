/*
 * ovstack dummy2 application for test
 */

#ifndef DEBUG
#define DEBUG
#endif


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <net/sock.h>

#include "ovstack.h"



#define OVDUMMY2_VERSION "0.0.1"

MODULE_VERSION (OVDUMMY2_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");



int
dummy2_recv_ops (struct sock * sk, struct sk_buff * skb)
{
	printk (KERN_INFO "%s: dummy2 recv packet\n", __func__);
	return 0;
}

static int
__init ovdummy2_init_module (void)
{
	int rc;
	struct net * net = get_net_ns_by_pid (1);

	printk ("struct net pointer is %p\n", net);

	rc = ovstack_register_app_ops (net, OVAPP_DUMMY2, dummy2_recv_ops);
	rc = ovstack_register_app_ops (net, OVAPP_DUMMY2, dummy2_recv_ops);

	printk (KERN_INFO "DUMMY2: ovstack dummy2 "
		"application (%d) is loaded\n", OVAPP_DUMMY2);
	return 0;
}
module_init (ovdummy2_init_module);


static void
__exit ovdummy2_exit_module (void)
{
	struct net * net = get_net_ns_by_pid (1);

	ovstack_unregister_app_ops (net, OVAPP_DUMMY2);
	ovstack_unregister_app_ops (net, OVAPP_DUMMY2);

	printk (KERN_INFO "DUMMY2 : ovstack dummy2 application "
		"(%d) is unloaded\n", OVAPP_DUMMY2);

	return;
}
module_exit (ovdummy2_exit_module);
