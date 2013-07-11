/*
 * ovstack dummy application for test
 */

#ifndef DEBUG
#define DEBUG
#endif


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <net/sock.h>

#include "ovstack.h"



#define OVDUMMY_VERSION "0.0.1"

MODULE_VERSION (OVDUMMY_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");



int
dummy_recv_ops (struct sock * sk, struct sk_buff * skb)
{
	printk (KERN_INFO "%s: dummpy recv packet\n", __func__);
	return 0;
}

static int
__init ovdummy_init_module (void)
{
	int rc;
	struct net * net = get_net_ns_by_pid (1);

	printk ("struct net pointer is %p\n", net);

	rc = ovstack_register_app_ops (net, OVAPP_DUMMY, dummy_recv_ops);
	rc = ovstack_register_app_ops (net, OVAPP_DUMMY, dummy_recv_ops);

	printk (KERN_INFO "DUMMY: ovstack dummy application (%d) is loaded\n", 
		OVAPP_DUMMY);
	return 0;
}
module_init (ovdummy_init_module);


static void
__exit ovdummy_exit_module (void)
{
	struct net * net = get_net_ns_by_pid (1);

	ovstack_unregister_app_ops (net, OVAPP_DUMMY);
	ovstack_unregister_app_ops (net, OVAPP_DUMMY);

	printk (KERN_INFO "DUMMY : ovstack dummy application "
		"(%d) is unloaded\n", OVAPP_DUMMY);

	return;
}
module_exit (ovdummy_exit_module);
