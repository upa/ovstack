/*
 * Session Routing in Overlay Network.
 */

#ifndef DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <uapi/linux/netfilter_ipv6.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>


#include "ovstack.h"

#define SROVGW "srovgw: "

#define SROVGW_VERSION	"0.0.1"
MODULE_VERSION (SROVGW_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");


#define FLOW_HASH_BITS	8	/* hash table size for flow */


/* per net_netmaspace instance */
static unsigned int srovgw_net_id;
struct srovgw_net {
	DECLARE_HASHTABLE (flow_table, FLOW_HASH_BITS);
};



/* - nf nook ops.
 * packets are NF_INET_FORWARDis hoooked, and if it is specified port session,
 * the flow is encapsulated in ovstack.
 */

static unsigned int
nf_ovsrgw_forward (const struct nf_hook_ops * ops,
		   struct sk_buff * skb,
		   const struct net_device * in,
		   const struct net_device * out,
		   int (*okfn) (struct sk_buff *))
{
	return NF_ACCEPT;
}


static struct nf_hook_ops nf_srovgw_ops[] __read_mostly = {
	{
		.hook		= nf_ovsrgw_forward,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_FIRST,
	},
};


/* - ovstack receive ops.
 * received ovstack packet is decapsulated, and original TCP/UDP header is
 * constructed by using hash value as the key.
 */

static int
ovstack_srovgw_recv (struct sk_buff * skb)
{
	return 0;
}


/* - initalize and terminate hooks 
 * init/exit net_namespace
 * init/exit module
 */


static __net_init int
srovgw_init_net (struct net * net)
{
	int rc;
	struct srovgw_net * sgnet = net_generic (net, srovgw_net_id);

	memset (sgnet, 0, sizeof (struct srovgw_net));
	__hash_init (sgnet->flow_table, 1 << FLOW_HASH_BITS);

	rc = ovstack_register_app_ops (net, OVAPP_SROV, ovstack_srovgw_recv);
	if (!rc) {
		printk (KERN_ERR SROVGW "failed to register ovstack app\n");
		return -1;
	}

	return 0;
}

static __net_exit void
srovgw_exit_net (struct net * net)
{
	int rc;

	rc = ovstack_unregister_app_ops (net, OVAPP_SROV);
	if (!rc) {
		printk (KERN_ERR SROVGW "failed to unregister ovstack app\n");
	}

	/* XXX: destroy srovgw_net */
	return;
}

static struct pernet_operations srovgw_net_ops = {
	.init	= srovgw_init_net,
	.exit	= srovgw_exit_net,
	.id	= &srovgw_net_id,
	.size	= sizeof (struct srovgw_net),
};


static int
__init srovgw_init_module (void)
{
	int rc;

	rc = register_pernet_device (&srovgw_net_ops);
	if (rc != 0)
		goto net_err;

	rc = nf_register_hooks (nf_srovgw_ops, ARRAY_SIZE (nf_srovgw_ops));
	if (rc != 0)
		goto nf_err;

	printk (KERN_INFO SROVGW "srov gateway (version %s) is loaded\n",
		SROVGW_VERSION);

	return rc;

nf_err:
	unregister_pernet_device (&srovgw_net_ops);
net_err:
	return rc;
}
module_init (srovgw_init_module);


static void
__exit srovgw_exit_module (void)
{
	unregister_pernet_device (&srovgw_net_ops);
	nf_unregister_hooks (nf_srovgw_ops, ARRAY_SIZE (nf_srovgw_ops));

	printk (KERN_INFO SROVGW "srov gateway (version %s) is unloaded\n",
		SROVGW_VERSION);
	return;
}
module_exit (srovgw_exit_module);
