#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <linux/notifier.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include "xt_SNATPBA.h"

static int xt_snat_pba_checkentry(const struct xt_tgchk_param *par) {
    // const struct xt_snat_pba_info *mr = par->targinfo;
    // printk(KERN_INFO "%s: --src: %pI4", THIS_MODULE->name, )
    return nf_ct_netns_get(par->net, par->family);
}

static void xt_snat_pba_destroy(const struct xt_tgdtor_param *par) {
    nf_ct_netns_put(par->net, par->family);
}

static struct nf_ct_event_notifier *saved_event_cb __read_mostly = NULL;

static int snat_pba_conntrack_event(const unsigned int events, struct nf_ct_event *item) {
    struct nf_conn *ct = item->ct;
    struct nf_ct_event_notifier *notifier;
    const struct nf_conntrack_tuple *tmp_tuple;
    int ret = NOTIFY_DONE;

	/* Call netlink first. */
	notifier = rcu_dereference(saved_event_cb);
	if (likely(notifier))
		ret = notifier->fcn(events, item);

    if (events & (1 << IPCT_NEW)) {
        printk(KERN_INFO "%s: IPCT_NEW\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_RELATED)) {
        printk(KERN_INFO "%s: IPCT_RELATED\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_DESTROY)) {
        printk(KERN_INFO "%s: IPCT_DESTROY\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_REPLY)) {
        printk(KERN_INFO "%s: IPCT_REPLY\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_ASSURED)) {
        printk(KERN_INFO "%s: IPCT_ASSURED\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_PROTOINFO)) {
        printk(KERN_INFO "%s: IPCT_PROTOINFO\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_HELPER)) {
        printk(KERN_INFO "%s: IPCT_HELPER\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_MARK)) {
        printk(KERN_INFO "%s: IPCT_MARK\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_SEQADJ)) {
        printk(KERN_INFO "%s: IPCT_SEQADJ\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_SECMARK)) {
        printk(KERN_INFO "%s: IPCT_SECMARK\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_LABEL)) {
        printk(KERN_INFO "%s: IPCT_LABEL\n", THIS_MODULE->name);
    }
    else if (events & (1 << IPCT_SYNPROXY)) {
        printk(KERN_INFO "%s: IPCT_SYNPROXY\n", THIS_MODULE->name);
    }
    else {
        printk(KERN_INFO "%s: OTHER CT EVENT\n", THIS_MODULE->name);
    }

    tmp_tuple = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);

    printk( KERN_INFO "%s: tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
	       THIS_MODULE->name, t, t->dst.protonum,
	       &t->src.u3.ip, ntohs(t->src.u.all),
	       &t->dst.u3.ip, ntohs(t->dst.u.all));

    return NOTIFY_DONE;
}

static struct nf_ct_event_notifier ctnl_notifier = {
	.fcn = snat_pba_conntrack_event
};

static int set_notifier_cb(struct net *net) {
    struct nf_ct_event_notifier *notifier;

    notifier = rcu_dereference(net->ct.nf_conntrack_event_cb);

    if (notifier == NULL) {
        nf_conntrack_register_notifier(net, &ctnl_notifier);
    }
    else if (notifier != &ctnl_notifier) {
        if (saved_event_cb == NULL) {
            saved_event_cb = notifier;
        }
        else if (saved_event_cb != notifier) {
            // TODO: error
        }
        rcu_assign_pointer(net->ct.nf_conntrack_event_cb, &ctnl_notifier);
    } else {
        // TODO: asi nejakej vypis, ze uz je muj notifier callback zaregistrovanej
        printk(KERN_INFO "%s: notifier for this module already registered.\n", THIS_MODULE->name);
    }

    return 0;
}

static void unset_notifier_cb(struct net *net) {
    struct nf_ct_event_notifier *notifier;

    notifier = rcu_dereference(net->ct.nf_conntrack_event_cb);

    if (notifier == &ctnl_notifier) {
        if (saved_event_cb == NULL) {
            nf_conntrack_unregister_notifier(net, &ctnl_notifier);
        } else {
            rcu_assign_pointer(net->ct.nf_conntrack_event_cb, saved_event_cb);
        }
    }
}


static struct pernet_operations natevents_net_ops = {
	.init = set_notifier_cb,
	.exit = unset_notifier_cb
};

static DEFINE_MUTEX(events_lock);
static void register_ct_events(void)
{
#define NETLINK_M "nf_conntrack_netlink"
    // printk(KERN_INFO "%s: enable .\n" THIS_MODULE->name);
	mutex_lock(&events_lock);

	register_pernet_subsys(&natevents_net_ops);

	mutex_unlock(&events_lock);
}

static void unregister_ct_events(void) {
    mutex_lock(&events_lock);

    unregister_pernet_subsys(&natevents_net_ops);

    rcu_assign_pointer(saved_event_cb, NULL);

    mutex_unlock(&events_lock);
}


/**
 * NOTE: Used from implementation of NAT in kernel (https://elixir.bootlin.com/linux/v5.4.53/source/net/netfilter/xt_nat.c)
 * @param dst 
 * @param src 
 */
static void xt_nat_convert_range(struct nf_nat_range2 *dst,
				 const struct nf_nat_ipv4_range *src)
{
	memset(&dst->min_addr, 0, sizeof(dst->min_addr));
	memset(&dst->max_addr, 0, sizeof(dst->max_addr));
	memset(&dst->base_proto, 0, sizeof(dst->base_proto));

	dst->flags	 = src->flags;
	dst->min_addr.ip = src->min_ip;
	dst->max_addr.ip = src->max_ip;
	dst->min_proto	 = src->min;
	dst->max_proto	 = src->max;
}

static unsigned int 
xt_snat_pba_target(struct sk_buff *skb, const struct xt_action_param *par) {
    // const struct nf_nat_ipv4_multi_range_compat *mr = par->targinfo;
	// struct nf_nat_range2 range;
	// enum ip_conntrack_info ctinfo;
	// struct nf_conn *ct;

	// ct = nf_ct_get(skb, &ctinfo);
	// // WARN_ON(!(ct != NULL &&
	// // 	 (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
	// // 	  ctinfo == IP_CT_RELATED_REPLY)));

	// xt_nat_convert_range(&range, &mr->range[0]);
	// return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC);
    return NF_DROP;
}

static struct xt_target xt_snat_pba_target_reg[] __read_mostly = {
    {
        .name       = "SNATPBA",
        .checkentry = xt_snat_pba_checkentry,
        .destroy    = xt_snat_pba_destroy,
        .target     = xt_snat_pba_target,
        .targetsize = sizeof(struct xt_snat_pba_info),
        .family     = NFPROTO_IPV4,
        .table      = "nat",
        .hooks      = (1 << NF_INET_POST_ROUTING) |
                      (1 << NF_INET_LOCAL_IN), // TODO: ?melo by tady byt i (1 << NF_INET_LOCAL_IN)?
        .me         = THIS_MODULE,
    },
};

static int __init xt_snat_pba_init(void) {
    // register_ct_events();

    printk(KERN_INFO "%s: Module initialized.\n", THIS_MODULE->name);
    return xt_register_targets(xt_snat_pba_target_reg,
                               ARRAY_SIZE(xt_snat_pba_target_reg));
}

static void __exit xt_snat_pba_exit(void) {
    // unregister_ct_events();

    printk(KERN_INFO "%s: Cleaning up module.\n", THIS_MODULE->name);
    xt_unregister_targets(xt_snat_pba_target_reg, ARRAY_SIZE(xt_snat_pba_target_reg));
}

module_init(xt_snat_pba_init);
module_exit(xt_snat_pba_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomas Odehnal <xodehn08@stud.fit.vutbr.cz>");
