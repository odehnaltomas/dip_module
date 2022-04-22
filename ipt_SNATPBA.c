#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <linux/notifier.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include "xt_SNATPBA.h"

#define MAX_PORTS_PER_IP 64512 /* 65536 - 1024 */

struct snatpba_block {
    /* New source IP address (public network) and port range (calculated). */
    struct nf_nat_ipv4_multi_range_compat   new_src;
    int     free_ports; /* Number of ports that are still free to use. */
};

struct list_record {
    struct snatpba_block *block;
    struct list_head list;
};

struct hashtable_cell {
    __be64                  key;    /* key = ((key + dst_ip) << 32) + src_ip */
    __be32                  orig_src_ip;
    __be32                  dst_ip;
    struct snatpba_block    *block;
    struct hlist_node       hashtable_list;
};


DEFINE_HASHTABLE(hash_blocks, 10);

LIST_HEAD(all_blocks_list);          /* Only for effective free of blocks. */
LIST_HEAD(available_blocks_list);    /* Free block ready for connections. */


static int xt_snat_pba_checkentry(const struct xt_tgchk_param *par) {
    const struct xt_snat_pba_info *mr = par->targinfo;
    int ip_num, blocks_num, blocks_num_per_ip, i, j;
    __be16 offset;

    printk(KERN_INFO "%s: --from-source: %pI4-%pI4, "
                "--to-source: %pI4-%pI4, "
                "--block-size: %u", THIS_MODULE->name, 
            &mr->from_src.min_ip, &mr->from_src.max_ip,
            &mr->to_src.range->min_ip, &mr->to_src.range->max_ip,
            mr->block_size);
    ip_num = mr->to_src.range->max_ip - mr->to_src.range->min_ip + 1;
    blocks_num_per_ip = MAX_PORTS_PER_IP / mr->block_size;
    blocks_num = (ip_num * MAX_PORTS_PER_IP) / mr->block_size;

    printk(KERN_INFO "%s: ip_num %d, blocks_num_per_ip: %d, blocks_num: %d\n",
            THIS_MODULE->name, ip_num, blocks_num_per_ip, blocks_num);

    offset = 0;
    for (i = 0; i < ip_num; i++) {
        offset += 1023;
        for (j=0; j < blocks_num_per_ip; j++) {
            struct snatpba_block *block = kzalloc(sizeof(struct snatpba_block), GFP_KERNEL);
            struct list_record *rec = kzalloc(sizeof(struct list_record), GFP_KERNEL);
            struct list_record *rec_n = kzalloc(sizeof(struct list_record), GFP_KERNEL);

            block->new_src.range->min.tcp.port = offset + 1;
            offset += mr->block_size;
            block->new_src.range->max.tcp.port = offset;

            block->new_src.range->min_ip = mr->to_src.range->min_ip + i;
            block->new_src.range->max_ip = mr->to_src.range->max_ip + i;

            block->free_ports = mr->block_size;

            rec->block = block;
            rec_n->block = block;

            list_add_tail(&rec->list, &available_blocks_list);
            list_add_tail(&rec_n->list, &all_blocks_list);
        }
        // offset += 65536 - offset;
        offset = 0;
    }
    // TODO: vypocitat a alokovat bloky pro spojeni a dat je do obou seznamu
    return nf_ct_netns_get(par->net, par->family);
}

static void xt_snat_pba_destroy(const struct xt_tgdtor_param *par) {
    // TODO: uvolnit bloky
    nf_ct_netns_put(par->net, par->family);
}

static struct nf_ct_event_notifier *saved_event_cb __read_mostly = NULL;

static int snatpba_conntrack_event(unsigned int events, struct nf_ct_event *item) {
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

    printk(KERN_INFO "%s: tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
	       THIS_MODULE->name, tmp_tuple, tmp_tuple->dst.protonum,
	       &tmp_tuple->src.u3.ip, ntohs(tmp_tuple->src.u.all),
	       &tmp_tuple->dst.u3.ip, ntohs(tmp_tuple->dst.u.all));

    return NOTIFY_DONE;
}

static struct nf_ct_event_notifier ctnl_notifier = {
	.fcn = snatpba_conntrack_event
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
static struct module *netlink_m;
static void register_ct_events(void)
{
#define NETLINK_M "nf_conntrack_netlink"
    printk(KERN_INFO "%s: enable.\n", THIS_MODULE->name);
	mutex_lock(&events_lock);

    printk(KERN_INFO "%s: tady", THIS_MODULE->name);
    if (!find_module(NETLINK_M)) {
        printk(KERN_INFO "%s: Loading " NETLINK_M "\n", THIS_MODULE->name);
        request_module(NETLINK_M);
    }

    /* Reference netlink module to prevent it's unsafe unload before us. */
	if (!netlink_m && (netlink_m = find_module(NETLINK_M))) {
		if (!try_module_get(netlink_m))
			netlink_m = NULL;
	}

	register_pernet_subsys(&natevents_net_ops);

	mutex_unlock(&events_lock);
}

static void unregister_ct_events(void) {
    mutex_lock(&events_lock);

    unregister_pernet_subsys(&natevents_net_ops);

    module_put(netlink_m);
    netlink_m = NULL;

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
    printk(KERN_INFO "%s: Pred inicializaci notifieru.\n", THIS_MODULE->name);
    register_ct_events();

    printk(KERN_INFO "%s: Module initialized.\n", THIS_MODULE->name);
    return xt_register_targets(xt_snat_pba_target_reg,
                               ARRAY_SIZE(xt_snat_pba_target_reg));
}

static void __exit xt_snat_pba_exit(void) {
    unregister_ct_events();

    printk(KERN_INFO "%s: Cleaning up module.\n", THIS_MODULE->name);
    xt_unregister_targets(xt_snat_pba_target_reg, ARRAY_SIZE(xt_snat_pba_target_reg));
}

module_init(xt_snat_pba_init);
module_exit(xt_snat_pba_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomas Odehnal <xodehn08@stud.fit.vutbr.cz>");
