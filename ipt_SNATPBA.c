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
#include <linux/byteorder/little_endian.h>
#include <linux/vmalloc.h>
#include "xt_SNATPBA.h"

#define MAX_PORTS_PER_IP 64512 /* 65536 - 1024 */

struct snatpba_block {
    /* New source IP address (public network) and port range (calculated). */
    struct nf_nat_ipv4_multi_range_compat   new_src;

    /* Number of ports that are still free to use. */
    int                                     free_ports;
};

struct list_record {
    struct snatpba_block *block;
    struct list_head list;
};

struct hashtable_cell {
    unsigned long long      key;    /* key = ((key + dst_ip) << 32) + src_ip */
    __be32                  orig_src_ip;
    __be32                  dst_ip;
    struct snatpba_block    *block;
    struct hlist_node       node;
};

struct rule_entry {
    DECLARE_HASHTABLE(rule_hashtable, 10);
    struct list_head avl_blc_list;
    struct list_head all_blc_list;
    struct xt_snatpba_info info;
    struct list_head list;

    // int snatpba_info_set;
};

static LIST_HEAD(rule_list);


// DEFINE_HASHTABLE(hash_blocks, 10);

// LIST_HEAD(all_blocks_list);          /* Only for effective free of blocks. */
// LIST_HEAD(available_blocks_list);    /* Free block ready for connections. */

/* This is global variable because of snatpba_conntrack_event() handler. */
// struct xt_snatpba_info snatpba_info;
int at_least_one_rule = 0;

static DEFINE_MUTEX(data_lock);

static int xt_snatpba_checkentry(const struct xt_tgchk_param *par) {
    const struct xt_snatpba_info *mr = par->targinfo;
    int ip_num, blocks_num, blocks_num_per_ip, i, j;
    __be16 offset;
    struct rule_entry *rule = kmalloc(sizeof(struct rule_entry), GFP_KERNEL);
    
    rule->avl_blc_list = (struct list_head)LIST_HEAD_INIT(rule->avl_blc_list);
    rule->all_blc_list = (struct list_head)LIST_HEAD_INIT(rule->all_blc_list);
    
    hash_init(rule->rule_hashtable);
    rule->info = *mr;

    printk(KERN_INFO "%s: --from-source: %pI4-%pI4, "
                "--to-source: %pI4-%pI4, "
                "--block-size: %u", THIS_MODULE->name, 
            &mr->from_src.min_ip, &mr->from_src.max_ip,
            &mr->to_src.range->min_ip, &mr->to_src.range->max_ip,
            mr->block_size);
    ip_num = ntohl(mr->to_src.range->max_ip - mr->to_src.range->min_ip) + 1;
    blocks_num_per_ip = MAX_PORTS_PER_IP / mr->block_size;
    blocks_num = ip_num * blocks_num_per_ip;

    printk(KERN_INFO "%s: ip_num %d, blocks_num_per_ip: %d, blocks_num: %d\n",
            THIS_MODULE->name, ip_num, blocks_num_per_ip, blocks_num);

    offset = 0;
    for (i = 0; i < ip_num; i++) {
        offset += 1023;
        for (j=0; j < blocks_num_per_ip; j++) {
            struct list_record *rec = kmalloc(sizeof(struct list_record), GFP_KERNEL);
            struct list_record *rec_n = kmalloc(sizeof(struct list_record), GFP_KERNEL);
            struct snatpba_block *block = kmalloc(sizeof(struct snatpba_block), GFP_KERNEL);

            block->new_src.range->min.tcp.port = htons(offset + 1);
            offset += mr->block_size;
            block->new_src.range->max.tcp.port = htons(offset);

            block->new_src.range->min_ip = mr->to_src.range->min_ip + htonl(i);
            block->new_src.range->max_ip = mr->to_src.range->max_ip + htonl(i);

            block->free_ports = mr->block_size;
            // printk(KERN_INFO "%s: ip addr: %pI4, port min: %u, port max: %u\n",
            //         THIS_MODULE->name, &block->new_src.range->min_ip,
            //         ntohs(block->new_src.range->min.tcp.port),
            //         ntohs(block->new_src.range->max.tcp.port));
            block->new_src.range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            block->new_src.range->flags |= NF_NAT_RANGE_MAP_IPS;

            rec->block = block;
            rec_n->block = block;

            list_add_tail(&rec->list, &rule->avl_blc_list);
            list_add_tail(&rec_n->list, &rule->all_blc_list);

            // kfree(block);
            // kfree(rec_n);
            // kfree(rec);
        }
        offset = 0;
    }

    /* Add rule resources into list with rules (of this target). */
    mutex_lock(&data_lock);
    list_add_tail(&rule->list, &rule_list);

    at_least_one_rule = 1;
    mutex_unlock(&data_lock);

    struct list_record *entry_data = NULL;
    list_for_each_entry(entry_data, &rule->all_blc_list, list) {
        struct snatpba_block *block = entry_data->block;

        printk(KERN_INFO "%s: ip addr: %pI4, port min: %u, port max: %u\n",
                THIS_MODULE->name, &block->new_src.range->min_ip,
                ntohs(block->new_src.range->min.tcp.port),
                ntohs(block->new_src.range->max.tcp.port));
    }

    return nf_ct_netns_get(par->net, par->family);
}

static void xt_snatpba_destroy(const struct xt_tgdtor_param *par) {
    struct list_record *entry_data = NULL;
    struct hashtable_cell *hash_entry;
    int bkt;
    const struct xt_snatpba_info *mr = par->targinfo;
    struct rule_entry *rule = NULL;

    printk(KERN_INFO "%s: xt_snatpba_destroy\n", THIS_MODULE->name);
    printk(KERN_INFO "%s: --from-source: %pI4-%pI4, "
                "--to-source: %pI4-%pI4, "
                "--block-size: %u", THIS_MODULE->name, 
            &mr->from_src.min_ip, &mr->from_src.max_ip,
            &mr->to_src.range->min_ip, &mr->to_src.range->max_ip,
            mr->block_size);
    mutex_lock(&data_lock);

    list_for_each_entry(rule, &rule_list, list) {
        
    }
    // while (!list_empty(&all_blocks_list)) {
    //     entry_data = list_entry(all_blocks_list.next, struct list_record, list);
    //     kfree(entry_data->block);
    //     list_del(&entry_data->list);
    //     kfree(entry_data);
    // }

    // while (!list_empty(&available_blocks_list)) {
    //     entry_data = list_entry(available_blocks_list.next, struct list_record, list);
    //     list_del(&entry_data->list);
    //     kfree(entry_data);
    // }

    // /**
    //  * There is probably better way to safely remove all entries,
    //  * but i didn't find any.
    //  */
    // while (!hash_empty(hash_blocks)) {
    //     hash_for_each(hash_blocks, bkt, hash_entry, node) {
    //         break;
    //     }
    //     hash_del(&hash_entry->node);
    //     kfree(hash_entry);
    // }
    

    mutex_unlock(&data_lock);
    nf_ct_netns_put(par->net, par->family);
}

static void
del_conn_from_hashtable(struct rule_entry *rule, struct hashtable_cell *el) {
    struct list_record *new_rec = kmalloc(sizeof(struct list_record), GFP_KERNEL);
    new_rec->block = el->block;

    list_add_tail(&new_rec->list, &rule->avl_blc_list);

    hash_del(&el->node);
    kfree(el);
}

static struct hashtable_cell *
add_conn_to_hashtable(struct rule_entry *rule, __be32 saddr, __be32 daddr,
                      unsigned long long entry_key) {
    struct list_record *list_entry;
    struct hashtable_cell *new_hash_entry = kmalloc(sizeof(struct hashtable_cell), GFP_KERNEL);

    if (list_empty(&rule->avl_blc_list)) {
        return NULL;
    }

    list_entry = list_first_entry(&rule->avl_blc_list, struct list_record, list);

    new_hash_entry->key = entry_key;
    new_hash_entry->orig_src_ip = saddr;
    new_hash_entry->dst_ip = daddr;
    new_hash_entry->block = list_entry->block;

    hash_add(rule->rule_hashtable, &new_hash_entry->node, entry_key);

    list_entry->block = NULL;
    list_del(&list_entry->list);
    kfree(list_entry);
    return new_hash_entry;
}

static struct nf_ct_event_notifier *saved_event_cb __read_mostly = NULL;

static int snatpba_conntrack_event(unsigned int events, struct nf_ct_event *item) {
    struct nf_conn *ct = item->ct;
    struct nf_ct_event_notifier *notifier;
    const struct nf_conntrack_tuple *ct_tuple, *ct_tuple2;
    struct hashtable_cell *hash_entry;
    unsigned long long this_key = 0;
    int ret = NOTIFY_DONE;
    struct rule_entry *rule = NULL;

	/* Call netlink first. */
	notifier = rcu_dereference(saved_event_cb);
	if (likely(notifier))
		ret = notifier->fcn(events, item);
    
    if (!at_least_one_rule) {
        printk(KERN_INFO "%s: not my connection\n", THIS_MODULE->name);
        return NOTIFY_DONE;
    }

    ct_tuple = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    ct_tuple2 = &(ct->tuplehash[IP_CT_DIR_REPLY].tuple);

    // printk(KERN_INFO "%s: snatpba_info min:%u max:%u\n",
	//        THIS_MODULE->name, ntohl(snatpba_info.from_src.min_ip), ntohl(snatpba_info.from_src.max_ip));

    if (events & (1 << IPCT_DESTROY) ||
            events & (1 << IPCT_ASSURED)) {
        mutex_lock(&data_lock);

        list_for_each_entry(rule, &rule_list, list) {
            if (ntohl(ct_tuple2->dst.u3.ip) >= 
                        ntohl(rule->info.to_src.range->min_ip) && 
                        ntohl(ct_tuple2->dst.u3.ip) <=
                        ntohl(rule->info.to_src.range->max_ip)) {
                // printk(KERN_INFO "%s: target --from-source: %pI4-%pI4, "
                //                 "--to-source: %pI4-%pI4, "
                //                 "--block-size: %u\n", THIS_MODULE->name, 
                //             &mr->from_src.min_ip, &mr->from_src.max_ip,
                //             &mr->to_src.range->min_ip, &mr->to_src.range->max_ip,
                //             mr->block_size);
                this_key = ct_tuple->src.u3.ip;
                this_key = (this_key << 32) + ct_tuple->dst.u3.ip;

                hash_for_each_possible(rule->rule_hashtable, hash_entry, node, this_key) {
                    if (hash_entry->key == this_key) {
                        printk(KERN_INFO "%s: connection for src: %pI4, dst: %pI4 in hashtable.\n",
                                THIS_MODULE->name, &ct_tuple->src.u3.ip, &ct_tuple->dst.u3.ip);
                        break;
                    }
                }

                if (events & (1 << IPCT_ASSURED)) {
                    printk(KERN_INFO "%s: IPCT_ASSURED\n", THIS_MODULE->name);

                    // TODO: lock
                    if (hash_entry->block->free_ports > 0) {
                        hash_entry->block->free_ports--;
                    }
                    // TODO: unlock
                }
                else if (events & (1 << IPCT_DESTROY)) {
                    printk(KERN_INFO "%s: IPCT_DESTROY\n", THIS_MODULE->name);

                    // TODO: lock
                    if (hash_entry->block->free_ports < 20) {
                        hash_entry->block->free_ports++;
                    }
                    else if (hash_entry->block->free_ports == 20) {
                        /** 
                         * This could occure when target is accepted,
                         * but the connection track somehow is not ACCEPTed
                         * and is DESTROYed
                         */
                        del_conn_from_hashtable(rule, hash_entry);
                    }

                    if (hash_entry->block->free_ports == 20) {
                        del_conn_from_hashtable(rule, hash_entry);
                    }
                }
                // TODO: unlock
                break;
            }
            mutex_unlock(&data_lock);
            
        }

    }
    // printk(KERN_INFO "%s: tuple orig %p: %u %pI4:%hu -> %pI4:%hu\n",
	//        THIS_MODULE->name, ct_tuple, ct_tuple->dst.protonum,
	//        &ct_tuple->src.u3.ip, ntohs(ct_tuple->src.u.all),
	//        &ct_tuple->dst.u3.ip, ntohs(ct_tuple->dst.u.all));
    // printk(KERN_INFO "%s: tuple repl %p: %u %pI4:%hu -> %pI4:%hu\n",
	//        THIS_MODULE->name, ct_tuple2, ct_tuple2->dst.protonum,
	//        &ct_tuple2->src.u3.ip, ntohs(ct_tuple2->src.u.all),
	//        &ct_tuple2->dst.u3.ip, ntohs(ct_tuple2->dst.u.all));

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
xt_snatpba_target(struct sk_buff *skb, const struct xt_action_param *par) {
    const struct xt_snatpba_info *mr = par->targinfo;
	struct nf_nat_range2 range;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
    struct hashtable_cell *curr = NULL;
    struct rule_entry *rule = NULL;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    // int ret;

    mutex_lock(&data_lock);

    list_for_each_entry(rule, &rule_list, list) {
        if (rule->info.to_src.range->min_ip == 
            mr->to_src.range->min_ip && 
            rule->info.to_src.range->max_ip ==
            mr->to_src.range->max_ip) {
                printk(KERN_INFO "%s: target --from-source: %pI4-%pI4, "
                                "--to-source: %pI4-%pI4, "
                                "--block-size: %u\n", THIS_MODULE->name, 
                            &mr->from_src.min_ip, &mr->from_src.max_ip,
                            &mr->to_src.range->min_ip, &mr->to_src.range->max_ip,
                            mr->block_size);
                printk(KERN_INFO "%s: target packet src: %pI4, dst:%pI4\n",
                        THIS_MODULE->name, &ip_header->saddr, &ip_header->daddr);
                break;
            }
    }

    unsigned long long this_key = ip_header->saddr;

    printk(KERN_INFO "%s: prisel paket do targetu\n", THIS_MODULE->name);
    printk(KERN_INFO "%s: %llu\n", THIS_MODULE->name, this_key);
    this_key = (this_key << 32) + ip_header->daddr;
    printk(KERN_INFO "%s: %llu\n", THIS_MODULE->name, this_key);

    hash_for_each_possible(rule->rule_hashtable, curr, node, this_key) {
        if (curr->key == this_key) {
            printk(KERN_INFO "%s: connection for src: %pI4, dst: %pI4 already in hashtable.\n",
                    THIS_MODULE->name, &ip_header->saddr, &ip_header->daddr);
            break;
        }
    }

    if (!curr) {
        printk(KERN_INFO "%s: connection for src: %pI4, dst: %pI4 not in hashtable.\n",
                    THIS_MODULE->name, &ip_header->saddr, &ip_header->daddr);
        
        curr = add_conn_to_hashtable(rule, ip_header->saddr, ip_header->daddr, this_key);

        if (!curr) {
            kfree(curr);
            return NF_DROP;
        }
        printk(KERN_INFO "%s: connection for key: %llu added into hashtable.\n",
                        THIS_MODULE->name, curr->key);
    }

	ct = nf_ct_get(skb, &ctinfo);
	WARN_ON(!(ct != NULL &&
		 (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
		  ctinfo == IP_CT_RELATED_REPLY)));

    printk(KERN_INFO "%s: min ip: %pI4, max ip %pI4, min port: %u, max port: %u\n",
            THIS_MODULE->name, &curr->block->new_src.range->min_ip, &curr->block->new_src.range->max_ip,
            ntohs(curr->block->new_src.range->min.tcp.port), ntohs(curr->block->new_src.range->max.tcp.port));
            
	xt_nat_convert_range(&range, &curr->block->new_src.range[0]);

    mutex_unlock(&data_lock);
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC);
}

static struct xt_target xt_snatpba_target_reg[] __read_mostly = {
    {
        .name       = "SNATPBA",
        .checkentry = xt_snatpba_checkentry,
        .destroy    = xt_snatpba_destroy,
        .target     = xt_snatpba_target,
        .targetsize = sizeof(struct xt_snatpba_info),
        .family     = NFPROTO_IPV4,
        .table      = "nat",
        .hooks      = (1 << NF_INET_POST_ROUTING) |
                      (1 << NF_INET_LOCAL_IN), // TODO: ?melo by tady byt i (1 << NF_INET_LOCAL_IN)?
        .me         = THIS_MODULE,
    },
};

static int __init xt_snatpba_init(void) {
    printk(KERN_INFO "%s: Pred inicializaci notifieru.\n", THIS_MODULE->name);
    register_ct_events();

    printk(KERN_INFO "%s: Module initialized.\n", THIS_MODULE->name);
    return xt_register_targets(xt_snatpba_target_reg,
                               ARRAY_SIZE(xt_snatpba_target_reg));
}

static void __exit xt_snatpba_exit(void) {
    unregister_ct_events();

    printk(KERN_INFO "%s: Cleaning up module.\n", THIS_MODULE->name);
    xt_unregister_targets(xt_snatpba_target_reg, ARRAY_SIZE(xt_snatpba_target_reg));
}

module_init(xt_snatpba_init);
module_exit(xt_snatpba_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomas Odehnal <xodehn08@stud.fit.vutbr.cz>");
