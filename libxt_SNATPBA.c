#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv4/ip_tables.h>
#include <arpa/inet.h>
#include "xt_SNATPBA.h"

enum {
    O_FROM_SRC = 0,
    O_TO_SRC,
    O_BLOCK_SIZE,
};

static void SNAT_PBA_help(void) {
    printf(
"SNATPBA target options:\n"
"   --from-source <ipaddr>[/<mask>]     Address of source (internal network).\n"
"   --to-source <ipaddr>[-<ipaddr>]     Address to map source to.\n"
"   --block-size <value>                Size of block for one station.\n"
);
}

static const struct xt_option_entry SNAT_PBA_opts[] = {
    {.name = "from-source", .id = O_FROM_SRC, .type = XTTYPE_HOSTMASK,
     .flags = XTOPT_MAND},
    {.name = "to-source", .id = O_TO_SRC, .type = XTTYPE_STRING,
     .flags = XTOPT_MAND},
    {.name = "block-size", .id = O_BLOCK_SIZE, .type = XTTYPE_UINT32,
     .flags = XTOPT_MAND},
    XTOPT_TABLEEND,
};

static void parse_to_src(const char *arg, struct nf_nat_ipv4_range *range) {
    char *tmp_arg, *dash;
    const struct in_addr *ip;

    tmp_arg = strdup(arg);

    dash = strchr(tmp_arg, '-');
    if (dash) {
        *dash = '\0';
    }

    ip = xtables_numeric_to_ipaddr(tmp_arg);
    if (!ip) {
        xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
                    tmp_arg);
    }
    range->min_ip = ip->s_addr;

    if (dash) {
        ip = xtables_numeric_to_ipaddr(dash+1);
        if (!ip) {
            xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
                        dash+1);
        }
        range->max_ip = ip->s_addr;
    } else {
        range->max_ip = range->min_ip;
    }

    if (range->max_ip < range->min_ip)  {
        xtables_error(PARAMETER_PROBLEM, "Bad IP addres range \"%s\"\n",
                    arg);
    }

    free(tmp_arg);
    return;
}

static void SNAT_PBA_parse(struct xt_option_call *cb) {
    struct xt_snat_pba_info *info = cb->data;
    const struct ipt_entry *xt_entry = cb->xt_entry;

    xtables_option_parse(cb);
    switch(cb->entry->id) {
        case O_FROM_SRC:
            info->options |= XT_SNATPBA_FROM_SRC;

            info->from_src_in = cb->val.haddr.in;
            info->from_src_mask = cb->val.hlen;

            /* Min address of range. (--from-source) */
            info->from_src.min_ip = cb->val.haddr.in.s_addr;

            struct in_addr tmp_in = cb->val.haddr.in;
            tmp_in.s_addr += ~cb->val.hmask.in.s_addr;

            /* Max address of range (--from-source) */
            info->from_src.max_ip = tmp_in.s_addr;
            break;
        case O_TO_SRC:
            info->options |= XT_SNATPBA_TO_SRC;

            if (xt_entry->ip.proto == IPPROTO_TCP
                        || xt_entry->ip.proto == IPPROTO_UDP
                        || xt_entry->ip.proto == IPPROTO_ICMP) {
                parse_to_src(cb->arg, &info->to_src.range[0]);
            } else {
                xtables_error(PARAMETER_PROBLEM,
				    "Need TCP, UDP with port specification");
            }
            break;
        case O_BLOCK_SIZE:
            info->options |= XT_SNATPBA_BLOCK_SIZE;

            info->block_size = cb->val.u32;
            break;
    }
}

static void SNAT_PBA_print(const void *ip, const struct xt_entry_target *target,
                           int numeric) {
    const struct xt_snat_pba_info *info = (const struct xt_snat_pba_info *)target->data;
    
    printf(" SNATPBA");
    if (info->options & XT_SNATPBA_FROM_SRC) {
        printf(" from-source:%s/%u", inet_ntoa(info->from_src_in), info->from_src_mask);
    }
    if (info->options & XT_SNATPBA_TO_SRC) {
        printf(" to-source:");
        struct in_addr min = {.s_addr = info->to_src.range->min_ip};
        struct in_addr max = {.s_addr = info->to_src.range->max_ip};
        if (min.s_addr == max.s_addr) {
            printf("%s", inet_ntoa(min));
        } else {
            printf("%s-", inet_ntoa(min));
            printf("%s", inet_ntoa(max));
        }
    }
    if (info->options & XT_SNATPBA_BLOCK_SIZE) {
        printf(" block-size:%u", info->block_size);
    }
}

static void SNAT_PBA_save(const void *ip, const struct xt_entry_target *target) {
    const struct xt_snat_pba_info *info = 
                            (const void *)target->data;
    if (info->options & XT_SNATPBA_FROM_SRC) {
        printf(" --from-source %s/%u", inet_ntoa(info->from_src_in), info->from_src_mask);
    }

    if (info->options & XT_SNATPBA_TO_SRC) {
        printf(" --to-source ");
        struct in_addr min = {.s_addr = info->to_src.range->min_ip};
        struct in_addr max = {.s_addr = info->to_src.range->max_ip};
        if (min.s_addr == max.s_addr) {
            printf("%s", inet_ntoa(min));
        } else {
            printf("%s-", inet_ntoa(min));
            printf("%s", inet_ntoa(max));
        }
    }

    if (info->options & XT_SNATPBA_BLOCK_SIZE) {
        printf(" --block-size %u", info->block_size);
    }
}

static struct xtables_target snat_pba_tg_reg = {
    .name           = "SNATPBA",
    .version        = XTABLES_VERSION,
    .family         = NFPROTO_IPV4,
    .size           = XT_ALIGN(sizeof(struct xt_snat_pba_info)),
    .userspacesize  = XT_ALIGN(sizeof(struct xt_snat_pba_info)),
    .help           = SNAT_PBA_help,
    .x6_parse       = SNAT_PBA_parse,
    .print          = SNAT_PBA_print,
    .save           = SNAT_PBA_save,
    .x6_options     = SNAT_PBA_opts,
};

void _init(void) {
    xtables_register_target(&snat_pba_tg_reg);
}
