#ifndef _XT_SNATPBA_H
#define _XT_SNATPBA_H

#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter.h>


#define XT_SNATPBA_FROM_SRC     0x01
#define XT_SNATPBA_TO_SRC       0x02
#define XT_SNATPBA_BLOCK_SIZE   0x04

struct xt_snatpba_info {
    __u8                                    options;
    struct in_addr                          from_src_in;
    uint8_t                                 from_src_mask;
    struct nf_nat_ipv4_range                from_src;
    struct nf_nat_ipv4_multi_range_compat   to_src;
    __u32                                   block_size;
};

#endif  /* _XT_SNATPBA_H */
