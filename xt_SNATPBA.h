#ifndef _XT_SNATPBA_H
#define _XT_SNATPBA_H

#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter.h>


#define XT_SNATPBA_FROM_SRC     0x01
#define XT_SNATPBA_TO_SRC       0x02
#define XT_SNATPBA_BLOCK_SIZE   0x04

/**
 * Private structure that is filled in libxt_SNATPBA userspace program
 * and sent into the functions of the kernel-side ipt_SNATPBA module.
 */
struct xt_snatpba_info {
    __u8                                    options;
    struct in_addr                          from_src_in;    /* Internal network IPv4 address (--from-source). */
    uint8_t                                 from_src_mask;  /* Mask of from_src_in address (--from-source). */

    /* Range of address from internal addresses. Example: --from-source=10.0.0.0/24 -> range=10.0.0.0-10.0.0.255 */
    struct nf_nat_ipv4_range                from_src;
    struct nf_nat_ipv4_multi_range_compat   to_src;     /* Range of the external addresses (external address pool). */
    __u32                                   block_size; /* Size of one block (number of available ports). */
};

#endif  /* _XT_SNATPBA_H */
