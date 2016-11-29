#ifndef __NLFAMILY_H__
#define __NLFAMILY_H__
#ifdef __KERNEL__
#include <net/genetlink.h>
#else
#include <linux/genetlink.h>
#include <netlink/netlink.h>
#include <netlink/attr.h>
#endif // __KERNEL__

#include "pkt_log.h"

#define VERSION_NR 1
#define FAMILY_NAME "AGENT_FAMILY"
#define INTERFACE_NAME_LEN 8
#define AGENT_MSG_LEN 128

/* attributes */
enum {
    AGENT_A_UNSPEC,
    AGENT_A_RET,
    AGENT_A_CNT,
    AGENT_A_PKT_LOG,
    AGENT_A_MSG,
    AGENT_A_INTERFACE,
    __AGENT_A_MAX,
};
#define AGENT_A_MAX (__AGENT_A_MAX - 1)

/* commands */
enum {
    AGENT_C_UNSPEC,
    AGENT_C_HOOK,
    AGENT_C_UNHOOK,
    AGENT_C_PULL,
    __AGENT_C_MAX,
};
#define AGENT_C_MAX (__AGENT_C_MAX - 1)

/* netlink attribute policy */
#ifdef __KERNEL__
#define AGENT_POLICY_LEN .len
#else
#define AGENT_POLICY_LEN .maxlen
#endif // __KERNEL__
static struct nla_policy agent_genl_policy[AGENT_A_MAX + 1] = {
    [AGENT_A_RET]       = { .type = NLA_U8 },
    [AGENT_A_CNT]       = { .type = NLA_U32 },
    [AGENT_A_PKT_LOG]   = { .type = NLA_UNSPEC, AGENT_POLICY_LEN = PKT_LOG_SIZE },
    [AGENT_A_MSG]       = { .type = NLA_STRING, AGENT_POLICY_LEN = AGENT_MSG_LEN },
    [AGENT_A_INTERFACE] = { .type = NLA_STRING, AGENT_POLICY_LEN = INTERFACE_NAME_LEN },
};

#endif
