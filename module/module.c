#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/genetlink.h>
#include <asm/spinlock.h>

#include "nlfamily.h"
#include "pkt_log.h"

#define MAX_PAYLOAD 65536
#define MAX_QUEUE_LEN (1 << 16)

static struct nf_hook_ops netfilter_ops;
static int netfilter_hooked;
static char ifce_name[INTERFACE_NAME_LEN + 1];
static char* temp_buffer;
static __u16 head, tail;
static spinlock_t tail_lock;
static pkt_log pkt_log_queue[MAX_QUEUE_LEN];

/* netlink family definition */
static struct genl_family agent_genl_family = {
    .id = GENL_ID_GENERATE, // genl will generate an id
    .hdrsize = 0,
    .name = FAMILY_NAME,
    .version = VERSION_NR,
    .maxattr = AGENT_A_MAX,
};

/* commands binding */
int agent_c_hook(struct sk_buff *skb, struct genl_info *info);
int agent_c_unhook(struct sk_buff *skb, struct genl_info *info);
int agent_c_pull(struct sk_buff *skb, struct genl_info *info);
struct genl_ops agent_genl_ops[AGENT_C_MAX] = {
    [0] = {
        .cmd = AGENT_C_HOOK,
        .flags = 0,
        .policy = agent_genl_policy,
        .doit = agent_c_hook,
        .dumpit = NULL,
    },
    [1] = {
        .cmd = AGENT_C_UNHOOK,
        .flags = 0,
        .policy = agent_genl_policy,
        .doit = agent_c_unhook,
        .dumpit = NULL,
    },
    [2] = {
        .cmd = AGENT_C_PULL,
        .flags = 0,
        .policy = agent_genl_policy,
        .doit = agent_c_pull,
        .dumpit = NULL,
    },
};

__u16 fetch_and_inc_tail(void)
{
    __u16 ret;
    spin_lock(&tail_lock);
    ret = tail;
    tail += 1;
    spin_unlock(&tail_lock);
    return ret;
}

unsigned int main_hook(const struct nf_hook_ops *ops,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    __u32 daddr, plen;
    __u16 pos, sport, dport;
    pkt_proto proto;
    
    if (strcmp(out->name, ifce_name) == 0) {
        // Get IP header
        iph = (struct iphdr *) skb_header_pointer(skb, 0, sizeof(struct iphdr), temp_buffer);
        daddr = ntohl(iph->daddr);
        plen = ntohs(iph->tot_len) - (iph->ihl << 2);

        if (iph->protocol == 0x6 || iph->protocol == 0x11) {
            if (iph->protocol == 0x6) { // tcp
                tcph = (struct tcphdr *) skb_header_pointer(skb, sizeof(struct iphdr), sizeof(struct tcphdr), temp_buffer);
                sport = htons(tcph->source);
                dport = htons(tcph->dest);
                proto = PROTO_TCP;
            } else { // udp
                udph = (struct udphdr *) skb_header_pointer(skb, sizeof(struct iphdr), sizeof(struct udphdr), temp_buffer);
                sport = htons(udph->source);
                dport = htons(udph->dest);
                proto = PROTO_UDP;
            }
 
            pos = fetch_and_inc_tail();
            pkt_log_queue[pos].sport = sport;
            pkt_log_queue[pos].dport = dport;
            pkt_log_queue[pos].daddr = daddr;
            pkt_log_queue[pos].len   = plen;
            pkt_log_queue[pos].proto = proto;
        }
        return NF_ACCEPT;
    } else {
        return NF_ACCEPT;
    }
}

int netfilter_hook(void)
{
    int ret;
    
    netfilter_ops.hook     = main_hook;
    netfilter_ops.pf       = PF_INET;
    netfilter_ops.hooknum  = 4; // NF_IP_POSTROUTING
    netfilter_ops.priority = NF_IP_PRI_FIRST;
    
    ret = nf_register_hook(&netfilter_ops);
    if (ret != 0) {
        printk(KERN_ERR "Failed to register netfilter hook: %d\n", ret);
        goto failure;
    }
    
    temp_buffer = kmalloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + MAX_PAYLOAD, GFP_ATOMIC);
    netfilter_hooked = 1;
    head = 0;
    tail = 0;
    spin_lock_init(&tail_lock);
    printk(KERN_INFO "Netfilter hooked.\n");
    return 0;

 failure:
    return -1;
}

void netfilter_unhook(void)
{
    nf_unregister_hook(&netfilter_ops);
    kfree(temp_buffer);
    netfilter_hooked = 0;
    printk(KERN_INFO "Netfilter unhooked.\n");
}

int init_module()
{
    int ret;
    
    netfilter_hooked = 0;

    // register new family with ops
    ret = genl_register_family_with_ops(&agent_genl_family, agent_genl_ops);
    if (ret != 0)
        goto failure;

    printk(KERN_INFO "Agent module inserted.\n");
    return 0;
    
 failure:
    printk(KERN_ERR "Failed to install agent module.\n");
    return -1;
}

void cleanup_module()
{
    int ret;
    printk(KERN_INFO "Removing agent module ...\n");

    if (netfilter_hooked)
        netfilter_unhook();
    
    // unregister netlink family
    ret = genl_unregister_family(&agent_genl_family);
    if (ret != 0)
        printk(KERN_ERR "Failed to unregister family: %d\n", ret);

    printk(KERN_INFO "Agent module removed.\n");
}

int send_reply_msg(struct genl_info* info, __u8 cmd, __u8 ret, char* msg, int flags)
{
    int rc;
    __u32 seq;
    struct sk_buff *skb;
    void* msg_head;

    seq = info->snd_seq;

    skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL) {
        printk(KERN_ERR "genlmsg_new failed\n");
        goto failure;
    }

    msg_head = genlmsg_put(skb, 0, seq,
                           &agent_genl_family, flags, cmd);
    if (msg_head == NULL) {
        printk(KERN_ERR "genlmsg_put failed\n");
        goto failure;
    }

    rc = nla_put_u8(skb, AGENT_A_RET, ret);
    if (rc != 0) {
        goto failure;
    }

    rc = nla_put_string(skb, AGENT_A_MSG, msg);
    if (rc != 0) {
        goto failure;
    }

    genlmsg_end(skb, msg_head);
    rc = genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
    if (rc != 0) {
        printk(KERN_ERR "genlmsg_unicast failed: %d\n", rc);
        goto failure;
    }

    return 0;
    
 failure:
    printk(KERN_ERR "Error occured in send_reply!\n");
    return -1;
}

int agent_c_hook(struct sk_buff *skb, struct genl_info *info)
{
    int rc;
    
    nla_strlcpy(ifce_name, info->attrs[AGENT_A_INTERFACE], INTERFACE_NAME_LEN);
    printk(KERN_INFO "AGENT HOOK on %s.\n", ifce_name);
    rc = netfilter_hook();
    if (rc != 0) {
        send_reply_msg(info, AGENT_C_HOOK, rc, "Failed to hook netfilter.", 0);
    } else {
        send_reply_msg(info, AGENT_C_HOOK, 0, "Netfilter hooked", 0);
    }
        
    return rc;
}

int agent_c_unhook(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_INFO "AGENT UNHOOK.\n");
    netfilter_unhook();
    return 0;
}

int agent_c_pull(struct sk_buff *skb, struct genl_info *info)
{
    int rc, cnt;
    __u32 seq;
    struct sk_buff *reply_skb;
    void* msg_head;
    __u16 pos;

    seq = info->snd_seq;

    reply_skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (reply_skb == NULL) {
        printk(KERN_ERR "genlmsg_new failed\n");
        goto failure;
    }

    msg_head = genlmsg_put(reply_skb, 0, seq,
                           &agent_genl_family, 0, AGENT_C_PULL);
    if (msg_head == NULL) {
        printk(KERN_ERR "genlmsg_put failed\n");
        goto failure;
    }

    rc = nla_put_u8(reply_skb, AGENT_A_RET, 0);
    if (rc != 0) {
        goto failure;
    }

    spin_lock(&tail_lock);
    cnt = tail - head;
    pos = head;
    head = tail;
    spin_unlock(&tail_lock);

    rc = nla_put_u32(reply_skb, AGENT_A_CNT, cnt);
    if (rc != 0) {
        goto failure;
    }
    while (cnt-- > 0) {
        nla_put(reply_skb, AGENT_A_PKT_LOG, PKT_LOG_SIZE, &(pkt_log_queue[pos++]));
    }

    genlmsg_end(reply_skb, msg_head);
    rc = genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid);
    if (rc != 0) {
        printk(KERN_ERR "genlmsg_unicast failed: %d\n", rc);
        goto failure;
    }

    return 0;
    
 failure:
    printk(KERN_ERR "Error occured in send_reply!\n");
    return -1;
}
