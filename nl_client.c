#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/genetlink.h>

#include "nl_client.h"
#include "nlfamily.h"
#include "pkt_log.h"

static struct nl_sock* sk;
static int fd; // the family descriptor

/*
 * s_ret:
 *   -1  - pasre message error
 *    0  - success
 *   ... - other status
 */
static uint8_t s_ret;
static pkt_log pkt_logs[MAX_PKT_LOG_NUM]; // server replied packet logs
static uint32_t pkt_log_num;              // number of received packet logs
static char s_msg[AGENT_MSG_LEN + 1];     // server reply message
static unsigned int reply_seq, ack_seq;

int __nl_client_hook_netfilter();
int __nl_client_unhook_netfilter();

// construct generic netlink message and put headers
struct nl_msg*  __nl_client_construct_msg(uint8_t cmd, int flags);

// send out message and wait for reply
int __nl_client_rpc(struct nl_msg* msg);

// callbacks
int __nl_client_ack_callback(struct nl_msg* msg, void* args);
int __nl_client_reply_callback(struct nl_msg* msg, void* args);

// receive messages
int __nl_client_wait_for_reply(unsigned int seq, unsigned int* p);

int nl_client_init(const char* ifce)
{
    int rc;
    
    // alloc netlink socket and connect
    sk = nl_socket_alloc();
    nl_socket_disable_auto_ack(sk);
    
    rc = genl_connect(sk);
    if (rc) {
        fprintf(stderr, "genl_connect error: %i\n", rc);
        goto failure;
    }

    // resolve family name
    fd = genl_ctrl_resolve(sk, FAMILY_NAME);
    if (fd < 0) {
        fprintf(stderr, "genl_ctrl_resolve %s error: %i\n", FAMILY_NAME, fd);
        goto failure;
    }

    // set callback function for the socket
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
                        __nl_client_reply_callback, NULL);
    nl_socket_modify_cb(sk, NL_CB_ACK, NL_CB_CUSTOM,
                        __nl_client_ack_callback, NULL);
    
    // hook netfilter module
    rc = __nl_client_hook_netfilter(ifce);
    if (rc) {
        fprintf(stderr, "Failed to hook netfilter: %i\n", rc);
        goto failure;
    }
        
    return 0;
    
 failure:
    fprintf(stderr, "Failed to init netlink client.\n");
    nl_socket_free(sk);
    return -1;
}

void nl_client_cleanup()
{
    int ret;
    ret = __nl_client_unhook_netfilter();
    if (ret) {
        fprintf(stderr, "Failed to unhook netfilter: %i\n", ret);
    }
    
    nl_socket_free(sk);
}

int nl_client_pull(pkt_log* logs)
{
    int ret;
    struct nl_msg* msg;
    msg = __nl_client_construct_msg(AGENT_C_PULL, 0);
    if (msg) {
        ret = __nl_client_rpc(msg);
        if (ret != 0) {
            return ret;
        } else {
            memcpy(logs, pkt_logs, sizeof(pkt_log) * pkt_log_num);
            return pkt_log_num;
        }
    } else {
        return -1;
    }
}

int __nl_client_hook_netfilter(const char* ifce)
{
    struct nl_msg* msg;
    
    msg = __nl_client_construct_msg(AGENT_C_HOOK, 0);
    if (msg) {
        nla_put_string(msg, AGENT_A_INTERFACE, ifce);
        return __nl_client_rpc(msg);
    } else {
        return -1;
    }
}

int __nl_client_unhook_netfilter()
{
    struct nl_msg* msg;
    
    msg = __nl_client_construct_msg(AGENT_C_UNHOOK, NLM_F_ACK);
    if (msg) {    
        return __nl_client_rpc(msg);
    } else {
        return -1;
    }    
}

int __nl_client_wait_for_reply(unsigned int seq, unsigned int* p)
{
    int rc;
    while ((*p) != seq) {
        rc = nl_recvmsgs_default(sk);
        if (rc != 0) {
            fprintf(stderr, "nl_recvmsgs_default error: %d\n", rc);
            return rc;
        }
    }
    return 0;
}

int __nl_client_rpc(struct nl_msg* msg)
{
    struct nlmsghdr* hdr;
    int rc;

    s_ret = 0;
    nl_send_auto(sk, msg);
    hdr = nlmsg_hdr(msg);
    
    if (hdr->nlmsg_flags & NLM_F_ACK)
        rc = __nl_client_wait_for_reply(hdr->nlmsg_seq, &ack_seq);
    else {
        s_ret = -1;    
        rc = __nl_client_wait_for_reply(hdr->nlmsg_seq, &reply_seq);
    }
    
    nlmsg_free(msg);

    if (rc != 0) return rc;
    return s_ret;
}

struct nl_msg* __nl_client_construct_msg(uint8_t cmd, int flags)
{
    struct nl_msg* msg;
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to alloc nl_msg.\n");
        goto failure;
    }

    // put generic netlink header, hdrlen = 0
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, fd, 0, flags,
                cmd, VERSION_NR);

    return msg;
 failure:
    return NULL;
}

int __nl_client_ack_callback(struct nl_msg* msg, void* args)
{
    struct nlmsghdr* hdr;
    
    // record sequence number
    hdr = nlmsg_hdr(msg);
    ack_seq = hdr->nlmsg_seq;
    
    // printf("ACK received: %d\n", ack_seq);
    return NL_STOP;
}

int __nl_client_reply_callback(struct nl_msg* msg, void* args)
{
    struct nlmsghdr* hdr;
    struct genlmsghdr* gnlh;
    struct nlattr* head;
    struct nlattr* current;
    struct nlattr* attrs[AGENT_A_MAX + 1];
    int len, cnt;

    hdr  = nlmsg_hdr(msg);
    gnlh = genlmsg_hdr(hdr);
    head = genlmsg_attrdata(gnlh, 0);
    len  = genlmsg_attrlen(gnlh, 0);

    // record sequence number
    reply_seq = hdr->nlmsg_seq;
    
    // parse attributes
    if (nla_parse(attrs, AGENT_A_MAX, head, len, agent_genl_policy) < 0) {
        fprintf(stderr, "Failed to parse attributes of reply message.\n");
        goto failure;
    }

    // store attributes
    s_ret = nla_get_u8(attrs[AGENT_A_RET]);
    len -= nla_total_size(nla_len(attrs[AGENT_A_RET]));

    strcpy(s_msg, "NO MESSAGE");
    if (attrs[AGENT_A_MSG]) {
        nla_strlcpy(s_msg, attrs[AGENT_A_MSG], AGENT_MSG_LEN + 1);
        len -= nla_total_size(nla_len(attrs[AGENT_A_MSG]));
    }

    if (attrs[AGENT_A_CNT] && attrs[AGENT_A_PKT_LOG]) {
        memset(pkt_logs, 0, sizeof(pkt_logs));
        pkt_log_num = nla_get_u32(attrs[AGENT_A_CNT]);
        if (pkt_log_num > 0) {
            cnt = 0;
            current = nla_next(attrs[AGENT_A_CNT], &len);
            while (len > 0 && cnt < pkt_log_num) {
                nla_memcpy(&(pkt_logs[cnt ++]), current, PKT_LOG_SIZE);
                current = nla_next(current, &len);
            }
        }
    }
    
    return NL_OK;
    
 failure:
    s_ret = -1;
    return NL_STOP;
}
