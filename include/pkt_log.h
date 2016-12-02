#ifndef __PKT_LOG_H__
#define __PKT_LOG_H__

#ifndef __KERNEL__
#include <stdint.h>
#endif

typedef enum {
    PROTO_TCP,
    PROTO_UDP
} pkt_proto;

typedef struct pkt_log_s {
    uint16_t  sport;
    uint16_t  dport;
    uint32_t  daddr;
    uint32_t  len;
    pkt_proto proto;
} pkt_log;

#define PKT_LOG_SIZE (sizeof(pkt_log))
#define MAX_PKT_LOG_NUM 65536

#endif