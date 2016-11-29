#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>

#include "uthash.h"
#include "nl_client.h"
#include "pkt_log.h"

#define INTERVAL 1e6 // us
#define PULL_INTERVAL 1e4 // us
#define MAX_RECORD_NUM 1024

void interrupt_handler(int signo)
{
    printf("Cleanning up...\n");
    nl_client_cleanup();
}

typedef struct traffic_record_s {
    uint32_t ip;
    uint32_t count;
    UT_hash_handle hh;
} traffic_record;

void main_loop()
{
    pkt_log logs[MAX_PKT_LOG_NUM];
    int ret, i, t;
    traffic_record* tr_hash = NULL;
    traffic_record records[MAX_RECORD_NUM];
    int record_num;

    while (1) {
        tr_hash = NULL;
        memset(records, 0, sizeof(records));
        record_num = 0;
        t = 0;

        while (t < INTERVAL) {
            usleep(PULL_INTERVAL);
            t += PULL_INTERVAL;
            ret = nl_client_pull(logs);
            if (ret < 0) {
                printf("Failed to pull from kernel module. rc = %d\n", ret);
                nl_client_cleanup();
                exit(-1);
            }

            //printf("ret: %d\n", ret);
            for (i = 0; i < ret; ++i) {
                traffic_record* tr_entry;
                uint32_t dst_ip = logs[i].daddr;
                int len = logs[i].len;
                //printf("%08x %d\n", dst_ip, len);
                HASH_FIND_INT(tr_hash, &dst_ip, tr_entry);
                if (tr_entry == NULL) {
                    if (record_num < MAX_RECORD_NUM) {
                        tr_entry = &(records[record_num ++]);
                        tr_entry->ip = dst_ip;
                        tr_entry->count = 0;
                        HASH_ADD_INT(tr_hash, ip, tr_entry);
                    }
                }
                if (tr_entry != NULL) {
                    tr_entry->count += len;
                }
            }
        }

        traffic_record* tr_entry;
        for (tr_entry = tr_hash; tr_entry != NULL; tr_entry=tr_entry->hh.next) {
            uint32_t ip = tr_entry->ip;
            int count = tr_entry->count;
            printf("%d.%d.%d.%d - ", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
            if (count > 1e9) {
                printf("%.2fGB\n", count / 1e9);
            } else if (count > 1e6) {
                printf("%.2fMB\n", count / 1e6);
            } else if (count > 1e3) {
                printf("%.2fKB\n", count / 1e3);
            } else {
                printf("%dB\n", count);
            }
        }
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    int rc;

    if (argc < 2) {
        printf("Usage: ./agent <interface>\n");
        goto exit;
    }
    
    rc = nl_client_init(argv[1]);
    if (rc) {
        fprintf(stderr, "nl_client_init failed: %i\n", rc);
        goto exit;
    }

    if (signal(SIGINT, interrupt_handler) == SIG_ERR) {
        printf("Failed to catch SIGINT\n");
        nl_client_cleanup();
        goto exit;
    }

    main_loop();
 exit:
    return 0;
}
