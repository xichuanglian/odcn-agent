#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "uthash.h"
#include "nl_client.h"
#include "pkt_log.h"

#define INTERVAL 1e6 // us
#define PULL_INTERVAL 1e4 // us
#define MAX_RECORD_NUM 1024

static int interrupted = 0;

void interrupt_handler(int signo)
{
    printf("Cleanning up...\n");
    interrupted = 1;
}

typedef struct traffic_record_s {
    uint64_t  id;
    uint32_t  daddr;
    uint32_t  sport;
    uint32_t  dport;
    pkt_proto proto;
    uint32_t  count;
    UT_hash_handle hh;
} traffic_record;

inline uint64_t calc_id(const pkt_log* log)
{
    return (log->daddr & (((uint64_t)1 << 31) - 1)) |
           ((uint64_t)(log->proto == PROTO_UDP) << 31) |
           ((uint64_t)log->sport << 32) | ((uint64_t)log->dport << 48);
}

void print_size(int s)
{
    if (s > 1e9) {
        printf("%.2fGB", s / 1e9);
    } else if (s > 1e6) {
        printf("%.2fMB", s / 1e6);
    } else if (s > 1e3) {
        printf("%.2fKB", s / 1e3);
    } else {
        printf("%dB", s);
    }
}

static char* message_buf;
static int message_len_max = 1024;
static char local_ip[16];

void double_messaage_buffer()
{
    int old_len = message_len_max;
    char* old_buf = message_buf;

    message_len_max *= 2;
    message_buf = malloc(message_len_max);
    memcpy(message_buf, old_buf, old_len);
    free(old_buf);
}

int upload_log(traffic_record* htable, int conn, struct sockaddr_in* s_addr)
{
    memset(message_buf, 0, message_len_max);
    traffic_record* tr_entry;
    int cur_len = 0;
    message_buf[cur_len ++] = '[';
    int first = 1;
    for (tr_entry = htable; tr_entry != NULL; tr_entry=tr_entry->hh.next) {
        if (!first) {
            message_buf[cur_len ++] = ',';
        } else {
            first = 0;
        }
        cur_len += sprintf(message_buf + cur_len,
                           "{"
                           "\"src_ip\":\"%s\","
                           "\"dst_ip\":\"%d.%d.%d.%d\","
                           "\"src_port\":%d,"
                           "\"dst_port\":%d,"
                           "\"size\":%d,",
                           local_ip,
                           (tr_entry->daddr >> 24) & 0xff,
                           (tr_entry->daddr >> 16) & 0xff,
                           (tr_entry->daddr >>  8) & 0xff,
                           (tr_entry->daddr >>  0) & 0xff,
                           tr_entry->sport, tr_entry->dport,
                           tr_entry->count);
        if (tr_entry->proto == PROTO_TCP) {
            cur_len += sprintf(message_buf + cur_len, "\"protocol\":\"tcp\"}");
        } else {
            cur_len += sprintf(message_buf + cur_len, "\"protocol\":\"udp\"}");
        }

        if (cur_len > 0.9 * message_len_max) {
            double_messaage_buffer();
        }
    }
    message_buf[cur_len ++] = ']';
    message_buf[cur_len ++] = '\n';

    if (sendto(conn, message_buf, cur_len , 0 , (struct sockaddr *) s_addr, sizeof(struct sockaddr_in)) == -1) {
        fprintf(stderr, "Failed to send on socket.\n");
        return -1;
    }
    return 0;
}

void print_info(traffic_record* htable, int level)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("time %ld.%06ld:\n", tv.tv_sec, tv.tv_usec);
    traffic_record* tr_entry;
    int tcp_sum, udp_sum;
    tcp_sum = 0;
    udp_sum = 0;
    for (tr_entry = htable; tr_entry != NULL; tr_entry=tr_entry->hh.next) {
        if (level > 1) {
            uint32_t ip = tr_entry->daddr;
            int count = tr_entry->count;
            if (tr_entry->proto == PROTO_UDP) {
                printf("\tUDP");
            } else {
                printf("\tTCP");
            }
            printf("/%d -> %d.%d.%d.%d:%d - ", tr_entry->sport,
                                               (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                                               (ip >> 8) & 0xff, ip & 0xff, tr_entry->dport);
            print_size(count);
            printf("\n");
        }
        if (tr_entry->proto == PROTO_TCP) {
            tcp_sum += tr_entry->count;
        } else {
            udp_sum += tr_entry->count;
        }
    }
    printf("--------------------------------\n");
    printf("\tTCP ");
    print_size(tcp_sum);
    printf("\n");
    printf("\tUDP ");
    print_size(udp_sum);
    printf("\n");
}

int main_loop(uint32_t server_ip, uint16_t server_port, int info_level)
{
    // Initialize UDP socket
    struct sockaddr_in s_addr;
    int conn;
 
    if ((conn = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) <= 0) {
        fprintf(stderr, "Failed to open UDP socket.\n");
        return -1;
    }
 
    memset((char *) &s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = htonl(server_ip);
    s_addr.sin_port = htons(server_port);

    message_buf = malloc(message_len_max);

    // Begin main loop
    pkt_log logs[MAX_PKT_LOG_NUM];
    int ret, i, t;
    traffic_record* tr_hash = NULL;
    traffic_record records[MAX_RECORD_NUM];
    int record_num;

    while (!interrupted) {
        tr_hash = NULL;
        memset(records, 0, sizeof(records));
        record_num = 0;
        t = 0;

        while (t < INTERVAL && !interrupted) {
            usleep(PULL_INTERVAL);
            t += PULL_INTERVAL;
            ret = nl_client_pull(logs);
            if (ret < 0) {
                printf("Failed to pull from kernel module. rc = %d\n", ret);
                goto error;
            }

            for (i = 0; i < ret; ++i) {
                traffic_record* tr_entry;
                uint32_t e_id = calc_id(&(logs[i]));
                int len = logs[i].len;
                HASH_FIND_INT(tr_hash, &e_id, tr_entry);
                if (tr_entry == NULL) {
                    if (record_num < MAX_RECORD_NUM) {
                        tr_entry = &(records[record_num ++]);
                        tr_entry->id = e_id;
                        tr_entry->daddr = logs[i].daddr;
                        tr_entry->sport = logs[i].sport;
                        tr_entry->dport = logs[i].dport;
                        tr_entry->proto = logs[i].proto;
                        tr_entry->count = 0;
                        HASH_ADD_INT(tr_hash, id, tr_entry);
                    }
                }
                if (tr_entry != NULL) {
                    tr_entry->count += len;
                }
            }
        }

        if (interrupted) break;

        if (upload_log(tr_hash, conn, &s_addr) < 0) {
            goto error;
        }
        if (info_level > 0) {
            print_info(tr_hash, info_level);
        }
    }
    close(conn);
    return 0;

error:
    close(conn);
    free(message_buf);
    return -1;
}

int get_local_ip(char* interface)
{
    int fd;
    struct ifreq ifr;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) <= 0) {
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    uint32_t ip = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
    sprintf(local_ip, "%d.%d.%d.%d", (ip >> 24) & 0xff,
                                     (ip >> 16) & 0xff,
                                     (ip >>  8) & 0xff,
                                     (ip >>  0) & 0xff);
    return 0;
}

void parse_ip_port(char* arg, unsigned int* ip, unsigned short* port) {
    int i[4], p;
    sscanf(arg, "%d.%d.%d.%d:%d", &i[0], &i[1], &i[2], &i[3], &p);
    int j;
    *ip = 0;
    for (j = 0; j < 4; ++j) {
        *ip |= i[j] << ((3 - j) * 8);
    }
    *port = p & 0xffff;
}

void show_help() {
    printf( "Usage:\n"
            "  -i <ifce> : NIC to use\n"
            "  -a <ip:port> : Server IP and UDP port\n"
            "  -v[v] : Print verbose info\n"
            "  -h : Show help\n" );
}

int main(int argc, char *argv[])
{
    int rc;
    uint32_t server_ip;
    uint16_t server_port;
    char ifce[IFNAMSIZ];
    int info_level = 0;

    server_ip = 0x7f000001; // 127.0.0.1
    server_port = 6789;
    strcpy(ifce, "eth0");  

    if (argc < 2) {
        printf("No option found.\n");
        show_help();
        goto exit;
    }
    int i = 1;
    while (i < argc) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            switch (arg[1]) {
                case 'i':
                    strcpy(ifce, argv[++ i]);
                    break;
                case 'a':
                    parse_ip_port(argv[++ i], &server_ip, &server_port);
                    break;
                case 'v':
                    info_level += 1;
                    if (arg[2] == 'v') {
                        info_level += 1;
                    }
                    break;
                case 'h':
                    show_help();
                    goto exit;
                default:
                    printf("Unrecognized option: %s\n", argv[i]);
                    goto exit;
            }
        }
        else {
            printf("Not an option: %s\n", argv[i]);
            goto exit;
        }
        i ++;
    }

    if (get_local_ip(ifce) != 0) {
        fprintf(stderr, "Failed to get local IP of interface %s. Exit!\n", argv[1]);
        goto exit;
    }

    rc = nl_client_init(ifce);
    if (rc) {
        fprintf(stderr, "nl_client_init failed: %i\n", rc);
        goto exit;
    }

    if (signal(SIGINT, interrupt_handler) == SIG_ERR) {
        fprintf(stderr, "Failed to catch SIGINT\n");
        nl_client_cleanup();
        goto exit;
    }

    rc = main_loop(server_ip, server_port, info_level);

    nl_client_cleanup();
    return rc;

 exit:
    return -1;
}
