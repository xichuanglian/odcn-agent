#ifndef NL_CLIENT_H
#define NL_CLIENT_H

#include "pkt_log.h"

int  nl_client_init(const char* ifce);
void nl_client_cleanup();
int  nl_client_pull(pkt_log* logs);

#endif
