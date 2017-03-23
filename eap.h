#ifndef _EAP_H
#define _EAP_H

#include "stdlib.h"
#include "stdio.h"
#include "pcap.h"
#include "string.h"
#include "ping.h"
#include "md5c.h"

extern u_char *clientMac;
extern u_char *boardCastMac;
extern char username[32];
extern char password[16];
extern u_char clientip[4];
extern u_char challenge[16];
extern pcap_t *p;

void *readPacket(void *);
void EAPAuth();
void EAPLogoff();
#endif
