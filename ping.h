#ifndef _PING_H
#define _PING_H

#include "sys/socket.h"
#include "stdio.h"
#include "netinet/in.h"
#include "pthread.h"

void *reciveUDP(void *id);
void sendPingStart();

#endif

