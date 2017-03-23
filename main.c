#include "stdlib.h"
#include "stdio.h"
#include "pthread.h"
#include "pcap.h"
#include "string.h"
#include "eap.h"
#include "ping.h"
#include "sys/socket.h"
#include "netinet/in.h"


pcap_t *p;
u_char *clientMac;
u_char *boardCastMac;
char username[32];
char password[16];
u_char clientip[] = {192,168,195,95};
u_char serverip[] = {192,168,127,129};
u_char challenge[16];
char interface_name[32];
int sockfd;
struct sockaddr_in addr;


int main(int argc,char *argv[]){
	if(argc != 6){
		printf("Wrong Args\n");
		return 0;
	}
	
	strcpy(username,argv[1]);
	strcpy(password,argv[2]);
	printf("Username:%s,Password:%s\n",username,password);
	sscanf(argv[3],"%d.%d.%d.%d",&clientip[0],&clientip[1],&clientip[2],&clientip[3]);
	strcpy(interface_name,argv[5]);

	printf("%d,%d,%d,%d\n",clientip[0],clientip[1],clientip[2],clientip[3]);

	int i,r;
	pthread_t tid1,tid2;
	char errBuf[512];
	struct bpf_program filter;
	char filterText[100];
	char devName[10];
	//scanf("%s",devName);
	p = pcap_open_live("eth0",65535,0,0,errBuf);
	if(p == NULL){
		printf("---%s\n",errBuf);
		return 0;
	}
	u_char cMac[] = {0x28,0xd2,0x44,0x2d,0x90,0x69};
	u_char bMac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
	sscanf(argv[4],"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&cMac[0],&cMac[1],&cMac[2],&cMac[3],&cMac[4],&cMac[5]);
	clientMac = cMac;
	boardCastMac = bMac;
	sprintf(filterText,"ether[0:4]=0x%02hhx%02hhx%02hhx%02hhx && ether[4:2]=0x%02hhx%02hhx",clientMac[0],clientMac[1],clientMac[2],clientMac[3],clientMac[4],clientMac[5]);	//过滤类型为0x888e的包
	//sprintf(filterText,"ether[16:2]=0x888e");	//过滤类型为0x888e的包
	/*---修正sprintf()函数字符串格式化问题---
	for(i=0;i<21;i++)
		if(filterText[i] == ' ')
			filterText[i] = '0';
	for(i=30;i<40;i++)
		if(filterText[i] == ' ')
			filterText[i] = '0';
	/*--------------------------------------*/
	printf("%s\n",filterText);
	r = pcap_compile(p,&filter,filterText,0,0);
	if(r == -1){
		printf("Err: %s\n",errBuf);
		return 0;
	}
	r = pcap_setfilter(p,&filter);
	if(r == -1){
		printf("ERR: %s\n",errBuf);
		return 0;
	}
	r = pthread_create(&tid1,NULL,readPacket,NULL);
	if(r != 0){
		printf("Create pthread error\n");
		return 1;
	}

	EAPAuth();
	pthread_join(tid1,NULL);
}
	

