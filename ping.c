#include "ping.h"
#include "time.h"

typedef unsigned char u_char;

extern u_char serverip[4];
extern u_char clientip[4];
extern u_char challenge[16];
extern char interface_name[32];
extern int sockfd;
extern struct sockaddr_in addr;
extern char username[32];
extern char password[16];
extern u_char *clientMac;

u_char globalCheck[4];
u_char counter;
u_char UknCode_1,UknCode_2,UknCode_3;

void putCode1(u_char buf[],u_char length){
	u_char v5 = length >> 2;
	unsigned int v6 = 0;
	unsigned int v7 = 0;
	*(unsigned int*)&buf[24] = 20000711;
	*(unsigned int*)&buf[28] = 126;
	int i;
	for(i=0;i<v5;i++){
		v6 ^= *(unsigned int *)&buf[4*i];
	}
	*(unsigned int*)&buf[24] = 19680126 * v6;
	*(unsigned int*)&buf[28] = 0;
	*(unsigned int*)&globalCheck = 19680126 * v6;
}
	
void putCode2(u_char buf[]){
	unsigned short v5 = 0;
	unsigned short v7 = 0;
	u_char v6 = 0;
	do{
		v7 = *(unsigned short *)&buf[2 * v6++];
		v5 ^= v7;
	}while(v6 < 20);
	*(unsigned int*)&buf[24] = 711 * v5;
}

void sendPingStart(){
	system("ifup vwan1");
	system("ifup wan");
	char ins[256] = {0};
	sprintf(ins,"ifconfig %s %d.%d.%d.%d netmask 255.255.255.0",interface_name,clientip[0],clientip[1],clientip[2],clientip[3]);
	printf(ins);
	system(ins);
	sprintf(ins,"route add -host 192.168.127.129 gw 192.168.%d.254",clientip[2]);
	printf(ins);
	system(ins);
	system("route add -net 210.38.0.0 netmask 255.255.0.0 gw 192.168.195.254");
	int tid2;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(61440);
	inet_pton(AF_INET,"192.168.127.129",&addr.sin_addr);
	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	if(connect(sockfd,(struct sockaddr *)&addr,sizeof(struct sockaddr_in))<0){
		printf("UDP Connect Error\n");
	}
	pthread_create(&tid2,NULL,reciveUDP,NULL);

	u_char startPack[] = {0x07,0x00,0x08,0x00,0x01,0x00,0x00,0x00};
	sendto(sockfd,startPack,8,0,0,0);
}



void sendPing38(){
	printf("Pring 38...\n");
	short t = (short)time(NULL);
	u_char buf[38] = {0};
	buf[0] = 0xff;
	memcpy(buf+1,globalCheck,4);
	memcpy(buf+5,challenge+4,12);
	strcpy(buf+20,"Drco");
	memcpy(buf+24,serverip,4);
	buf[28] = UknCode_1;
	if(UknCode_2 >= 128){
		buf[29] = UknCode_2<<1 | 1;
	}else{
		buf[29] = UknCode_2 << 1;
	}
	memcpy(buf+30,clientip,4);
	buf[34] = 0x01;
	if(UknCode_3%2 == 0){
		buf[35] = UknCode_3 >> 1;
	}else{
		buf[35] = UknCode_3>>1 | 128;
	}
	memcpy(buf+36,(unsigned char *)(&t),2);
	sendto(sockfd,buf,38,0,0,0);
}

void sendPing40(u_char step){
	printf("Ping 40...\n");
	u_char buf[40] = {0};
	buf[0] = 0x07;
	buf[1] = counter;
	buf[2] = 0x28;
	buf[4] = 0x0b;
	buf[5] = step;
	*(unsigned int*)&buf[6] = 0x6f6c02dc;
	if(step == 3){
		memcpy(buf+28,clientip,4);
		printf("after\n");
		putCode2(buf);
	}
	counter++;
	sendto(sockfd,buf,40,0,0,0);
}

void sendPingInfo(u_char data[]){
	u_char buf[244] = {0};
	u_char otherInfo[201] = {0};
	u_char usrLength = strlen(username);
	
	u_char dns1[4] = {223,5,5,5};
	u_char dns2[4] = {223,6,6,6};

	buf[0] = 0x07;
	buf[1] = 0x01;
	buf[2] = usrLength + 233;
	buf[4] = 0x03;
	buf[5] = usrLength;
	memcpy(buf+6,clientMac,6);
	memcpy(buf+12,clientip,4);
	buf[16] = 0x02;
	buf[17] = 0x22;
	buf[19] = 0x24;
	memcpy(buf+20,data,4);
	strcpy(buf+32,username);
	strcpy(otherInfo,"laji");
	memcpy(otherInfo+32,dns1,4);
	memcpy(otherInfo+40,dns2,4);
	otherInfo[52] = 0x94;
	otherInfo[56] = 0x06;
	otherInfo[60] = 0x02;
	otherInfo[64] = 0xf0;
	otherInfo[65] = 0x23;
	otherInfo[68] = 0x02;
	strcpy(otherInfo+72,"DrCOM");
	otherInfo[77] = 0x05;
	otherInfo[78] = 0xb8;
	otherInfo[79] = 0x01;
	otherInfo[80] = 0x04;
	strcpy(otherInfo+136,"391515fd339f62b530cd63a027cd4ef95139069f");
	memcpy(buf+32+usrLength,otherInfo,201);
	putCode1(buf,usrLength+233);
	sendto(sockfd,buf,usrLength+233,0,0,0);
}


void pingCycle(){
	sleep(1);
	while(1){
		sendPing40(1);
		sleep(10);
		sendPing38();
		sleep(5);
	}
}

void *reciveUDP(void *tid){
	u_char buf[4096];
	int n;
	pthread_t t_cycle;

	while(1){
		n = recvfrom(sockfd,buf,4096,0,0,0);
		if(buf[0]==0x07){
			if(buf[2]==0x10 && n==32){
				sendPingInfo(buf+8);
			}else if(buf[2]==0x30){
				UknCode_1 = buf[24];
				UknCode_2 = buf[25];
				UknCode_3 = buf[31];
				pthread_create(&t_cycle,NULL,pingCycle,NULL);
			}else if(buf[2]==0x28){
				if(buf[5] == 0x02){
					sendPing40(3);
				}
			}
		}
	}
}


