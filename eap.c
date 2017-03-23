#include "eap.h"
#include "unistd.h"

#define VLAN_TAG 4

extern char password[16];
unsigned char handled = 0;
int isUDP = 0;

void showPacket(u_char *packet,int len){
	int i;
	printf("Len: %d\n",len);
	printf("[");
	for(i=0;i<len;i++){
		printf("%d ",packet[i]);
	}
	printf("]\n");
}	
	

void handlePacket(u_char *userarg,const struct pcap_pkthdr *pkthdr,const u_char* packet){
	if(packet[16]!=0x88 || packet[17]!=0x8e){
		return;
	}
	switch(packet[18+VLAN_TAG]){
		case 0x03:
			if(!isUDP){
				sendPingStart();
			}
			isUDP = 1;
			handled = 1;
			printf("Success\n");
			break;
		case 0x01:	//Request
			switch(packet[22+VLAN_TAG]){
				case 0x04:
					responseMd5Challenge(packet+24+VLAN_TAG);
					break;
				case 0x02:
					break;//Send Notification
				case 0x01:
					responseIdentity(packet[19+VLAN_TAG]);
					break;//Send Identity
			}
			break;
		case 0x04:
			handled = 1;
			printf("Failed\n");
			printf("Retry...\n");
			sleep(5);
			EAPLogoff();
			EAPLogoff();
			EAPAuth();
	}
}

void sendEAPOL(u_char version,u_char type,u_char srcMAC[6],u_char dstMAC[6]){
	u_char buf[60+VLAN_TAG] = {0};
	memcpy(buf,dstMAC,6);
	memcpy(buf+6,srcMAC,6);
	buf[12] = 0x81;	//0x8100,Vlan tag
	buf[15] = 0x02;
	buf[12+VLAN_TAG] = 0x88;	
	buf[13+VLAN_TAG] = 0x8e;
	buf[14+VLAN_TAG] = version;
	buf[15+VLAN_TAG] = type;
	showPacket(buf,60+VLAN_TAG);
	pcap_sendpacket(p,buf,60+VLAN_TAG);
}

void sendEAP(u_char id,u_char type,u_char typedata[],u_char datalen,u_char code,u_char srcMAC[6],u_char dstMAC[6]){
	u_char buf[60+VLAN_TAG] = {0};
	memcpy(buf,dstMAC,6);
	memcpy(buf+6,srcMAC,6);
	buf[12] = 0x81; //0x8100,Vlan tag
	buf[15] = 0x02;
	buf[12+VLAN_TAG] = 0x88;
	buf[13+VLAN_TAG] = 0x8e;
	buf[14+VLAN_TAG] = 0x01;	//Version
	buf[15+VLAN_TAG] = 0x00;	//Type
	buf[17+VLAN_TAG] = datalen + 5;	//EAP-Length
	buf[18+VLAN_TAG] = code;
	buf[19+VLAN_TAG] = id;
	buf[21+VLAN_TAG] = datalen + 5;
	buf[22+VLAN_TAG] = type;
	memcpy(buf+23+VLAN_TAG,typedata,datalen);
	showPacket(buf,60+VLAN_TAG);
	pcap_sendpacket(p,buf,60+VLAN_TAG);
}

void EAPAuth(){
	printf("EAP Start...\n");
	sendEAPOL(0x01,0x01,clientMac,boardCastMac);
}

void EAPLogoff(){
	sendEAPOL(0x01,0x00,clientMac,boardCastMac);
}

void responseIdentity(u_char id){
	printf("response Identity...\n");
	u_char data[37];
	u_char ukBytes[] = {0x00,0x44,0x61,0x00,0x00};
	strcpy(data,username);
	memcpy(data+strlen(username),ukBytes,5);
	memcpy(data+strlen(username)+5,clientip,4);
	sendEAP(id,0x01,data,strlen(username)+9,2,clientMac,boardCastMac);
}

void responseMd5Challenge(u_char *data){
	printf("Response EAP-MD5-Challenge...\n");
	u_char dataPack[37] = {0};
	u_char mPack[37] = {0};
	u_char ukBytes[] = {0x00,0x44,0x61,0x26,0x00};
	MD5_CTX ctx;
	printf("+++++\n");
	showPacket(data,16);
	strcpy(mPack+1,password);
	memcpy(mPack+1+strlen(password),data,16);
	MD5Init(&ctx);
	MD5Update(&ctx,mPack,17+strlen(password));
	MD5Final(challenge,&ctx);
	printf("MD5\n");
	showPacket(mPack,23);
	showPacket(challenge,16);
	dataPack[0] = 16;
	memcpy(dataPack+1,challenge,16);
	strcpy(dataPack+17,username);
	memcpy(dataPack+17+strlen(username),ukBytes,5);
	memcpy(dataPack+22+strlen(username),clientip,4);
	showPacket(dataPack,37);
	sendEAP(0x00,0x04,dataPack,37,0x02,clientMac,boardCastMac);
}



void *readPacket(void *threadid){
	while(1){
		pcap_loop(p,1,handlePacket,NULL);
	}
}

