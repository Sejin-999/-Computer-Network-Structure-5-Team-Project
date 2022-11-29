#include<stdio.h>
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//icmp header
#include<netinet/tcp.h>		//tcp header
#include<sys/socket.h>		//sock 생성
#include<arpa/inet.h> 		//
#include<fcntl.h> 		//open 함수
#include<unistd.h> 		// close 함수

//선언 Start
void ProcessPacket(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_icmp_packet(unsigned char* , int);
void PrintData (unsigned char* , int);

//선언 End

// 초기값 설정 Start

int sock_raw_ICMP , sock_raw_TCP;   //icmp , tcp 용 raw 소캣 선언
FILE *logfile; //로그파일 생성 
int tcp=0,icmp=0,others=0,total=0,i,j; //초기화
struct sockaddr_in source,dest; //구조체 선언

// 초기값 설정 End

int main()
{
	int saddr_size , data_size , data_size_icmp;
	struct sockaddr saddr;
	struct in_addr in;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //malloc 메모리 생성 
	
	logfile=fopen("log.txt","w"); //로그파일오픈 ...
	if(logfile==NULL) printf("Unable to create file.");
	printf("캡처 프로그램 시작...\n");
	//raw 소캣 생성.. 소캣 선언용
	sock_raw_ICMP = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP); //icmp socket 생성
	sock_raw_TCP = socket(AF_INET , SOCK_RAW , IPPROTO_TCP); //TCP socket 생성
	
	if((sock_raw_ICMP < 0)  &&(sock_raw_TCP < 0))   //소캣 값 선언 오류시 체크
	{
		printf("소캣 에러 ... 종료합니다\n");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		//소캣받기 Start
		data_size = recvfrom(sock_raw_TCP, buffer , 65536 , 0 , &saddr , &saddr_size);  //tcp 소캣 
		data_size_icmp = recvfrom(sock_raw_ICMP, buffer , 65536 , 0 , &saddr , &saddr_size);
		//소캣받기 End
		if((data_size <0) && (data_size_icmp < 0) )  // 소캣 recv 오류 
		{
			printf("recv 오류 확인\n");
			return 1;
		}
		//Now process the packet
		ProcessPacket(buffer , data_size);
		ProcessPacket(buffer , data_size_icmp);
	}
	close(sock_raw_TCP);
	close(sock_raw_ICMP);
	printf("TCP, ICMP 소캣 종료 확인...\n);
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			print_icmp_packet(Buffer,Size);
			break;
		
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d ICMP : %d  Others : %d   Total : %d\r",tcp,icmp,others,total+1);  //최초 값받을떄 udp값 하나가 들어옴... total+1
}

void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
			
	fprintf(logfile,"\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer,Size);
		
	fprintf(logfile,"\n");
	fprintf(logfile,"TCP Header\n");
	fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile,"\n");
	fprintf(logfile,"                        DATA Dump                         ");
	fprintf(logfile,"\n");
		
	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile,"TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile,"Data Payload\n");	
	PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
						
	fprintf(logfile,"\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
			
	fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");	
	
	print_ip_header(Buffer , Size);
			
	fprintf(logfile,"\n");
		
	fprintf(logfile,"ICMP Header\n");
	fprintf(logfile,"   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11) 
		fprintf(logfile,"  (TTL Expired)\n");
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
		fprintf(logfile,"  (ICMP Echo Reply)\n");
	fprintf(logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(logfile,"\n");

	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile,"UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile,"Data Payload\n");	
	PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));
	
	fprintf(logfile,"\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
	
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile,"."); //otherwise print a dot
			}
			fprintf(logfile,"\n");
		} 
		
		if(i%16==0) fprintf(logfile,"   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
			
			fprintf(logfile,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				else fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}
	}
}
