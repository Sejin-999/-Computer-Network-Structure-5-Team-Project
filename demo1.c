#include<stdio.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>	
#include<stdlib.h>	//malloc
#include<string.h>	//strlen

#include<netinet/ip_icmp.h>	
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>	
#include<netinet/if_ether.h>	
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,total=0,i,j;	

int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
		
	unsigned char *buffer = (unsigned char *) malloc(65536);
	
	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
	{
		printf("로그파일 생성 불가");
	}
	printf("캡처시작 . ICMP , TCP , UDP\n");
	
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;  //그냥 PROTOCOL_TCP 이런걸로 열면 들어오는것밖에안되고 하나씩 다열어줘야한다. 
	
	
	if(sock_raw < 0)
	{
		perror("알수없는 소캣에러");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 )
		{
			printf("리시브오류\n");
			return 1;
		}
		//프로세스 패킷 시작 
		ProcessPacket(buffer , data_size);
	}
	close(sock_raw);
	printf("캡처 종료");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) 
	{
		case 1:  //ICMP Protocol
			++icmp;
			print_icmp_packet( buffer , size);
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
		
		default: 
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d  Others : %d   Total : %d\r", tcp , udp , icmp , others , total);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	fprintf(logfile , "\n\nTCP\n");	
		
	print_ip_header(Buffer,Size);
	
	if((ntohs(tcph->source)==22) || (ntohs(tcph->dest)==22)){
		//ssh 캡처 
		fprintf(logfile , "\n");
		fprintf(logfile , "SSH 패킷 캡처\n");
		fprintf(logfile , "   |== 출발 Port  == |    : %u\n",ntohs(tcph->source));
		fprintf(logfile , "   |== 목적지 Port ==|    : %u\n",ntohs(tcph->dest));
		fprintf(logfile , "   |== 시퀀스 번호 ==|     : %u\n",ntohl(tcph->seq));
		fprintf(logfile , "   |== 확인 번호   ==|     : %u\n",ntohl(tcph->ack_seq));
		fprintf(logfile , "   |== Checksum   ==|     : %d\n",ntohs(tcph->check));
		fprintf(logfile , "   |== 긴급 포인터 ==|     : %d\n",tcph->urg_ptr);
		fprintf(logfile , "\n");
		fprintf(logfile , "                        데이터 덤프                     ");
		fprintf(logfile , "\n");

		fprintf(logfile , "IP Header\n");
		PrintData(Buffer,iphdrlen);

		fprintf(logfile , "TCP Header\n");
		PrintData(Buffer+iphdrlen,tcph->doff*4);

		fprintf(logfile , "Data Payload\n");	
		PrintData(Buffer + header_size , Size - header_size );

		fprintf(logfile , "\n");
		
	}
	
	if((ntohs(tcph->source)==53) || (ntohs(tcph->dest)==53)){
		//DNS TCP 캡처 
		fprintf(logfile , "\n");
		fprintf(logfile , "DNS TCP 캡처\n");
		fprintf(logfile , "   |== 출발 Port  == |    : %u\n",ntohs(tcph->source));
		fprintf(logfile , "   |== 목적지 Port ==|    : %u\n",ntohs(tcph->dest));
		fprintf(logfile , "   |== 시퀀스 번호 ==|     : %u\n",ntohl(tcph->seq));
		fprintf(logfile , "   |== 확인 번호   ==|     : %u\n",ntohl(tcph->ack_seq));
		fprintf(logfile , "   |== Checksum   ==|     : %d\n",ntohs(tcph->check));
		fprintf(logfile , "   |== 긴급 포인터 ==|     : %d\n",tcph->urg_ptr);
		fprintf(logfile , "\n");
		fprintf(logfile , "                        데이터 덤프                     ");
		fprintf(logfile , "\n");

		fprintf(logfile , "IP Header\n");
		PrintData(Buffer,iphdrlen);

		fprintf(logfile , "TCP Header\n");
		PrintData(Buffer+iphdrlen,tcph->doff*4);

		fprintf(logfile , "Data Payload\n");	
		PrintData(Buffer + header_size , Size - header_size );

		fprintf(logfile , "\n");
		
	}
	
	
	if((ntohs(tcph->source)==80) || (ntohs(tcph->dest)==80)){
		//HTTP TCP 캡처 
		fprintf(logfile , "\n");
		fprintf(logfile , "HTTP TCP 캡처\n");
		fprintf(logfile , "   |== 출발 Port  == |    : %u\n",ntohs(tcph->source));
		fprintf(logfile , "   |== 목적지 Port ==|    : %u\n",ntohs(tcph->dest));
		fprintf(logfile , "   |== 시퀀스 번호 ==|     : %u\n",ntohl(tcph->seq));
		fprintf(logfile , "   |== 확인 번호   ==|     : %u\n",ntohl(tcph->ack_seq));
		fprintf(logfile , "   |== Checksum   ==|     : %d\n",ntohs(tcph->check));
		fprintf(logfile , "   |== 긴급 포인터 ==|     : %d\n",tcph->urg_ptr);
		fprintf(logfile , "\n");
		fprintf(logfile , "                        데이터 덤프                     ");
		fprintf(logfile , "\n");

		fprintf(logfile , "IP Header\n");
		PrintData(Buffer,iphdrlen);

		fprintf(logfile , "TCP Header\n");
		PrintData(Buffer+iphdrlen,tcph->doff*4);

		fprintf(logfile , "Data Payload\n");	
		PrintData(Buffer + header_size , Size - header_size );

		fprintf(logfile , "\n");
		
	}

	fprintf(logfile , "\n");
	fprintf(logfile , "TCP 캡처\n");
	fprintf(logfile , "   |== 출발 Port  == |    : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |== 목적지 Port ==|    : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |== 시퀀스 번호 ==|     : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |== 확인 번호   ==|     : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |== Checksum   ==|     : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |== 긴급 포인터 ==|     : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        데이터 덤프                     ");
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);

	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);

	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );

	fprintf(logfile , "\n");
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
	// 설정 Start
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile , "\n\nUDP Packet\n");
	
	print_ip_header(Buffer,Size);			
	// 설정 End
	
	// 필터링 Start
	if((ntohs(udph->dest) == 53)||(ntohs(udph->source) == 53)){
		//udp ... dns check

		fprintf(logfile , "\nDNS UDP 캡처\n");
		fprintf(logfile , "   |== 출발 Port  == |     : %d\n" , ntohs(udph->source));
		fprintf(logfile , "   |== 목적지 Port ==|     : %d\n" , ntohs(udph->dest));
		fprintf(logfile , "   |== UDP Checksum==|     : %d\n" , ntohs(udph->check));
		
		
		fprintf(logfile , "\n");
		fprintf(logfile , "IP Header\n");
		PrintData(Buffer , iphdrlen);

		fprintf(logfile , "UDP Header\n");
		PrintData(Buffer+iphdrlen , sizeof udph);

		fprintf(logfile , "Data Payload\n");	


		PrintData(Buffer + header_size , Size - header_size);

		fprintf(logfile , "\n");
	}
	
	if((ntohs(udph->dest) == 80)||(ntohs(udph->source) == 80)){
		//udp ... http check

		fprintf(logfile , "\nHTTP UDP 캡처\n");
		fprintf(logfile , "   |== 출발 Port  == |     : %d\n" , ntohs(udph->source));
		fprintf(logfile , "   |== 목적지 Port ==|     : %d\n" , ntohs(udph->dest));
		fprintf(logfile , "   |== UDP Checksum==|     : %d\n" , ntohs(udph->check));
		
		
		fprintf(logfile , "\n");
		fprintf(logfile , "IP Header\n");
		PrintData(Buffer , iphdrlen);

		fprintf(logfile , "UDP Header\n");
		PrintData(Buffer+iphdrlen , sizeof udph);

		fprintf(logfile , "Data Payload\n");	


		PrintData(Buffer + header_size , Size - header_size);

		fprintf(logfile , "\n");
	}
	//필터링 End

	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	
	
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n");
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	fprintf(logfile , "\n\nICMP Packet\n");	
	
	print_ip_header(Buffer , Size);
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile , "Data Payload\n");	
	
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n");
}

void PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); 
				
				else fprintf(logfile , "."); 
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); 
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}
