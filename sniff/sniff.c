#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "sniff.h"

char *ptr;
char *etherparse(char *buff, ether *ethernetheader)
{

    ptr = buff;

    memcpy(ethernetheader->dest_mac, ptr, 6);
    ptr += 6;

    memcpy(ethernetheader->src_mac, ptr, 6);
    ptr += 6;

    memcpy(&ethernetheader->eth_type, ptr, 2);
    ptr += 2;
    return ptr;
}

void print_ether(ether *eth)
{
    printf("MAC     | ");
    for (int j = 0; j < 6; j++)
    {
        printf("%.2X", eth->src_mac[j]);
        if (j < 5)
            printf(":");
    }
    printf(" --> ");
    for (int i = 0; i < 6; i++)
    {
        printf("%.2X", eth->dest_mac[i]);
        if (i < 5)
            printf(":");
    }
    printf(" PROTO: 0x%04x\n", ntohs(eth->eth_type));
}
int check_ipver(ether *eth)
{
    if (ntohs(eth->eth_type) == 0x0800)
    {
        return 1;
    }
    else if (ntohs(eth->eth_type) == 0x86DD)
    {
        return 2;
    }
    else if(ntohs(eth->eth_type)==0x0806){
        return 3;
    }
    return 0;
}

char* arp_parse(arp_hdr* arp,char* ptr){          
    memcpy(&arp->htype,ptr,2);
    ptr+=2;
    memcpy(&arp->ptype,ptr,2);
    ptr+=2;
    memcpy(&arp->hlen,ptr,1);
    ++ptr;
    memcpy(&arp->plen,ptr,1);
    ++ptr;
    memcpy(&arp->op,ptr,2);
    ptr+=2;
    memcpy(&arp->sha,ptr,6);
    ptr+=6;
    memcpy(&arp->spa,ptr,4);
    ptr+=4;
    memcpy(&arp->tha,ptr,6);
    ptr+=6;
    memcpy(&arp->tpa,ptr,4);
    ptr+=4;
}

void print_arp(arp_hdr* arp){
    /*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Hardware Type (HTYPE)         |   Protocol Type (PTYPE)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hardware Addr Length (HLEN) | Protocol Addr Length (PLEN)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Operation (OPER)            |                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Hardware Address (SHA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Hardware Address (SHA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Protocol Address (SPA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Protocol Address (SPA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Hardware Address (THA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Hardware Address (THA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Protocol Address (TPA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Protocol Address (TPA)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

    struct in_addr spa_addr, tpa_addr;
    spa_addr.s_addr = arp->spa;
    tpa_addr.s_addr = arp->tpa;

    printf("ARP  | op: %u\n", ntohs(arp->op));
    printf("     Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->sha[0], arp->sha[1], arp->sha[2],
           arp->sha[3], arp->sha[4], arp->sha[5]);
    printf("     Sender IP: %s\n", inet_ntoa(spa_addr));
    printf("     Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->tha[0], arp->tha[1], arp->tha[2],
           arp->tha[3], arp->tha[4], arp->tha[5]);
    printf("     Target IP: %s\n", inet_ntoa(tpa_addr));

}

char *ip4_parse(char *buff, ip4_hdr *ip, char *ptr)
{
    memcpy(&ip->ver_ihl, ptr, 1);
    ++ptr;
    memcpy(&ip->service, ptr, 1);
    ++ptr;
    memcpy(&ip->length, ptr, 2);
    ptr += 2;
    memcpy(&ip->ident, ptr, 2);
    ptr += 2;
    memcpy(&ip->frag, ptr, 2);
    ptr += 2;
    memcpy(&ip->ttl, ptr, 1);
    ++ptr;
    memcpy(&ip->protocol, ptr, 1);
    ++ptr;
    memcpy(&ip->check, ptr, 2);
    ptr += 2;
    memcpy(ip->src, ptr, 4);
    ptr += 4;
    memcpy(ip->dst, ptr, 4);
    ptr += 4;
    return ptr;
}
void print_ip4addr(unsigned char *ip)
{
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void print_ip4(ip4_hdr *iph)
{
    unsigned char version = iph->ver_ihl >> 4;
    unsigned char ihl = iph->ver_ihl & 0x0F;

    printf("IP      | ");
    print_ip4addr(iph->src);
    printf(" --> ");
    print_ip4addr(iph->dst);
    printf(" VERSION:%u", version);
    printf(" IHL:%u", ihl);
    printf(" PROTO:%u", iph->protocol);
    printf(" TOS:%u", iph->service);
    printf(" TTL:%u", iph->ttl);
    printf(" ID:%u", ntohs(iph->ident));
    printf(" CHECK:%x", ntohs(iph->check));
    printf(" LEN:%u\n", ntohs(iph->length));
}
char *ip6_parse(ip6_hdr *ip6, char *ptr)
{
    memcpy(&ip6->header, ptr, 4);
    ptr += 4;
    memcpy(&ip6->head, ptr, 4);
    ptr += 4;
    memcpy(&ip6->src, ptr, 16);
    ptr += 16;
    memcpy(&ip6->des, ptr, 16);
    ptr += 16;
    return ptr;
}

void print_ip6(ip6_hdr *ip6)
{
    uint32_t full_header = ntohl(ip6->header);
    ip6->version = full_header >> 28;
    ip6->traffic_class = (full_header >> 20) & 0xFF;
    ip6->flow_label = full_header & 0xFFFFF;

    uint32_t full_head = ntohl(ip6->head);
    ip6->payload_len = full_head >> 16;
    ip6->next_header = (full_head >> 8) & 0xFF;
    ip6->hop_limit = full_head & 0xFF;

    printf("IP6     |");
    printf("%u", ip6->src);
    printf("-->%u", ip6->des);
    printf(" ver:%u", ip6->version);
    printf(" traffclas:%u", ip6->traffic_class);
    printf(" flowlb:%u", ip6->flow_label);
    printf(" payloadlen:%u", ip6->payload_len);
    printf(" nexhead:%u", ip6->next_header);
    printf(" hoplim:%u\n", ip6->hop_limit);
}

int transport_layer_checker4(ip4_hdr *ip)
{
    if (ip->protocol == 6)
    {
        return 1;
    }
    else if (ip->protocol == 17)
    {
        return 2;
    }
    else if (ip->protocol == 1)
    {
        return 3;
    }
    return 0;
}
int transport_layer_checker6(ip6_hdr *ip)
{
    if (ip->next_header == 6)
    {
        return 1;
    }
    else if (ip->next_header == 17)
    {
        return 2;
    }
    return 0;
}

char *tcp_parser(tcp *tcph, char *ptr)
{
    memcpy(&tcph->src, ptr, 2);
    ptr += 2;
    memcpy(&tcph->des, ptr, 2);
    ptr += 2;
    memcpy(&tcph->seqno, ptr, 4);
    ptr += 4;
    memcpy(&tcph->ackno, ptr, 4);
    ptr += 4;
    memcpy(&tcph->flag, ptr, 2);
    ptr += 2;
    memcpy(&tcph->winsize, ptr, 2);
    ptr += 2;
    memcpy(&tcph->check, ptr, 2);
    ptr += 2;
    memcpy(&tcph->urgptr, ptr, 2);
    ptr += 2;
    

    return ptr;
}

char* print_tcp(tcp *tcp,char* ptr)
{

    uint16_t flags_all = ntohs(tcp->flag);
    tcp->doff = (flags_all >> 12);
    tcp->res1 = (flags_all >> 6) & 0xF;
    uint16_t flags_only = flags_all & 0x003F;

    printf("TCP     |");
    printf(":%u", ntohs(tcp->src));
    printf("-->:%u", ntohs(tcp->des));
    printf(" SEQNO:%u", ntohl(tcp->seqno));
    printf(" ACKNO:%u", ntohl(tcp->ackno));
    //printf(" doff:%u",tcp->doff);
    if (flags_only & 0x20)
    {
        tcp->urg = 1;
        printf(" URG");
    }
    if (flags_only & 0x10)
    {
        tcp->ack = 1;
        printf(" ACK");
    }
    if (flags_only & 0x08)
    {
        tcp->psh = 1;
        printf(" PSH");
    }
    if (flags_only & 0x04)
    {
        tcp->rst = 1;
        printf(" RST");
    }
    if (flags_only & 0x02)
    {
        tcp->syn = 1;
        printf(" SYN");
    }
    if (flags_only & 0x01)
    {
        tcp->fin = 1;
        printf(" FIN");
    }
    if (flags_only & 0x40)
        printf(" ECE");
    if (flags_only & 0x80)
        printf(" CWR");
    printf("(0x%04x)", flags_only);
    printf(" WINSIZE:%u", ntohs(tcp->winsize));
    printf(" CHECK:%u", ntohs(tcp->check));
    printf(" URGPTR:%u \n", ntohl(tcp->urgptr));
    if(tcp->doff>5){
        int n = tcp->doff -5;
        //printf("n:%d",n);
        ptr+=n*4;

    }
    return ptr;
    
}

char *udp_parse(udp *udp, char *ptr)
{
    memcpy(&udp->src, ptr, 2);
    ptr += 2;
    memcpy(&udp->des, ptr, 2);
    ptr += 2;
    memcpy(&udp->lenght, ptr, 2);
    ptr += 2;
    memcpy(&udp->checksum, ptr, 2);
    ptr += 2;
    return ptr;
}

void print_udp(udp *udph)
{
    printf("UDP     |");
    printf("%u", ntohs(udph->src));
    printf("-->%u", ntohs(udph->des));
    printf(" LEN:%u", ntohs(udph->lenght));
    printf(" CHECK:%u\n", ntohs(udph->checksum));
}

char *icmp_parse(icmp_hdr *icmp, char *ptr)
{
    memcpy(&icmp->header, ptr, 4);
    ptr += 4;
    memcpy(icmp->message, ptr, 4);
    ptr += 4;
    return ptr;
}

void print_icmp(icmp_hdr *icmp)
{
    u_int32_t full_header = icmp->header;

    icmp->type = full_header >> 24;
    icmp->code = (full_header >> 16) & 0xFF;
    icmp->check = full_header & 0xFFFF;

    printf("ICMP     |");
    printf("type:%u", icmp->type);
    printf("code:%u", icmp->code);
    printf("check:%u", ntohs(icmp->check));
    printf("body: %02x %02x %02x %02x\n",
           icmp->message[0], icmp->message[1],
           icmp->message[2], icmp->message[3]);
    }

int check_proto(tcp* tcp){
    if(ntohs(tcp->src)==443|| ntohs(tcp->des)==443){
        return 1;
    }
    return 0;
}

char* tls_record_hdr_parse(tls_record_header* tls,char* ptr){
    memcpy(&tls->content_type,ptr,1);
    ++ptr;
    memcpy(&tls->version,ptr,2);
    ptr+=2;
    memcpy(&tls->len,ptr,2);
    ptr+=2;
    return ptr;
}

void print_tls_record_hdr(tls_record_header* tls){
    printf("TLS_RCD |");
    printf(" type:%u",tls->content_type);
    printf(" ver:%u",ntohs(tls->version));
    printf(" len:%u \n",ntohs(tls->len));
}