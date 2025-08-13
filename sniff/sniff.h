#ifndef SNIFF_H
#define SNIFF_H
#include <linux/if_ether.h>

typedef struct
{
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short eth_type;

} ether;

typedef struct
{
    uint16_t htype;        /* Format of hardware address */
    uint16_t ptype;        /* Format of protocol address */
    uint8_t hlen;          /* Length of hardware address */
    uint8_t plen;          /* Length of protocol address */
    uint16_t op;           /* ARP opcode (command) */
    uint8_t sha[ETH_ALEN]; /* Sender hardware address */
    uint32_t spa;          /* Sender IP address */
    uint8_t tha[ETH_ALEN]; /* Target hardware address */
    uint32_t tpa;          /* Target IP address */
} arp_hdr;

char *arp_parse(arp_hdr *arp, char *ptr);
void print_arp(arp_hdr *arp);

typedef struct
{
    unsigned char ver_ihl;
    unsigned char service;
    unsigned short length;
    unsigned short ident;
    unsigned short frag;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned char src[4];
    unsigned char dst[4];

} ip4_hdr;

typedef struct
{
    union
    {
        uint32_t header;
        struct
        {
            uint32_t version : 4;
            uint32_t traffic_class : 8;
            uint32_t flow_label : 20;
        };
    };
    union
    {
        uint32_t head;
        struct
        {
            uint32_t payload_len : 16;
            uint32_t next_header : 8;
            uint32_t hop_limit : 8;
        };
    };
    __uint128_t src;
    __uint128_t des;

} ip6_hdr;

int check_ipver(ether *eth);

char *ip6_parse(ip6_hdr *ip6, char *ptr);
void print_ip6(ip6_hdr *ip6);

char *etherparse(char *buff, ether *ethernetheader);
void print_ether(ether *eth);

char *ip4_parse(char *buff, ip4_hdr *ip, char *ptr);
void print_ip4addr(unsigned char *ip);
void print_ip4(ip4_hdr *iph);

int transport_layer_checker4(ip4_hdr *ip);
int transport_layer_checker6(ip6_hdr *ip);

typedef struct
{
    unsigned short src;
    unsigned short des;
    uint32_t seqno;
    uint32_t ackno;
    union
    {
        unsigned short flag;
        struct
        {
            uint16_t res1 : 4;
            uint16_t doff : 4;
            uint16_t fin : 1;
            uint16_t syn : 1;
            uint16_t rst : 1;
            uint16_t psh : 1;
            uint16_t ack : 1;
            uint16_t urg : 1;
            uint16_t ece : 1;
            uint16_t cwr : 1;
        };
    };
    unsigned short winsize;
    unsigned short check;
    unsigned short urgptr;

} tcp;

char *tcp_parser(tcp *tcph, char *ptr);
char* print_tcp(tcp *tcp,char* ptr);

int check_proto(tcp* tcp);

typedef struct
{
    unsigned short src;
    unsigned short des;
    /*union
    {
        unsigned short lenght;
        struct
        {
            uint16_t zero : 8;
            uint16_t protocol : 8;
            uint16_t len : 16;
        };
    };*/
    unsigned short lenght;

    unsigned short checksum;

} udp;

char *udp_parse(udp *udp, char *ptr);
void print_udp(udp *udph);

typedef struct
{
    union
    {
        uint32_t header;
        struct
        {
            u_int32_t type : 8;
            u_int32_t code : 8;
            u_int32_t check : 16;
        };
    };
    unsigned char message[4];

} icmp_hdr;

char *icmp_parse(icmp_hdr *icmp, char *ptr);
void print_icmp(icmp_hdr *icmp);

typedef enum
{
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20
} HandshakeType;

typedef struct{
    uint8_t content_type;
    u_int16_t version;
    uint16_t len;
    

} tls_record_header;

char* tls_record_hdr_parse(tls_record_header* tls,char*);
void print_tls_record_hdr(tls_record_header* tls);

typedef struct
{
    HandshakeType msg_type;
    uint8_t  length[3];

} tls_handshake;

#endif