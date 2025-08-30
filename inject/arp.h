#ifndef ARP_H
#define ARP_H


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
struct arp_header {
    uint16_t htype;    // Hardware type (1 for Ethernet)
    uint16_t ptype;    // Protocol type (0x0800 for IPv4)
    uint8_t  hlen;     // Hardware size (6)
    uint8_t  plen;     // Protocol size (4)
    uint16_t opcode;   // 1 for request, 2 for reply
    unsigned char src_mac[6];
    unsigned char src_ip[4];
    unsigned char des_mac[6];
    unsigned char des_ip[4];
} __attribute__((packed));

#endif