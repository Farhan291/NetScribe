#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct arp_header {
  uint16_t htype;  // Hardware type (1 for Ethernet)
  uint16_t ptype;  // Protocol type
  uint8_t hlen;    // Hardware size
  uint8_t plen;    // Protocol size
  uint16_t opcode; // 1 for request, 2 for reply
  unsigned char src_mac[6];
  unsigned char src_ip[4];
  unsigned char des_mac[6];
  char des_ip[4];
} __attribute__((packed));

void create_arp(unsigned char *desmac, char *target_ip);

#endif
