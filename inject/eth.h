#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include <stdio.h>
typedef struct {
  unsigned char dest_mac[6];
  unsigned char src_mac[6];
  unsigned short eth_type;

} eth_pkt;

void eth_create(unsigned char *des, char *text, ssize_t len, uint16_t ethtype);
int parse_mac(char *str, unsigned char *mac);

#endif
