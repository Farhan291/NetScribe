#ifndef UDP_H
#define UDP_H
#include <stdint.h>
#include <stdio.h>
typedef struct {
  unsigned short src;
  unsigned short des;
  unsigned short lenght;
  unsigned short checksum;
} udp_hdr;

typedef struct {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t proto;
  uint16_t length;
} pseudo_hdr;
int get_default_gateway(char *gw_ip, char *iface_out);
uint16_t checksum(uint16_t *buf, int len);
void create_udp(unsigned char *des, char *text, ssize_t len, int srcp,
                int dstp);

#endif
