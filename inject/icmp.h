#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seq;
} icmp_hdr;
void create_icmp(char *des);
#endif
