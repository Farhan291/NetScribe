#ifndef SNIFF_MAIN_H
#define SNIFF_MAIN_H

#define BUFFER 4048
#define FLAG_TCP (1 << 0)
#define FLAG_UDP (1 << 1)
#define FLAG_ICMP (1 << 2)
#define FLAG_ARP (1 << 3)

typedef enum {
  PROTOCOL_UNKNOWN = 0,
  PROTOCOL_TCP,
  PROTOCOL_UDP,
  PROTOCOL_ICMP
} TransportProto;

typedef enum { IP_UNKNOWN = 0, IP_V4, IP_V6, ARP } ip_version_t;

int sniff_main(int argc, char **argv);
#endif
