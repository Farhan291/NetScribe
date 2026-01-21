#include "icmp.h"
#include "arp.h"
#include "eth.h"
#include "ip.h"
#include "src_ip.h"
#include "srcmac_addr.h"
#include "udp.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define ICMP_ECHO 0

void create_icmp(char *des) {
  eth_pkt eth = {0};
  ip4_hdr ip = {0};
  icmp_hdr icmp = {0};
  unsigned char srcmac[6];
  unsigned char dst_ip[4];
  char interface[IFNAMSIZ];
  srcmac_addr(srcmac, interface);
  unsigned char my_ip[4];

  if (inet_pton(AF_INET, des, dst_ip) != 1) {
    printf("Invalid destination IP\n");
    return;
  }
  get_srcip(my_ip);
  char gw_ip[16];
  char gp_iface[IFNAMSIZ];
  int s = get_default_gateway(gw_ip, gp_iface);
  if (s == -1) {
    perror("get_default_gateway()");
    return;
  }
  unsigned char desmac[6];

  if (memcmp(dst_ip, my_ip, 4) == 0) {
    printf("idk");
    memcpy(desmac, srcmac, 6);
  } else {
    create_arp(desmac, gw_ip);
  }

  unsigned char buffer[42];
  unsigned char *ptr = buffer;

  memcpy(&eth.dest_mac, desmac, 6);
  memcpy(&eth.src_mac, srcmac, 6);
  eth.eth_type = htons(0x0800);
  memcpy(ptr, &eth, 14);
  ptr += 14;

  memcpy(&ip.src, my_ip, 4);
  memcpy(&ip.dst, dst_ip, 4);
  ip.ver_ihl = (4 << 4) | 5;
  ip.length = htons(sizeof(ip4_hdr) + sizeof(icmp_hdr));
  ip.service = 0;
  ip.ident = htons(6969);
  ip.ttl = 48;
  ip.frag = 0;
  ip.protocol = 1;
  ip.check = 0;
  // https://github.com/wwwlaomao/embedded-c-utils/blob/main/icmp-checksum.c
  ip.check = ipv4_checksum((unsigned short *)&ip, sizeof(ip) / 2);
  memcpy(ptr, &ip, sizeof(ip));
  ptr += sizeof(ip);

  icmp.type = ICMP_ECHO;
  icmp.code = 0;
  icmp.id = htons(6969);
  icmp.seq = htons(6969);
  icmp.checksum = 0;

  icmp.checksum = checksum((uint16_t *)&icmp, sizeof(icmp));

  memcpy(ptr, &icmp, sizeof(icmp));
  ptr += sizeof(icmp);

  int packet_len = ptr - buffer;

  int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sd < 0) {
    perror("socket()");
    close(sd);
    return;
  }
  struct sockaddr_ll dest = {0};
  dest.sll_family = AF_PACKET;
  dest.sll_ifindex = if_nametoindex(interface);
  dest.sll_halen = 6;
  memcpy(dest.sll_addr, desmac, 6);
  ssize_t sent_bytes =
      sendto(sd, buffer, packet_len, 0, (struct sockaddr *)&dest, sizeof(dest));

  if (sent_bytes < 0)
    perror("sendto");
  else
    printf("ICMP Echo Request sent (%zd bytes)\n", sent_bytes);

  close(sd);
}
