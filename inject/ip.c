#include "ip.h"
#include "arp.h"
#include "src_ip.h"
#include "srcmac_addr.h"
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

unsigned short ipv4_checksum(unsigned short *buf, int nwords) {
  unsigned long sum = 0;
  for (int i = 0; i < nwords; i++)
    sum += ntohs(buf[i]);
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return htons(~sum & 0xFFFF);
}

void create_ip(char *des_ip) {
  unsigned char my_ip[4];
  unsigned char des_ip_bin[4];
  char interface[IFNAMSIZ];
  unsigned char my_mac_address[6];
  unsigned char desmac_addr[6];
  unsigned char buffer[34];

  if (inet_pton(AF_INET, des_ip, des_ip_bin) != 1) {
    printf("Invalid IP address\n");
    return;
  }

  int success = srcmac_addr(my_mac_address, interface);
  get_srcip(my_ip);
  create_arp(desmac_addr, des_ip);
  unsigned char *ptr = buffer;
  memcpy(ptr, desmac_addr, 6);
  ptr += 6;
  memcpy(ptr, my_mac_address, 6);
  ptr += 6;
  uint16_t ethertype = htons(0x0800);
  memcpy(ptr, &ethertype, 2);
  ptr += 2;

  ip4_hdr ip = {0};
  ip.ver_ihl = (4 << 4) | 5;
  ip.length = htons(sizeof(ip4_hdr));
  ip.service = 0;
  ip.ident = htons(6969);
  ip.ttl = 48;
  ip.frag = 0;
  ip.protocol = 0;
  memcpy(ip.src, my_ip, 4);
  memcpy(ip.dst, des_ip_bin, 4);
  ip.check = ipv4_checksum((unsigned short *)&ip, sizeof(ip) / 2);
  memcpy(ptr, &ip, sizeof(ip));
  ptr += sizeof(ip);

  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("socket");
    return;
  }
  struct sockaddr_ll dest = {0};
  dest.sll_family = AF_PACKET;
  dest.sll_ifindex = if_nametoindex(interface);
  dest.sll_halen = 6;
  memcpy(dest.sll_addr, desmac_addr, 6);
  ssize_t sent = sendto(sock, buffer, sizeof(buffer), 0,
                        (struct sockaddr *)&dest, sizeof(dest));
  if (sent < 0)
    perror("sendto");
  close(sock);
}
