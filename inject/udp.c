#include "udp.h"
#include "arp.h"
#include "eth.h"
#include "ip.h"
#include "src_ip.h"
#include "srcmac_addr.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int get_default_gateway(char *gw_ip, char *iface_out) {
  FILE *f =
      fopen("/proc/net/route", "r"); // read route file to know gateway ip addr
  if (!f) {
    perror("fopen");
    return -1;
  }
  char line[256];
  fgets(line, sizeof(line), f);
  while (fgets(line, sizeof(line), f)) {
    char iface[IFNAMSIZ];
    unsigned long dest, gateway;
    int flags;
    if (sscanf(line, "%s %lx %lx %X", iface, &dest, &gateway, &flags) != 4)
      continue;
    if (dest == 0) {
      struct in_addr addr;
      addr.s_addr = gateway;
      if (!inet_ntop(AF_INET, &addr, gw_ip, 16)) {
        perror("inet_ntop");
        fclose(f);
        return -1;
      }
      if (iface_out)
        strcpy(iface_out, iface);

      fclose(f);
      return 0;
    }
  }
  fclose(f);
  return -1;
}
// ones-complement checksum
// https://gist.github.com/fxlv/81209bbd150abfeaceb1f85ff076c9f3
uint16_t checksum(uint16_t *buf, int len) {
  uint32_t sum = 0;
  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1)
    sum += *(uint8_t *)buf;
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

void create_udp(unsigned char *des, char *text, ssize_t len, int srcp,
                int dstp) {
  eth_pkt eth = {0};
  ip4_hdr ip = {0};
  udp_hdr udp = {0};
  unsigned char srcmac[6];
  char interface[IFNAMSIZ];
  srcmac_addr(srcmac, interface);
  unsigned char my_ip[4];
  get_srcip(my_ip);
  char gw_ip[4];
  char gp_iface[IFNAMSIZ];
  int s = get_default_gateway(gw_ip, gp_iface);
  if (s == -1) {
    perror("get_default_gateway()");
    return;
  }
  unsigned char desmac[6];
  create_arp(desmac, gw_ip);
  unsigned char buffer[42 + len];
  unsigned char *ptr = buffer;

  memcpy(&eth.dest_mac, desmac, 6);
  memcpy(&eth.src_mac, srcmac, 6);
  eth.eth_type = htons(0x0800);
  memcpy(ptr, &eth, 14);
  ptr += 14;

  memcpy(&ip.src, my_ip, 4);
  memcpy(&ip.dst, des, 4);
  ip.ver_ihl = (4 << 4) | 5;
  ip.length = htons(sizeof(ip4_hdr) + sizeof(udp_hdr) + len);
  ip.service = 0;
  ip.ident = htons(6969);
  ip.ttl = 48;
  ip.frag = 0;
  ip.protocol = 17;
  ip.check = 0;
  ip.check = ipv4_checksum((unsigned short *)&ip, sizeof(ip) / 2);
  memcpy(ptr, &ip, sizeof(ip));
  ptr += sizeof(ip);

  udp.src = htons(srcp);
  udp.des = htons(dstp);
  udp.lenght = htons(sizeof(udp_hdr) + len);
  udp.checksum = 0;
  memcpy(ptr, &udp, 8);
  ptr += 8;

  memcpy(ptr, text, len);
  ptr += len;

  pseudo_hdr psh;
  memcpy(&psh.src, my_ip, 4);
  memcpy(&psh.dst, des, 4);
  psh.zero = 0;
  psh.proto = 17;
  psh.length = udp.lenght;
  int psize = sizeof(pseudo_hdr) + sizeof(udp_hdr) + len;
  unsigned char *buf = malloc(psize);

  memcpy(buf, &psh, sizeof(psh));
  memcpy(buf + sizeof(psh), &udp, sizeof(udp));
  memcpy(buf + sizeof(psh) + sizeof(udp), text, len);
  udp.checksum = checksum((uint16_t *)buf, psize);
  free(buf);

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
  ssize_t sent_bytes = sendto(sd, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&dest, sizeof(dest));
  close(sd);
}
