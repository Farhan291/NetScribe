#include "srcmac_addr.h"
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

void get_srcip(unsigned char *ip) {
  char interface[IFNAMSIZ];
  unsigned char my_mac_address[6];
  int sucesss = srcmac_addr(my_mac_address, interface);
  int fd;
  struct ifreq ifr = {0};
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    return;
  }
  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
    perror("ioctl");
    close(fd);
    return;
  }
  struct sockaddr_in *src_ip = (struct sockaddr_in *)&ifr.ifr_addr;
  memcpy(ip, &src_ip->sin_addr, 4);
  printf("IP address of %s: %d.%d.%d.%d\n", interface, ip[0], ip[1], ip[2],
         ip[3]);

  close(fd);
}
