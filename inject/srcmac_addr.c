#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int srcmac_addr(unsigned char *mac, char *interface) {
  struct ifreq ifr; /*https://man7.org/linux/man-pages/man7/netdevice.7.html*/
  struct ifconf ifc;
  char buf[1024];
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock == -1) {
    perror("sock()");
  };

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if (ioctl(sock, SIOCGIFCONF, &ifc) ==
      -1) /* The kernel does: It fills  buffer with an array of struct ifreqs,
             one for each interface. */
  {
    perror("ioctl()");
  }

  struct ifreq *ptr = (struct ifreq *)buf;
  struct ifreq *end = ptr + (ifc.ifc_len / sizeof(struct ifreq));
  for (; ptr != end; ptr++) {
    memcpy(ifr.ifr_name, ptr->ifr_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
      perror("ioctl SIOCGIFFLAGS");
      continue;
    }
    // Skip loopback interfaces
    if (ifr.ifr_flags & IFF_LOOPBACK)
      continue;
    // Skip docker interfaces
    if (strncmp(ifr.ifr_name, "docker", 6) == 0)
      continue;

    strcpy(interface, ifr.ifr_name);
    // kernel fills ifr_hwaddr with mac address based on interface name
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
      memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
      close(sock);
      return 0;

    } else {
      perror("ioctl SIOCGIFHWADDR");
      close(sock);
      return -1;
    }
  }
  return -1;
}
