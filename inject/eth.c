#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <string.h>
#include "../server/server.h"
#include "srcmac_addr.h"

void eth_create(unsigned char *des, char *text)
{
    int sd = create_socket();
    int s = strlen(text);
    unsigned char interface[IFNAMSIZ];
    unsigned char my_mac_address[6];
    unsigned char ethhdr[14 + s + 1];
    unsigned char *ptr = ethhdr;
    struct sockaddr_ll des_addr;
    int su = srcmac_addr(my_mac_address, interface);
    memset(&des_addr, 0, sizeof(des_addr));
    des_addr.sll_family = AF_PACKET;
    des_addr.sll_ifindex = if_nametoindex(interface);
    if (des_addr.sll_ifindex == 0)
    {
        perror("if_nametoindex");
        return;
    }
    des_addr.sll_halen = 6;
    memcpy(des_addr.sll_addr, des, 6);

    memcpy(ethhdr, des, 6);
    ptr += 6;
    memcpy(ptr, my_mac_address, 6);
    ptr += 6;
    uint16_t ethertype = htons(0x88B5);
    memcpy(ptr, &ethertype, 2);
    ptr += 2;
    memcpy(ptr, text, s);
    ptr += s;
    ssize_t sent_bytes = sendto(sd, ethhdr, 14 + s, 0,
                                (struct sockaddr *)&des_addr, sizeof(des_addr));
}

int parse_mac(char *str, unsigned char *mac)
{
    if (strlen(str) != 17)
        return -1;
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6)
    {
        return -1;
    }
    for (int i = 0; i < 6; ++i)
        mac[i] = (unsigned char)values[i];
    return 0;
}
void main()
{
    unsigned char dest_mac[] = "ff:ff:ff:ff:ff:ff";
    unsigned char des_mac[6]={0};
    int s = parse_mac(dest_mac,des_mac);
    eth_create(des_mac, "iamlight");
}