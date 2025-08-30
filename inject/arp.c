#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "srcmac_addr.h"
#include "src_ip.h"
#include "arp.h"

void create_arp(unsigned char* desmac, unsigned char* target_ip)
{

    unsigned char my_ip[4];
    unsigned char interface[IFNAMSIZ];
    unsigned char my_mac_address[6];
    //unsigned char target_ip[4] = {192, 168, 1, 1};
    int successs = srcmac_addr(my_mac_address, interface);
    get_srcip(my_ip);
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    unsigned char buffer[42];
    unsigned char *ptr = buffer;
    memset(ptr, 0xff, 6);
    ptr += 6;
    memcpy(ptr, my_mac_address, 6);
    ptr += 6;
    uint16_t ethertype = htons(0x0806);
    memcpy(ptr, &ethertype, 2);
    ptr += 2;

    struct arp_header *arp = (struct arp_header* )ptr;
    arp->htype = htons(1);      // Ethernet
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;
    arp->plen = 4;
    arp->opcode = htons(1);
    memcpy(arp->src_ip, my_ip, 4);
    memcpy(arp->src_mac, my_mac_address, 6);
    memcpy(arp->des_ip,target_ip, 4);
    memset(arp->des_mac,0x00,6);

    struct sockaddr_ll dest = {0};
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_ARP);
    dest.sll_halen = 6;
    dest.sll_ifindex = if_nametoindex(interface); 
    memset(dest.sll_addr, 0xff, 6);

    if (sendto(sock, buffer, 42, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sock);
        exit(1);
    }
    printf("ARP request sent for %d.%d.%d.%d\n",
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    while (1) {
        unsigned char recv_buf[1500];
        ssize_t len = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
        if (len < 0) {
            perror("recvfrom");
            break;
        }

        struct arp_header *rarp = (struct arp_header *)(recv_buf + 14); 

        memcpy(desmac,&rarp->src_mac,6);

        if (ntohs(rarp->opcode) == 2 && memcmp(rarp->src_ip, target_ip, 4) == 0) {
            printf("Got ARP reply: %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                   rarp->src_ip[0], rarp->src_ip[1], rarp->src_ip[2], rarp->src_ip[3],
                   desmac[0], desmac[1], desmac[2],
                   desmac[3], desmac[4], desmac[5]);
            break;
        }
    }

    close(sock);
}

