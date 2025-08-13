#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

#include "server/server.h"
#include "sniff/sniff.h"
#define BUFFER 4048

int main(void)
{

    int rs = create_socket();
    printf("%d", rs);
    if (rs < 0)
    {
        return 1;
    }
    char buffer[BUFFER];
    char *ptr;

    while (1)
    {
        ssize_t rc = recvfrom(rs, buffer, sizeof(buffer), 0, NULL, NULL);
        if (rc < 0)
        {
            perror("recvfrom() ");
        }

        if (rc < 14)
        {
            fprintf(stderr, "Packet too short: %zd bytes\n", rc);
            continue;
        }
        ether eth;
        ptr = etherparse(buffer, &eth);
        print_ether(&eth);

        int check1 = check_ipver(&eth);
        int check = 0;
        int check2 = 0;
        if (check1 == 1)
        {
            ip4_hdr ip4;
            ptr = ip4_parse(buffer, &ip4, ptr);
            print_ip4(&ip4);
            check = transport_layer_checker4(&ip4);
        }
        else if (check1 == 2)
        {
            ip6_hdr ip6;
            ptr = ip6_parse(&ip6, ptr);
            print_ip6(&ip6);
            check = transport_layer_checker6(&ip6);
        }
        else if (check1 == 3)
        {
            arp_hdr arp;
            ptr = arp_parse(&arp, ptr);
            print_arp(&arp);
        }
        // printf("check1: %d \n",check1);
        // printf(" \n check:       %d",check);
        if (check == 1)
        {
            tcp tcp;
            ptr = tcp_parser(&tcp, ptr);
            ptr = print_tcp(&tcp, ptr);
            check2 = check_proto(&tcp);
            //printf("TLS: %d \n", check2);
            if (check2 == 1)
            {
                tls_record_header tls;
                ptr = tls_record_hdr_parse(&tls, ptr);
                print_tls_record_hdr(&tls);
            }
        }
        else if (check == 2)
        {
            udp udp;
            ptr = udp_parse(&udp, ptr);
            print_udp(&udp);
        }
        else if (check == 3)
        {
            icmp_hdr icmp;
            ptr = icmp_parse(&icmp, ptr);
            print_icmp(&icmp);
        }
    }
}