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
    size_t tcp_payload_len = 0;

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
            int ip_total_len = ntohs(ip4.length);
            int ip_hdr_len = (ip4.ver_ihl & 0x0F) * 4;
            tcp_payload_len = ip_total_len - ip_hdr_len;
            check = transport_layer_checker4(&ip4);
        }
        else if (check1 == 2)
        {
            ip6_hdr ip6;
            ptr = ip6_parse(&ip6, ptr);
            print_ip6(&ip6);
            tcp_payload_len =ip6.payload_len;
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
            print_tcp(&tcp);
            tcp_payload_len = tcp_payload_len - tcp.doff * 4;
            // printf("len:%zd\n", tcp_payload_len);
            if (tcp_payload_len == 0)
            {
                printf("NO TCP PAYLOAD \n");
                continue;
            }
            check2 = check_proto(&tcp);
            // printf("TLS: %d \n", check2);
            if (check2 == 1)
            {
                tls_record_header tls;
                ptr = tls_record_hdr_parse(&tls, ptr);
                print_tls_record_hdr(&tls);
                if (tls.content_type == 22)
                {

                    size_t record_bytes = ntohs(tls.len); // from TLS record header
                    size_t consumed = 0;
                    printf("bytes:%d", record_bytes);

                    while (consumed < record_bytes)
                    {
                        tls_handshake tlsh;
                        char *start = ptr;

                        // Parse handshake header (type + 3-byte length)
                        ptr = tls_record_frag_parse(&tlsh, ptr);
                        print_tls_record_frag(&tlsh);

                        // Get handshake body length (3-byte field)
                        uint32_t hlen = (tlsh.length[0] << 16) |
                                        (tlsh.length[1] << 8) |
                                        tlsh.length[2];

                        // Skip handshake message body
                        ptr += hlen;

                        // Update how many bytes we’ve consumed from this TLS record
                        consumed += (ptr - start);
                    }
                }
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