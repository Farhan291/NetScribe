#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "server/server.h"
#include "sniff/sniff.h"
#define BUFFER 4048

typedef enum {
  PROTOCOL_UNKNOWN = 0,
  PROTOCOL_TCP,
  PROTOCOL_UDP,
  PROTOCOL_ICMP
} TransportProto;

typedef enum { IP_UNKNOWN = 0, IP_V4, IP_V6, ARP } ip_version_t;

int main(void) {

  int rs = create_socket();
  if (rs < 0) {
    return 1;
  }
  char buffer[BUFFER];
  char *ptr;
  size_t tcp_payload_len = 0;

  while (1) {
    ssize_t rc = recvfrom(rs, buffer, sizeof(buffer), 0, NULL, NULL);
    if (rc < 0) {
      perror("recvfrom() ");
    }

    if (rc < 14) {
      fprintf(stderr, "Packet too short: %zd bytes\n", rc);
      continue;
    }
    ether eth;
    ptr = etherparse(buffer, &eth);
    print_ether(&eth);

    int check_ip = check_ipver(&eth);
    int check_protocol = 0;
    int check_port = 0;

    switch (check_ip) {
    case IP_V4: {
      ip4_hdr ip4;
      ptr = ip4_parse(buffer, &ip4, ptr);
      print_ip4(&ip4);
      int ip_total_len = ntohs(ip4.length);
      int ip_hdr_len = (ip4.ver_ihl & 0x0F) * 4;
      tcp_payload_len = ip_total_len - ip_hdr_len;
      check_protocol = transport_layer_checker4(&ip4);
      break;
    }
    case IP_V6: {
      ip6_hdr ip6;
      ptr = ip6_parse(&ip6, ptr);
      print_ip6(&ip6);
      tcp_payload_len = ip6.payload_len;
      check_protocol = transport_layer_checker6(&ip6);
      break;
    }
    case ARP: {
      arp_hdr arp;
      ptr = arp_parse(&arp, ptr);
      print_arp(&arp);
      break;
    }
    default:
      break;
    }
    switch (check_protocol) {

    case PROTOCOL_TCP: {
      tcp tcp;
      ptr = tcp_parser(&tcp, ptr);
      print_tcp(&tcp);

      tcp_payload_len = tcp_payload_len - tcp.doff * 4;

      if (tcp_payload_len == 0) {
        printf("NO TCP PAYLOAD \n");
        break;
      }

      check_port = check_proto(&tcp);

      if (check_port == 1) {
        tls_record_header tls;
        ptr = tls_record_hdr_parse(&tls, ptr);
        print_tls_record_hdr(&tls);

        if (tls.content_type != 22) {
          printf("Non-handshake record (Type %u) - skipping parsing\n",
                 tls.content_type);
          break;
        }

        size_t record_bytes = ntohs(tls.len);
        size_t consumed = 0;

        if (record_bytes > tcp_payload_len) {
          record_bytes = tcp_payload_len;
        }

        while (consumed + 4 <= record_bytes) {
          tls_handshake tlsh;

          ptr = tls_record_frag_parse(&tlsh, ptr);

          uint32_t hlen =
              (tlsh.length[0] << 16) | (tlsh.length[1] << 8) | tlsh.length[2];

          if (consumed + 4 + hlen > record_bytes) {
            printf("Handshake body overflows buffer (fragmented packet). "
                   "Stopping parse.\n");
            break;
          }

          print_tls_record_frag(&tlsh);

          ptr += hlen;
          consumed += (4 + hlen);
        }
      }
      break;
    }

    case PROTOCOL_UDP: {
      udp udp;
      ptr = udp_parse(&udp, ptr);
      print_udp(&udp);
      break;
    }

    case PROTOCOL_ICMP: {
      icmp_hdr icmp;
      ptr = icmp_parse(&icmp, ptr);
      print_icmp(&icmp);
      break;
    }

    default:
      break;
    }
  }
}
