#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../server/server.h"
#include "sniff.h"
#include "sniff_main.h"

int proto_flags = 0;
int opt;
int sniff_main(int argc, char **argv) {
  while ((opt = getopt(argc, argv, "tuia")) != -1) {
    switch (opt) {
    case 't':
      proto_flags |= FLAG_TCP;
      break;
    case 'u':
      proto_flags |= FLAG_UDP;
      break;
    case 'i':
      proto_flags |= FLAG_ICMP;
      break;
    case 'a':
      proto_flags |= FLAG_ARP;
      break;
    default:
      fprintf(stderr, "Usage: %s [-t] [-u] [-i] [-a]\n", argv[0]);
      return 1;
    }
  }
  if (proto_flags == 0)
    proto_flags = FLAG_TCP | FLAG_UDP | FLAG_ICMP;

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
    ip4_hdr ip4;
    ip6_hdr ip6;
    arp_hdr arp;
    ptr = etherparse(buffer, &eth);

    int check_ip = check_ipver(&eth);

    if ((proto_flags & FLAG_ARP) &&
        !(proto_flags & (FLAG_TCP | FLAG_UDP | FLAG_ICMP)) && check_ip != ARP) {
      continue;
    }
    int check_protocol = 0;
    int check_port = 0;

    switch (check_ip) {
    case IP_V4: {
      ptr = ip4_parse(buffer, &ip4, ptr);
      int ip_total_len = ntohs(ip4.length);
      int ip_hdr_len = (ip4.ver_ihl & 0x0F) * 4;
      tcp_payload_len = ip_total_len - ip_hdr_len;
      check_protocol = transport_layer_checker4(&ip4);
      break;
    }
    case IP_V6: {
      ptr = ip6_parse(&ip6, ptr);
      tcp_payload_len = ip6.payload_len;
      check_protocol = transport_layer_checker6(&ip6);
      break;
    }
    case ARP: {
      if (!(proto_flags & FLAG_ARP))
        continue;
      ptr = arp_parse(&arp, ptr);
      check_protocol = PROTOCOL_UNKNOWN;
      break;
    }
    default:
      break;
    }
    if (check_protocol == PROTOCOL_TCP && !(proto_flags & FLAG_TCP))
      continue;

    if (check_protocol == PROTOCOL_UDP && !(proto_flags & FLAG_UDP))
      continue;

    if (check_protocol == PROTOCOL_ICMP && !(proto_flags & FLAG_ICMP))
      continue;

    print_ether(&eth);
    switch (check_ip) {
    case IP_V4:
      print_ip4(&ip4);
      break;
    case IP_V6:
      print_ip6(&ip6);
      break;
    case ARP:
      print_arp(&arp);
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
