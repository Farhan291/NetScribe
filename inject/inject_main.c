#include "arp.h"
#include "eth.h"
#include "fileio.h"
#include "ip.h"
#include "udp.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ETH_FLAG (1 << 0)
#define ARP_FLAG (1 << 1)
#define IP_FLAG (1 << 2)
#define PAYLOAD_FLAG (1 << 3)
#define UDP_FLAG (1 << 4)

uint16_t g_ethertype = 0x88B5;
char *g_payload_file = NULL;
int src_port = 6969;
int dst_port = 6969;

int layer_flag = 0;
int payload_flag;
int inject_main(int argc, char **argv) {
  int opt = 0;
  while ((opt = getopt(argc, argv, "aeius:d:t:p:")) != -1) {
    switch (opt) {
    case 'e':
      layer_flag |= ETH_FLAG;
      break;
    case 'a':
      layer_flag |= ARP_FLAG;
      break;
    case 'i':
      layer_flag |= IP_FLAG;
      break;
    case 'u':
      layer_flag |= UDP_FLAG;
      break;
    case 's':
      src_port = atoi(optarg);
      break;
    case 'd':
      dst_port = atoi(optarg);
      break;
    case 'p':
      g_payload_file = optarg;
      break;
    case 't':
      g_ethertype = (uint16_t)strtol(optarg, NULL, 16);
      break;
    }
  }
  // inject ethernet
  if (layer_flag & ETH_FLAG) {
    if (optind >= argc) {
      printf(
          "Usage: netscribe -e [-t ethertype] [-p payloadfile] <dest-mac>\n");
      return 1;
    }
    char *dest_mac = argv[optind];
    unsigned char des_mac[6] = {0};
    if (parse_mac(dest_mac, des_mac) != 0) {
      printf("Invalid MAC address\n");
      return 1;
    }
    char *text = "iamlight";
    size_t payload_len = 8;

    char *file_payload = NULL;

    if (g_payload_file) {
      file_payload = (char *)payload(g_payload_file, &payload_len);

      if (!file_payload) {
        printf("Failed to load payload file\n");
        return 1;
      }

      text = file_payload;
    }

    eth_create(des_mac, text, payload_len, g_ethertype);
  }
  // inject arp
  if (layer_flag & ARP_FLAG) {
    if (optind >= argc) {
      printf("Usage: netscribe -a  <dest-ip> \n");
      return 1;
    }
    char *dst_ip = argv[optind];
    unsigned char desmac[6];
    create_arp(desmac, dst_ip);
  }
  // inject ip4
  if (layer_flag & IP_FLAG) {
    if (optind >= argc) {
      printf("Usage: netscribe -i <dest-ip> \n");
      return 1;
    }
    char *dst_ip = argv[optind];
    create_ip(dst_ip);
  }
  // inject udp
  if (layer_flag & UDP_FLAG) {
    if (optind >= argc) {
      printf("Usage: netscribe -u -s <src_port> -d <dst_port> [-p payloadfile] "
             "<dest-ip>\n");
      return 1;
    }

    char *dst_ip_str = argv[optind];
    unsigned char dst_ip[4];
    if (inet_pton(AF_INET, dst_ip_str, dst_ip) != 1) {
      printf("Invalid destination IP\n");
      return 1;
    }
    char *text = "hello\n";
    size_t payload_len = strlen(text);
    char *file_payload = NULL;

    if (g_payload_file) {
      file_payload = (char *)payload(g_payload_file, &payload_len);
      if (!file_payload) {
        printf("Failed to load payload file\n");
        return 1;
      }
      text = file_payload;
    }
    printf("UDP inject:\n");
    printf("  Src port: %d\n", src_port);
    printf("  Dst port: %d\n", dst_port);
    printf("  Dest IP : %s\n", dst_ip_str);
    printf("  Payload : %zu bytes\n", payload_len);

    create_udp(dst_ip, text, payload_len, src_port, dst_port);

    if (file_payload)
      free(file_payload);
  }

  return 0;
}
