#include "eth.h"
#include "fileio.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define ETH_FLAG (1 << 0)
#define ARP_FLAG (1 << 1)
#define IP_FLAG (1 << 2)
#define PAYLOAD_FLAG (1 << 3)

uint16_t g_ethertype = 0x88B5;
char *g_payload_file = NULL;
int layer_flag = 0;
int payload_flag;
int inject_main(int argc, char **argv) {
  int opt = 0;
  while ((opt = getopt(argc, argv, "aeit:p:")) != -1) {
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
    case 'p':
      g_payload_file = optarg;
      break;
    case 't':
      g_ethertype = (uint16_t)strtol(optarg, NULL, 16);
      break;
    }
  }
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
  return 0;
}
