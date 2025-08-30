#ifndef ETH_H
#define ETH_H

typedef struct
{
    struct eth
    {
        unsigned char dest_mac[6];
        unsigned char src_mac[6];
        unsigned short eth_type;
    };

} eth_pkt;

void eth_create(unsigned char *des, char *text);
int parse_mac(char *str, unsigned char *mac);

#endif