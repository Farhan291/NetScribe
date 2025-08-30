#ifndef IP_H
#define IP_H

typedef struct
{
    unsigned char ver_ihl;
    unsigned char service;
    unsigned short length;
    unsigned short ident;
    unsigned short frag;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned char src[4];
    unsigned char dst[4];

} ip4_hdr;

#endif
