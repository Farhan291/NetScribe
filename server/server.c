#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


int create_socket(){
    int raw_sock = socket(
        AF_PACKET,
        SOCK_RAW,
        htons(ETH_P_ALL)
    );
    if (raw_sock<0) {
        perror("socket()");
        return -1;
    }
    return raw_sock;
}

