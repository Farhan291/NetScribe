build:
	gcc -o netscribe main.c sniff/sniff.c sniff/sniff_main.c server/server.c inject/inject_main.c inject/eth.c inject/srcmac_addr.c inject/fileio.c inject/arp.c  inject/src_ip.c
clean:
	rm -f netscribe

