build:
	gcc -o netscribe main.c sniff/sniff.c sniff/sniff_main.c server/server.c

clean:
	rm -f netscribe

