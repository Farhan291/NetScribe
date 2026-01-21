# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -Wextra -O2
LDFLAGS := 

# Output binary
TARGET := netscribe

# Source files
SRCS := \
    main.c \
    sniff/sniff.c \
    sniff/sniff_main.c \
    server/server.c \
    inject/inject_main.c \
    inject/eth.c \
    inject/srcmac_addr.c \
    inject/fileio.c \
    inject/arp.c \
    inject/src_ip.c \
    inject/udp.c \
    inject/ip.c \
    inject/icmp.c

# Object files 
OBJS := $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link step
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile step
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Rebuild everything
re: clean all

.PHONY: all clean re

