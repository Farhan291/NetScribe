# NetScribe

NetScribe is a packet sniffer and packet injector written in C using Linux raw sockets.

It is designed as an educational and experimental tool to explore how Ethernet, ARP, IPv4, UDP, and ICMP work at the wire level.  
All packets are parsed and crafted manually without relying on external networking libraries.

This project implements parts of a basic user-space network stack.

---

> [!IMPORTANT]  
> This project is for educational and research purposes only.
>
> Running packet sniffers and injectors on networks you do not own or have permission to test may be illegal.
>
> Use responsibly.

---

## Table of Contents

- [Supported Protocols and Key Features](#supported-protocols-and-key-features)
- [Installation & Build](#installation--build)
  - [Prerequisites](#prerequisites)
  - [Build Instructions](#build-instructions)
- [Permissions](#permissions)
- [Usage](#usage)
  - [Sniff mode](#sniff-mode)
  - [Inject Mode](#inject-mode)
    - [Ethernet Injection](#ethernet-injection)
    - [ARP Injection](#arp-injection)
    - [IPv4 Injection](#ipv4-injection)
    - [UDP Injection](#udp-injection)
    - [ICMP Injection (Ping)](#icmp-injection-ping)
- [Implementation Details](#implementation-details)
- [Current Status](#current-status)
- [TODO](#todo)

## Supported Protocols and Key Features

- **Multiple Protocol Support** : NetScribe natively handles a wide range of protocols including Ethernet, ARP, IPv4, IPv6, ICMP, TCP, and UDP, ensuring broad coverage for both analysis and generation.

- **Network Packet Injecting** : Create and transmit custom-crafted network packets directly on specified network interfaces. This includes defining custom MAC addresses, IP headers, and source/destination ports for UDP/TCP.

- **Payload Integration** : Load custom data directly from external files into your network packets. This allows for testing how networks handle specific data structures or large payloads without manual string entry.

- **Network Sniffing** : Capture Live network traffic with customizable filtering options. Users can isolate specific traffic types (e.g., just TCP or ARP) and perform deep packet inspection, including TLS handshake analysis.

---

## Installation & Build

### Prerequisites

- A Linux-based environment (required for raw sockets).

- gcc and make.

### Build Instructions

Clone the repository and compile the project

```bash
git clone https://github.com/Farhan291/NetScribe.git
cd NetScribe
make
```

---

## Permissions

Since NetScribe uses raw sockets, it requires elevated privileges. Instead of running everything with sudo, it is recommended to grant the executable the specific capabilities it needs:

```bash
 sudo setcap cap_net_raw+ep ./netscribe
```

## Usage

NetScribe has two main modes:

- `sniff` → Packet sniffer

- `inject` → Packet injector

General format:

```bash
./netscribe <mode> [options]
```

### Sniff mode

Sniffing all supported network protocol packets:

```bash
./netscribe sniff
```

**Protocol Filters**

- ` -t`: TCP

- ` -u`: UDP

- `-i`: ICMP/ICMPv6

- `-a`: ARP

## Example:

Sniff UDP, ICMP, and ARP

```bash
./netscribe sniff -u -i -a
```

---

## Inject Mode

Inject manually crafted packets.

**Ethernet Injection**

```bash
./netscribe inject -e -t <ethertype> [-p payloadfile] <dest-mac>
```

**Example**  
Ethernet packet with the payload `data.txt` to the MAC address `00:11:22:33:44:55` with ethertype `0x69696`.

```bash
./netscribe inject -e -t 0x6969 -p data.txt 00:11:22:33:44:55
```

---

**ARP Injection**  
Send an ARP request for a given IP.

```bash
./netscribe inject -a <dest-ip>
```

**Example**  
ARP request asking who has the IP address `192.168.1.1`.

```bash
./netscribe inject -a 192.168.1.1
```

---

**IPv4 Injection**  
Send a raw IPv4 packet (no transport payload):

```bash
./netscribe inject -i <dest-ip>
```

**Example**  
IP packet from Host machine IP to the IP address `8.8.8.8`.

```bash
./netscribe inject -i 8.8.8.8
```

---

**UDP Injection**  
Send a UDP packet with custom ports and optional payload

```bash
./netscribe inject -u -s <src_port> -d <dst_port> [-p payloadfile] <dest-ip>
```

**Example**  
UDP packet with the payload file `msg.txt` from the Host machine IP address to the IP address `192.168.1.5` with the source port `6969` and the destination port `53`:

```bash
./netscribe inject -u -s 6969 -d 53 -p msg.txt 192.168.1.5
```

---

**ICMP Injection** (Ping)  
Send an ICMP Echo Request (custom ping):

```bash
./netscribe inject -c <dest-ip>
```

**Example**  
ICMP packet from Host machine IP address to the IP address `1.1.1.1`

```bash
./netscribe inject -c 1.1.1.1
```

## Implementation Details

NetScribe manually implements:

- Ethernet frame parsing and construction
- ARP request/reply handling
- IPv4 header construction and checksum
- UDP header construction and checksum
- ICMP Echo Request with checksum
- Basic routing logic:
  - Direct delivery on same subnet
  - Gateway resolution for remote hosts
- ARP resolution using raw sockets
- Interface discovery using ioctl

No external packet libraries are used.

## Current Status

**Sniffing**: Stable  
 **Injection**:

- **Ethernet**: Done
- **ARP**: Done
- **IPv4**: Done
- **UDP**: Done
- **ICMP**: Done
- **TCP**: Not yet implemented

## TODO

- [ ] TCP packet injection (SYN, ACK, RST)
- [ ] TCP checksum and handshake logic
- [ ] Logging to file
- [ ] PCAP export
