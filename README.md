# NetScribe

NetScribe is a packet sniffer written in C using raw sockets.
It is currently in active development and focuses on packet sniffing (injection is coming soon).

## Installation & Build

### Prerequisites

- A Linux-based environment (required for raw sockets).

- gcc and make.

### Build Instructions

Clone the repository and compile the project

```bash
git clone https://github.com/Farhan291/NetScribe.git
cd netscribe
make build
```

## Usage

### Permissions

Since NetScribe uses raw sockets, it requires elevated privileges. Instead of running everything with sudo, it is recommended to grant the executable the specific capabilities it needs:

```bash
 sudo setcap cap_net_raw+ep ./netscribe
```

### Running sniffer

Run NetScribe in sniff mode.  
You can capture all traffic or apply specific protocol filters.

#### Sniff everything:

```bash
 ./netscribe sniff
```

#### Sniff only TCP packets:

```bash
 ./netscribe sniff -t
```

#### Sniff UDP, ICMP, and ARP packets:

```bash
$ ./netscribe sniff -u -i -a
```

Filter Flags:

- ` -t`: TCP

- ` -u`: UDP

- `-i`: ICMP/ICMPv6

- `-a`: ARP

### Status

⚠ In development

Sniffing is functional

Packet injection is work in progress

### TODO

- [ ] Packet injection (Ethernet / ARP / IP / TCP / UDP)
- [ ] Better filtering (ports, IPs)
- [ ] Logging to file
- [ ] Cleaner output formats
