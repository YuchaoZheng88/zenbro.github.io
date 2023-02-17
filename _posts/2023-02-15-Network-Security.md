---
title: Network Security 
author: Yuchao
date: 2023-02-15 11:33:00 +0800
categories: [sec]
tags: [network, linux]
math: true
mermaid: true
---

# Seed network security

---

### Basic

#### Basic Network Utilities
- Wireshark, ping, netcat, telnet, ssh, iptables, ip addr, ip route, dig

#### classful addressing
- A: 0.0.0.0      - 127.255.255.255,  0...        , /8
- B: 128.0.0.0  - 191.255.255.255,  10...      , /16
- C: 192.0.0.0  - 223.255.255.255,  110...    , /24
- D: 224.0.0.0  - 239.255.255.255,  1110...  , multicast
- E: 240.0.0.0  - 255.255.255.255,   1111..  , reserve
- remember: 128, 192, 224, 240, 256 always half of the left
- easy for routing, mask is default from IP address.

#### private IP
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
- only used internally, cannot be routed out to the Internet.

#### loopback IP
- virtual interface that receive packets that send out.

#### NAT
- network address translation.
- maybe more layers of NAT, like using VM.

---

### sniff & spoof

#### socket APIs
- system call, that application give data through to kernel.

#### send a packet
python
```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(data, {IP, PORT})
# listen: $ nc -luv 9090 ; l: listen u: udp v:verbol
```

c
```c
// https://man7.org/linux/man-pages/man7/ip.7.html
// https://man7.org/linux/man-pages/man2/socket.2.html
// https://linux.die.net/man/2/sendto

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>   // includes netinet/in.h

void main()
{
	char *data = "hello server. \n";

	// structure describing an IPv4 socket address. another one: sockaddr_in6
	// defined in netinet/in.h
	struct sockaddr_in dest_info; 
	memset((char *) &dest_info, 0, sizeof(dest_info));
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = inet_addr("10.0.2.5");
	dest_info.sin_port = htons(9090);  
	// htons, host to network by short type ,convert value between host and network byte order.

	// defined in sys/socket.h
	// int socket(int domain, int type, int protocol);
	// the last parameter can be filled with 0, as only UDP protocol can be used.
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	sendto(sock, data, strlen(data), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}
```


#### how packets received
- NIC: (check frame destination)
- Copy to ring buffer in kernel. (by DMA)
- NIC interrupts CPU.
- CPU copies packets from buffer into a queue. (buffer has more room)
- Callback handler invoked by kernel to process data from queue. (based on protocols)

#### Promiscuous  & Monitor 

#### BSD Packet Filter(BPF)

#### PCAP




---



# Linux Network Internals

## User-Space Tools
- iputils, ifconfig, route, netstat, and arp, but also ipmaddr, iptunnel, ether-wake, netplugd
- 
