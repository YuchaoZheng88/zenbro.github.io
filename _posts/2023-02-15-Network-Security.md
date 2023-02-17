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

#### send a packet, client
- OS will randomly pick a source port number for the code below.

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
	// a file descriptor will be returned.
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
	sendto(sock, data, strlen(data), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}
```

#### receive a packet, server

python

```python
import socket
IP = "0.0.0.0"
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP, PORT)) # computer may have multiple NIC, use IP specify one

while True:
	data, (ip, port) = sock.recvfrom(1024)
	print("Sender: {} and Port: {}".format(ip, port))
	print("Received message: {}".format(data))
```

c
- https://www.geeksforgeeks.org/socket-programming-cc/
- server.sin_addr.s_addr = htonl(INADDR_ANY);  // any interface
- bind(sock, (struct sockaddr *)&server, sizeof(server)) // return <0 means failure
- recvfrom(sock, buf, 1500-1, 0, (struct sockaddr *) &client, &clientlen);
- https://pubs.opengroup.org/onlinepubs/007904875/functions/recvfrom.html

#### how packets received
- 1. NIC: filter packet by frame destination (MAC addr)
- 2. NIC copy to computer RAM(ring buffer in kernel), by DMA (direct memory access). or old way to on-chip memory.
- 3. NIC interrupts(aka, informs) CPU. CPU needs to quickly take data out, because RAM or on-chip memory have limited space.
- 4. Link-level driver is triggered when CPU takes control. It will take data out to upper  layer.
- 4b. copy to raw socket. (dest IP not for me will not be dropped later.)
- 4c. can pass to BPF( low level packet filter), before protocol stack, to save computer resources.
- 5. Protocol stack. (first of it is IP layer, look IP addr again, if it is for me. If not, drop, unless router, to foward) 

#### packet sniffing
- Promiscuous mode  & Monitor mode. (Get data not for me on layer 2)
- raw socket. (Get data not for me on layer 3) header not stripped of through raw socket, normal socket will only get data.

```c
// https://man7.org/linux/man-pages/man7/packet.7.html
// https://man7.org/linux/man-pages/man2/setsockopt.2.html
int main(){
	int PACKET_LEN = 512;
	char buffer[PACKET_LEN];
	struct sockaddr saddr;
	struct packet_mreq mr; 
	
	// create raw socket
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	// turn on promiscuous mode	
	mr.mr_type = PACKET_MR_PROMISC;
	setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
	
	//capture packets
	while(1){
		int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t*)sizeof(saddr));
		if(data_size) printf("get packet");
	}
	close(sock);
	return 0;
}
```

#### BSD Packet Filter(BPF)
- low level filter.
- OS specific.

#### PCAP (to sniff)
- https://www.tcpdump.org/
- developed by tcpdump.
- split the sniffing part from tcpdump, to a library called libpcap. Can be used by other programs.
- linux: libpcap. Windows: WinPcap, Npcap.
- tools based on it: wireshark, tcpdump, scapy, nmap, snort, McAfee.
- how to use: 1. initial config. 2. set filter. 3. start sniffing.
- as above: 1. pcapt_t *pcap_open_live(...); 2. int pcap_compile(...); 3. int pcap_setfilter(...);
- build BPF from human-readable strings; open promiscuous mode.




---



# Linux Network Internals

## User-Space Tools
- iputils, ifconfig, route, netstat, and arp, but also ipmaddr, iptunnel, ether-wake, netplugd
- 
