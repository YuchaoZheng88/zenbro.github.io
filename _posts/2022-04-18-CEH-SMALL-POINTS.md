---
title: CEH small points
author: Yuchao
date: 2022-04-18 11:33:00 +0800
categories: [sec]
tags: [ceh]
math: true
mermaid: true
---


Insertion attack
- TTL field, some packets will end in IDS
- like tcp 3 packets [maliciou][xxx][s], IDS see maliciouxxxs, backend see malicious.
- PHF attack, “phf” in GET request.

Unicode invasion, aka Obfuscating
- bypass IDS, IDS cannot recognize, but web server can decode
- \u017F can be used as S 

Rogue router: Message authentication to prevent.

Regulation:
- HIPAA:  Health Insurance Portability and Accountability Act. modernize the flow of healthcare information.
- FISMA: The Federal Information Security Management Act of 2002. requires each federal agency
- ISO/IEC 27002
- COBIT: Control Objectives for Information and Related Technologies.
- NIST-800-53: defines security and privacy controls for all U.S. federal information systems except those related to national security
- PCI-DSS: Payment Card Industry Data Security Standard, handle branded credit cards from the major card schemes.
- EU Safe Harbor: prevent private organizations store customer data from accidentally disclosing or losing personal information.
- SOX: Public Company Accounting Reform and Investor Protection Act. aka Sarbanes–Oxley Act
- DMCA: Digital Millennium Copyright Act
- PII: personally identifiable information 

NIST Cybersecurity Framework`s functions: Identify, Protect, Detect, Respond, Recover

PCI Data Security Standards:
- Build and Maintain a Secure Network
- Protect Cardholder Data
- Maintain a Vulnerability Management Program
- Implement Strong Access Control Measures
- Regularly Monitor and Test Networks
- Maintain an Information Security Policy

MAC address: 6-byte/ 12-hex/ 48-bit.

MAC filtering

CRLF attack: Carriage Return (ASCII 13, \r) Line Feed (ASCII 10, \n)
- attackers can set fake cookies, steal CSRF tokens, disclose user information by injecting a script (XSS)
```
GET /%0d%0aSet-Cookie:CRLFInjection=PreritPathak HTTP/1.1
```

Rootkit: 
- was a collection of tools that enabled administrative access to a computer or network
- now provides root-level, privileged access while hiding
- Sensitive data stolen, Malware infection, File removal, Eavesdropping, Remote control

type of rootkit:
- User-mode or application rootkit.    easy to detect
- Kernel-mode Rootkit.     difficult to detect,  change the code of the core components of the operating system
- Bootkits.       infecting its master boot record (MBR)
- Firmware rootkits.       routers, network cards, hard drives or system BIOS
- hypervisor Rootkit.    installed between the hardware and the kernel, intercept hardware calls made by the original operating system.

Hosts:
- /etc/hosts OR c:\Windows\System32\Drivers\etc\hosts:
- Block a website: in host file to 0.0.0.0 (better) or 127.0.0.1 (waste tiny resources)
- Test, Shortcuts, Improve speed (than DNS query)...

c:/boot.ini:
- NT-based operating system prior to Windows Vista

etc/networks:
- like hosts, but for network.

Non-repudiation: cannot deny the validity of something.

Man-in-the-Middle Attack
Replay attack

Traffic analysis attack: passive & active 

Payment Card Industry Data Security Standard
- Perform external penetration testing at least annually 
- and after any significant infrastructure or application upgrade or modification (operating system upgrade, a sub-network added, a web server added)

Kon-Boot:  allows users to bypass Microsoft Windows and Apple macOS passwords.

Cain & Abel: 
- password recovery tool for Microsoft Windows. 
- forge certificates for authentication.
- create certificates that are not officially signed by a CA

PAP: Password Authentication Protocol.  a weak authentication protocol. not encrypt any data.

Markov Chains attack: assemble a certain password database

Toggle-Case:  creates every possible case combination

PKI protect email at Presentaion layer.

Quantum cryptography:  encrypted by a sequence of photons that have a spinning trait.
QKD: quantum key distribution
Quantum coin flipping
Einstein-Podolsky-Rosen (EPR) paradox

Firewall:
- Application firewall: Internet Relay Chat (IRC) is an application layer protocol. Find SQLi, XXS. layer 7
- Network-based application firewalls:  can understand FTP, DNS, HTTP. check for malware.
- Host-based application firewalls:  monitors application system calls or other general system communication.
- multi-homed firewall: a node with multiple NICs that connects to two or more networks.
- statefull firewall: layer 4
- Access control list: layer 3 or 4.

testing:
- Fuzzing testing: Black Box
- Concolic testing:  treats program variables as symbolic
- Monkey testing: fuzz to crash
- Security testing:  intended to reveal flaws in the security mechanisms of an information system that protect data and maintain functionality as intended.

Nmap: 
- -F (Fast (limited port) scan)
- -T paranoid|sneaky|polite|normal|aggressive|insane (0|1|2|3|4|5), -T5 very fast.
- -sA ACK scan. map out firewall rulesets. For unfiltered systems, open and closed ports will both return a RST packet.
- -sS scan by stealth
- -sU scan for UDP. DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68)
- -sT scan with TCP connect. 
- -sP scan by PING.
- -O OS scan need root privileges.
- use enip-info script. ``` nmap --script enip-info -sU -p 44818 <host> ```find Device Type, Vendor ID, Product name, Serial Number, Product code, Revision Number, status, state, as well as the Device IP.
- http-methods script. detect HTTP methods.
- http-enum script. Enumerates directories used by popular web applications and servers.
- HTTP ETag. aka entity tag, allows a client to make conditional requests
- -sY: SCTP INIT scan. SCTP is a relatively new alternative to the TCP and UDP protocols
- -R: reverse DNS resolution on the target IP addresses
- -r: randomizes the port scan order
- -D decoy, hide your IP in decoy IPs.
- -f fragment packets, split up the TCP header over several packets, 
- -S IP_Address (Spoof source address).
- -PN dont ping
- -PU UDP ping
- -PP ICMP timestamp ping
- -PY SCTP init ping
- -sn disable the port scan

ICMP type code:
- 0 echo reply (response)
- 3 Destination unreachable
- 4 Source quench (deprecated)
- 5 Redirect
- 8 echo (request)

Nikto: scanner for web servers for dangerous files/CGIs, outdated server software.

netsparker: security scanner

Layer 4 vs layer 5:
- Transport layer: establishes a connection between two machines, transmitting segments. TCP.
- Session layer: create, maintain, terminate connections between two processes. PPTP. RPC. Password Authentication.
- An application can run many processes simultaneously to accomplish the work of the application.

port: 16-bit, 4-hex, 2-byte

IPv6: 128 bits. 32-hex, 16-byte. (4-times of v4). No broadcast, instead of multicast

IPv4: 32 bits. 8-hex, 4-byte.

SQL injection:
- Compromised data integrity.
- Unauthorized access to an application.
- Information disclosure.
- Loss of data availability.

ACK scanning: 
- whether the port is filtered or unfiltered.
- if firewall stateful(no response or  ICMP destination unreachable) 
- if stateless(RST, no matter open or closed).

TCP Connect/Full Open Scan:
- full 3-way hand shake.  most reliable

Inverse TCP flag scanning: 
- include: FIN, XMAS, NULL, URG, PSH
- open: no response. close: RST and ACK bits set.

Xmas Scan:
- sX
- PSH, URG, FIN.
- Each operating system or network device responds different  to Xmas packets 
- revealing local information such as OS (Operating System), port state and more.
- open: no response. close: RST.

Null Scan:
- sN
- no flag.

FIN scan (-sF): if open, no response(no previous connection).

The Maimon scan:  sM, FIN/ACK
- open: no response. close: RST.

Half-open scan: aka  SYN scan. it’s a fast and sneaky. if closed, RST is back. if open, SYN/ACK is back.
- concern: a lot of half open connections.

Scan:
- Banner Grabbing: protocol HTTP, FTP, SMTP; tools Telnet, nmap, Netcat. See response banner information about service.
- IPID scan: aka IDLESSDP Scanning scan.
- SSDP Scanning: Simple Service Discovery Protocol, text-based protocol based on HTTPU

XSS, aka HTML Injection
XSS Reflection: XSS in URL.

Vulnerability scanning 3 steps:
- 1. Locating nodes.
- 2. Service and OS discovery on them.
- 3. Testing services and OS vulnerabilities.

Wrapping attacks: 
- A Simple Object Access Protocol (SOAP) message is encoded as an XML document.
- valid signature ONLY covers the unmodified element while the faked one is processed.

SOAP:  
- extensibility 
- neutrality. (over HTTP, SMTP, TCP, UDP)
- independence (any programming model)

WS-Address spoofing:
- provides additional routing information in the SOAP header
- allowing asynchronous communication
- a subtype:  BPEL Rollback. requires the existence of BPEL engine

WS-Security: an extension to SOAP to apply security to Web services.

WS-Policy: allows web services to use XML to advertise their policies.

WSDL: Web Services Description Language

SOAPAction spoofing: 
- an additional HTTP header element called SOAPAction
-  the operation to be executed solely on the information contained in the SOAPAction attribute

XML Flooding: send a large number of legitimate SOAP Messages

Soap Array Attack:  cause a denial of service attack to limit the web service availability.  lead to memory exhaustion. declares an array with 1,000,000,000 String elements.



SQLi:
- DMS-specific SQLi / out-of-band OOB SQLi.  DNS or HTTP query to the SQL server with SQL statement. create DNS or HTTP requests to transfer data to an attacker
- Classic SQLi. Error based, or UNION based.
- Compound SQLi. SQLi with XSS, DoS, DNS hijacking.
- Blind SQLi. based on True/False questions.
- Union-based SQLi

CSRF: 
- aka. one-click attack, or session riding
- Unlike cross-site scripting (XSS), which exploits the trust a user has for a particular site, CSRF exploits the trust that a site has in a user's browser.

Manipulating Hidden Fields:  the server's trust of client-side processing by modifying data on the client-side.

Protocol		Published		Status
- SSL 1.0		Unpublished	Unpublished
- SSL 2.0		1995				Deprecated in 2011 (RFC 6176)
- SSL 3.0		1996				Deprecated in 2015 (RFC 7568)
- TLS 1.0		1999				Deprecated in 2020 (RFC 8996)[8][9][10]
- TLS 1.1		2006				Deprecated in 2020 (RFC 8996)[8][9][10]
- TLS 1.2		2008	
- TLS 1.3		2018

Heartbleed:
- a security bug in the OpenSSL cryptography library.
- classified as a buffer over-read, transmit server`s memory(RAM) to attacker.
- lack of bounds checking
- CVE-2014-0160

SSL/TLS Renegotiation Vulnerability:  DoS, or MITM into HTTPS sessions.

POODLE attack:  "Padding Oracle On Downgraded Legacy Encryption", fallback to SSL 3.0.

Snort: Sniffer Mode / Packet Logger Mode / Network Intrusion Detection System Mode

tcpdump: Wireshark for CLI
tcpslice: a tool for extracting portions of packet trace files generated using tcpdump's -w flag.
- -w: Write the raw packets to file rather than parsing and printing them out.

tcptrace:  TCP connection analysis tool, through dump files

protocol analyzer: a tool used to monitor data traffic and analyze captured signals. 

arp cache poisoning: aka arp apoofing. MitM, attacker must access the network.
- check two different IP addresses that share the same MAC address.

ARP on network layer. 

BetterCap: tool for MitM.

ARP cache: a table of IP to MAC. 

Dynamic ARP inspection (DAI): 
- check if ARP packet match a valid entry in the DHCP snooping database, if not, drop the packet.
Port security: lock port(s) to certain MAC addresses.
- Dynamic locking / Static locking
DHCP relay:
-  DHCP option 82, also known as the DHCP relay agent information option, to help protect supported Juniper devices against spoofing (forging) of IP addresses and MAC addresses, and DHCP IP address starvation.
Spanning tree:
- prevent bridge loops.
- layer 2

DHCP Starvation attack:  ton of bogus DISCOVER packets. Typically next, bring attacker`s rogue DHCP server.



Static application security testing (SAST) white-box
dynamic application security testing (DAST) black-box
Mobile Application Security Testing (MAST) 
Interactive Application Security Testing (IAST)

Metasploit module
- Auxiliary module: scanners, fuzzier, and SQL injection tools
- Exploit Module: code within the database runs on a victim computer.
- Payload Module: payload is generally attached to the exploit before its execution.
- NOPS Module:  x86 chips as 0x90.
- getsystem:  Metasploit post-exploitation module to escalate privileges.

msfvenom should be used in place of msfpayload+msfencode: msfencode bypass antivirus

IDS/IPS:
- WIPS: Wireless Intrusion Prevention System
- HIDS: host-based intrusion detection system. one of the last layers of defense and reside on computer endpoints. signature-based
detection method
- NIDS: Network-based intrusion detection system.  at the physical and network layers after it has passed through a firewall. Only packet level analysis, can be bypass by encryption.
- AIDS: Anomaly-based intrusion detection system. often with artificial intelligence type techniques.  a high false-positive rate 
- SIDS: signature-based IDS

Snort rule:
- ``` alert tcp any 21 -> 10.199.12.8 any (msg:"FTP Packet "; sid:1000010)
- Rule Header, Rule Option
- action protocol LIP LPort direction RIP RPort, Rule Option

Intranet machine to visit Internet:
- Mediation servers like IRC, Usenet, SMTP and Proxy server
- Network address translation (NAT)
- Tunneling protocol

Proxy server: sit in middle between an external network and the private network.
- Routers and switches don’t sit in the middle, merely passing traffic along based on source and destination addresses.

router: seperate Broadcast domains

Sybil attack: creating a large number of pseudonymous identities. attack distributed hash table (DHT) system.
Exploit Kits: simply a collection of exploits.

Cloudborne attack: infrastructure-as-a-service (IaaS) attack.  implant backdoor in the firmware

SaaS, PaaS, IaaS

Staas - Storage as a Service



cloud carrier/ auditor/ broker/ consumer

Cloud deployment models:
- Public cloud.            on a subscription basis
- Private cloud.          used by a single organization
- Hybrid cloud.           private and public 
- Community cloud     restricted to the members of the community

Virus
- multipartite virus: attack both the boot sector and executable files.
- stealth virus: change the read system call, when the user asks to read a code modified by a virus, the original form of code is shown rather than infected code. types:  boot virus,  file virus, Macroviruses. ex:  Virus.DOS.Stealth.551, Exploit.Macro.Stealth, Exploit.MSWord.Stealth, Brain, Fish.
- tunneling virus: bypass scanner. installing itself in the interrupt handler chain. or in device drivers
- A polymorphic virus: generates numerous mutated versions of itself.
- Macro virus: documents, spreadsheets, and other data files
- Cavity virus: aka Spacefiller, overwriting unused areas of executable files.
- Encryption virus, aka Ransomware


Google search:
- [site:] [inurl:] [link:] [cache:]
- [related:] Lists web pages that are similar to a specified web page.
- Put minus (-) in front of any term (including operators) to exclude that term from the results

Social engineering:
- quid pro quo attack. (aka “something for something” attack)
- Reverse Social Engineering. (victim find the attacker)
- Tailgating. aka piggybacking.  follows an authorized individual into a secured premise.
- Elicitation. the subtle extraction of information during an apparently normal and innocent conversation.
- Pretexting. use fake identities to manipulate the receipt of information.
- Honey trap. pretends to be an attractive person and fakes an online relationship
- Diversion theft.  persuading victims to send it to the wrong recipient
- Baiting.  offer playing on fear, greed, and temptation
- impersonation attack. 
- Session Donation. 

Boot Sector Virus:
- Move the MBR(Master Boot Record) to another location on hard disk.
- copy it self to the original location of the MBR.

Low-bandwidth attacks: nmap`s slow scan.

Session Splicing:  split the attack traffic into many packets such that no single packet triggers the IDS.
- tools: Nessus,  'Nikto', 'whisker' and 'Sandcat'

Desynchronization Attack: RFID(Radio-frequency identification ) related threat.


- Metasploit: important sub-projects include the Opcode Database, shellcode archive and related research.
- Analyst's Notebook:  software product from IBM for data analysis and investigation.
- Palantir: Palantir Technologies is a public American software company that specializes in big data analytics. 

802.1x protocol: 
- defines an access control and authentication protocol
- IEEE standard for port-based authentication
- client authentication in wireless networks, security access

Dragonblood: WPA3 vulnerabilities.

Key reinstallation attack: KRACK, a severe replay attack on WPA2.

KRACK attack: Key Reinstallation Attack, a replay attack. 

WEP: Wired Equivalent Privacy,  mimic the privacy characteristics of a wired LAN,  
- insecure RC4 cipher
- Initialization Vector (IV) is Too Small

RC4: symmetric stream cipher. 

RC5, RC6: symmetric-key block cipher.

RADIUS: 
- Remote Authentication Dial-In User Service,  
- a networking protocol that 
- provides centralized authentication, authorization, and accounting (AAA) management for users

digital signature: unforgeable, authentic

multi-factor authentication scheme:
- Something you have
- Something you know
- Something you are
- Somewhere you are

counter-based authentication: both the token and the authenticating server maintain a counter, whose value besides a shared secret key is used to generate the one-time password.

Footprinting: passive collection of information without touching the target system/network/computer.
Scanning: active collection of information.
Enumeration: active, gather more information.

DOS:
- Slowloris: tries to keep many connections to the target web server open and hold them open as long as possible. most likely successful
- HTTP GET/POST (HTTP Flood): 
- Spoofed Session Flood.  contains multiple SYN and multiple ACK packets along with one or more RST or FIN
- IP fragmentation scan/attack. Fragmentation is associated with IP; whereas Segmentation is associated with TCP. 
- Phlashing. exploits a vulnerability in network-based firmware updates, permanent.
- Teardrop attack.  attempts to make a computer resource unavailable by flooding a network or server with requests and data
- APDoS. advanced persistent DoS.  persist for weeks
- Smurf. distributed denial-of-service. ICMP. 
- Fraggle attack. distributed denial-of-service. UDP. 
- bonk attack: sends fragmented UDP packets to a Windows system, may cause the system to crash, DoS
- Yo-yo. aimed at cloud-hosted. attack until a cloud-hosted service scales outwards. when scales back down, the attack resumes,
- XOIC. a ddos tool.

SQLi Tautology: OR '1' = '1'; --

Bluedriving: wardriving utility. check same devices on map.

Bluetooth attack:
- Bluejacking:  transmits data to the target device.
- Bluesmacking: specially crafted packet can make a device unusable(DoS).
- Bluesnarfing:  theft of information from the target device.
- Bluebugging: Similar to bluesnarfing, 10–15 meters.

Jailbreaking exploits: 
- 1. Userland Exploit: It allows user-level access but does not allow iboot-level access.
- 2. iBoot Exploit: An iBoot jailbreak allows user-level and iboot-level access.
- 3. Bootrom Exploit: It allows user-level access and iboot-level access.

Jailbreaking types: Tethered, Semi-Tethered and Untethered.
- Untethered Jailbreak: patches the kernel during the device boot to keep jailbroken after each reboot
- Semi-untethered Jailbreak: like semi-tethered, but without using a computer.
- Tethered Jailbreak:  computer running the jailbreaking software, or the iOS device will not be able to boot at all.  
- Semi-tethered Jailbreak: can reboot, but will have an unpatched kernel.

patch management: Making determinations about patch disposition for business systems.

aLTEr attack: a fake eNodeB (the 4G cell tower), Man-in-The-Middle (MiTM)
- <https://alter-attack.net/media/breaking_lte_on_layer_two.pdf>

Ettercap: a comprehensive suite for man in the middle attacks.

Jamming signal attack. 

Attack model:
1. Ciphertext-only attack (COA): access only to a set of ciphertexts, can guess standard protocol data.
2. Known-plaintext attack:  access to at least a limited number of pairs of plaintext and the corresponding enciphered text.
3. Chosen-plaintext attack: able to choose a number of plaintexts to be enciphered and have access to the resulting ciphertext. 
- Adaptive chosen-plaintext attack:  choose step by step
4. Chosen-ciphertext attack (CCA): can choose arbitrary ciphertext and have access to plaintext decrypted from it.
5. Open key model attacks:  some knowledge about the key for the cipher being attacked.

Rubber-hose attack: the cryptanalyst uses blackmail, threats, torture, extortion, bribery, etc.

File system permissions vulnerability:
- Processes may automatically execute specific binaries as part of their functionality or to perform other actions.

Firewalking: utilizes traceroute techniques and TTL values to analyze IP packet responses in order to determine gateway ACL (Access Control List) filters and map networks. 

Windows system tools:
- ```gpedit.msc ```  Group Policy Editor
- ```ncpa.cpl. ncpa ```  Network Control Panel Applet, cpl = Control Panel
- ``` services.msc ``` Opens Windows Services Manager.
- ``` compmgmt.msc ``` Computer Management Console

Honey pot types:
- Pure honeypots.  full-fledged production systems.
- Low-interaction Honeypots.  will not be able to interact with your decoy system in any depth.
- High interaction honeypots.  emulates certain protocols or services.
- Research honeypots. gather information about the black hat community. not to a specific organization.

fingerprinting: Matching OS characteristics from a scan to a database in Nmap.

find honey pots:
- Honeyd Honeypot: perform time-based TCP fingerprinting methods
- User-Mode Linux (UML) Honeypot: analyze /proc/mounts, /proc/interrupts, and /proc/cmdline, which contain UML-specific information.
- Sebek-based Honeypots: analyzing the congestion in the network layer 
- Snort_inline Honeypot: analyzing the outgoing packets

Website defacement vulnerability: commonly carried out by hacktivists.

Risk Mitigation:
- accept. Risk Acceptance
- avoid. Risk Avoidance. most expensive of all risk mitigation options
- reduce. Risk Limitation. most common
- transfer. Risk Transference

Risk = Threat Probability * Vulnerability Impact

Full disk encryption:
- BitLocker Drive Encryption leaves an unencrypted volume to boot from, while the volume containing the operating system is fully encrypted.

recovery:
- AV (Asset value) 
- SLE (Single Loss Expectancy)
- ARO (Annual rate of occurrence)
- ALE (Annual Loss Expectancy)

IPSec:
- IPSec: Key exchange, Packet headers and trailers, Authentication, Encryption, Transmission, Decryption. On layer 3 (Network).
- IPsec driver.  performs protocol-level functions required to encrypt and decrypt packets
- IKE: Internet Key Exchange, used to set up a security association (SA), exchange secret keys
- AH (Authentication Header) protocol. integrity / ESP (Encapsulating Security Payload) protocol. integrity AND confidentiality
- tunnel mode (gateway-to-gateway) / transport mode (host to host)
- AH tunnel/ AH trasport/ ESP tunnel/ ESP transport

Remote access policy:  using of a VPN  for gaining access to an internal corporate network

IPsec suite protocols: 
- Authentication Header (AH), 
- Encapsulating Security Protocol (ESP), 
- Security Association (SA), one of the most common is Internet Key Exchange (IKE)

some attacks:
- Clickjacking: invisible page or HTML element.
- Session Fixation: attacker can send a link containing a fixed session-id. Unlike.
- Session Hijacking: rely on stealing the Session ID. (cookie hijacking)
- HTML Injection:  sends HTML code through any vulnerable field.  quite similar to the XSS attack
- HTTP Parameter Pollution: passing of multiple parameters having the same name, application may interpret values in unanticipated ways.

Network or TCP Session Hijacking: 
TCP communication with incrementing sequence number.  create a state where the client and server are unable to exchange data; enabling him/her to forge acceptable packets for both ends, which mimic the real packets. Thus, the attacker is able to gain control of the session. below some types: 
- IP Spoofing
- Man in the middle Attack (TCP Hijacking). Initial sequence numbers (ISN) 
- Blind Hijacking. (source routing is disabled)
- UDP session Hijacking
- <https://www.greycampus.com/opencampus/ethical-hacking/network-or-tcp-session-hijacking?sscid=c1k4_w62kp>

Registration hijacking:  attacker replaces the legitimate registration with a false one.

DMZ Network: extra layer of security

on application layer protocol:
- SFTP: FTP over SSH (Secure Shell),  port 22,
- FTPS: FTP-SSL. (adds support for the Transport Layer Security (TLS), SSL is now prohibited)
- SSL:  Secure Sockets Layer

access-list example:
- FTP uses port 21 for control, 20 for data transfer. 
- TCP traffic destined to port 21 and port 20 is denied and everything else is explicitly permitted. 
```
access-list 102 deny tcp any any eq ftp
access-list 102 deny tcp any any eq ftp-data
access-list 102 permit ip any any
```

FTP vs HTTP: FTP file transfer, HTTP website access. Both on application layer.

protocol:
- PPP: Point-to-Point Protocol, layer-2, between two routers directly without any host
- PEM: Privacy-Enhanced Mail, 
- SET: Secure Electronic Transaction, security protocols and formats that enabled users to employ the existing credit card payment infrastructure.

Fileless malware: operates in memory,  low-observable characteristics (LOC), 
Adware: aka advertisement-supported software, 

Malware detection:
- Cloud-based detection: providing data to the cloud engine for processing.
- Behavioral-based detection:  observes how the program executes
- Heuristics-based detection: might look for rare instructions or junk code; without an exact signature match.
- Real-time protection

Hit-list scanning: a list of vulnerable hosts can be composed in advance and sent along with the worm

worm: does not need a host or human interaction to disrupt and corrupt data

IDOR: (Insecure direct object references )
- ``` https://insecure-website.com/customer_account?customer_number=132355 ```

LoT layers:
1. Sensor-connected LOT
2. LOT gateway. connected to the internet
3. Cloud. 
4. IOT Analytics. raw data is converted into actionable business insights

FCC ID search: gather information about LoT devices.

LoTSeeker: scan the target network for IoT devices and detect default, factory-set credentials.

Censys: automated monitoring LoT.

Shodan: world’s first search engine for Internet-connected devices.

Bullguard IoT: find if your device is on Shodan.

Power/Clock/Reset Glitching: one type of fault injection attack to IoT device

achieve chip-level security of an IoT device: encypting the JTAG interface.

Prevent sniff attacks: use encryption protocols ("best option")

Sniffing:
- active. Sniffing the switch.  bogus MAC address. layer 2
- passive.  sniffing the hub. layer 1

Unspecified Proxy Activities: configured multiple domains pointing to the same host to switch quickly between the domains and avoid detection

CAM table: 
- aka content-addressable memory table
- contains a list of MAC addresses that are associated with a port on a layer 2 switching device

CAM Overflow: context-addressable memory (CAM) table. no more new MAC addresses can be learned. turn switch into a hub.

VLAN hopping attack: 2 methods  switch spoofing and double tagging

email:
- spoofing.  fabrication of an email header, make the recipient think the email originated from someone else.
- harvesting. (or scraping ). obtaining lists of email addresses using various methods. open-source tool: theHarvester.
- masquerading.  broader concept than spoofing, more than just header.
- phishing.  malicious link to many people. spear phishing to specific people.

Evilginx:
- phishing tool.
- a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. 

whaling: phishing, masquerade as a senior one, CEO fraud

Smishing: mobile phones phishing. aka SIM swap scam, SIM splitting, simjacking, SIM swapping

Vishing: voice phishing

Clone phishing: create an almost identical or cloned email, only attachment changed.

Infoga: a tool gathering email accounts information (IP, hostname, country,...) from a different public source

docker:  platform as a service (PaaS) products

docker config network

1. docker macvlan network:  
- assign a MAC address to each container’s virtual network interface
- appear to be a physical network interface directly connected to the physical network
- NIC need “promiscuous mode”

2. docker Bridge networking
- containers on same bridge network to communicate, on different can not.

3. docker Host networking
- container’s network stack is not isolated from the Docker host
- container bind to host`s port
- use when handle a large range of ports, as it does not require network address translation (NAT)

4. docker Overlay networking
- creates a distributed network among multiple Docker daemon hosts

Residual risk = (Inherent risk) – (impact of risk controls)
- the amount of risk left over after natural or inherent risks have been reduced by risk controls.

WHOIS:  protocol that used for querying databases that store the registered users or assignees of an Internet resource

Internet Assigned Numbers Authority:  a standards organization, oversee global IP allocation /autonomous system /DNS...

CAPTCHA:  "Completely Automated Public Turing test to tell Computers and Humans Apart"

Internet Engineering Task Force: IETF,  standards that comprise the Internet protocol suite (TCP/IP)

Wireless networks two types:
- ad hoc.  peer to peer. (mesh topology)
- infrastructure.  an access point that all devices connect to (star topology)

Wireless Network:
- The SSID (service set identifier): make your network visible and easily accessible.
- Invisible wifi: disable SSID, connect by configure their settings manually by including the network name, security mode, and other relevant info.
-  NetStumbler or Kismet can easily locate hidden networks.

- 802.11a: 5 GHz bands, 54 Mbit/s
- 802.11n: 2.4 GHz / 5 GHz bands, 54 Mbit/s to 600 Mbit/s,
- 802.11g: 2.4 GHz band, 54 Mbit/s, 
- 802.11i:  specifies security mechanisms for wireless networks
- 802.16: 1-6 miles.

On a wireless network, proper credentials: SSID and password
- SSID    Name of a Network
- BSSID  basic service set identifier 
- ESSID  Extended Service Set Identification

WPA: Wi-Fi Protected Access

WPA2: 
- use 4 way handshake to protect against replay attacks.
- use CCMP as authentication protocol

WPA3-Enterprise: 192-bit cryptographic strength, cryptographic tools to protect sensitive data.

- Aircrack-ng: detector, packet sniffer, WEP and WPA/WPA2-PSK cracker and analysis tool for 802.11 wireless LANs

Zig-Bee: short-range wireless.

wifi:
- Kismet: network detector, packet sniffer, and intrusion detection system for 802.11 wireless LANs. 
- Wireshark with Airpcap: analyzing packets on your wireless network
- Wi-Fi Pineapple:  a wireless auditing platform

Wardriving:  physically searching for wireless networks

packet sniffers:
- tshark (can specify the individual fields you want printed in the output)
- tcpdump (can not specity individual fields)
- Snoop (can not specity individual fields)

some ports:
- FTP: tcp/21(command), tcp/20(data).
- SSH: tcp/22
- Telnet: tcp/23
- SMTP: tcp/25.
- DNS: udp/port 53.
- POP3: tcp/110.
- NTP: udp/port 123 (Network Time Protocol)
- CHARGEN: udp,tcp/19 (Character Generator Protocol)
- XDMCP: udp,tcp/177 (X Display Manager Control Protocol )
- SNMP: udp,tcp/161 (Simple Network Management Protocol) (version3 has encryption)
- Server Message Block (SMB): tcp/139 (on NetBIOS) or tcp/445(after windows 2000)
- LDAP : tcp/389. (Lightweight Directory Access Protocol)
- LDAPS: tcp/636. 
- kiwi syslog:  tcp/514.
- printer: tcp/515.
- BGP: tcp/179 (Border Gateway Protocol)
- IMAP: tcp/143, Internet Message Access Protocol
- Service Location Protocol (SLP)

SNMP:
- application layer, use UDP protocol
- protocol data units (PDUs)
- TRAP. An asynchronous alert sent by the agent to the SNMP manager

NetBIOS:
- Network Basic Input Output System
- Enumeration: list computers, shared resources
- nbtstat: gather NetBIOS configurations information on Windows

JXplorers: query remote LDAP servers, to gather information

LDAP:  implementation of X.500. X.509

LDAP Enumeration Countermeasures:
- use SSL or STARTTLS
- enable account lockout
- Restrict access to Active Directory by using software such as Citrix.
- Use NTLM.  Windows New Technology LAN Manager.  security protocols by Microsoft to authenticate users' identity

X.509: 
- standard describes what and how certificates are created. 
- public key cryptography.
- is the specification for a certificate
- organizational unit(OU) is a field in a certificate specified in X.509

AOL Search <https://search.aol.com/>: same as google, baidu, duckduckgo.
zabasearch: Find people, addresses & phone numbers.
ike-scan: Discover and fingerprint IKE hosts (IPsec VPN Servers)

Cloud Hopper: APT10

Cloud Hopper attacker:  used MSP's as intermediaries to acquire assets

An advanced persistent threat (APT)

APT lifecycle: ( requires more resources than a standard web application attack)
- 1. Define target
- 2. Find and organize accomplices
- 3. Build or acquire tools
- 4. Research target
- 5. Test for detection
- 6. Deployment
- 7. Initial intrusion
- 8. Outbound connection initiated
- 9. Expand access and obtain credentials
- 10. Strengthen foothold
- 11. Exfiltrate data
- 12. Cover tracks and remain undetected

Cyber Kill Chain 7 steps:
- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation (installs an access point)
- Command and Control
- Actions on Objective ( ransom, data exfiltration, data destruction)

robots.txt:  
- a text file webmasters create to instruct web robots (typically search engine robots) how to crawl pages on their website
- sitemap.xml, for large websites.

DNS spoofing:
- 1. send DNS queries to the DNS resolver
- 2. overloads the DNS with poisoned responses
- 3. wait legitimate user to query DNS

DNS cache snooping:
- if the DNS server has a specific DNS record cached
- deduce if the DNS server's user have recently visited a specific site.

vulnerability assessment solutions:
- Product-based solutions. in internal network, drawback is no outside view.
- Service-based solutions. mimics the perspective of a hacker

vulnerability assessment tools employ:
- Tree-based assessment. 
- Inference-based assessment.  begin with scan all machines and ports.

risk assessment`s four components:
- 1. Technical Safeguards.               vulnerability scan
- 2. Organizational safeguards         “minimum necessity rule.”
- 3. Physical safeguards                  physical protection of information
- 4. Administrative safeguards         information from a legal perspective

risk assessment methods:
- Business impact analysis (BIA)  study how various types of negative events (violations, failures or destructions) can affect

SMTP commands:
- VRFY. verify a user ID
- HELO – The client "signs on" to the server using the HELO command
- MAIL FROM – The client must tell the server who the mail is from
- RCPT TO – Who the mail is going to
- DATA – Ready for the actual message input
- QUIT – If no errors, the message would have been sent, close the connection
- NOOP –  testing to avoid timeouts
- EXPN – verify the existence of one or more mailboxes
- StartTLS - use TLS or SSL 
- VRFY, EXPN used to find valid users, email boxes by hackers.

open mail relay:  an SMTP server that is configured to allow anyone on the Internet to send email through it

Message transfer agent: aka mail transfer agent, mail relay. Messages exchanged between mail servers.

TPM:  hardware on a motherboard, Trusted Platform Module, generate encryption keys and keep a part of the key inside the TPM rather than all on the disk.

DROWN attack: 
- Decrypting RSA with Obsolete and Weakened eNcryption.
- affect all types of servers that offer services encrypted with SSLv3/TLS yet still support SSLv2
- cve-2016-0800

Padding oracle attack:
- "padding oracle" who freely responds to queries about whether a message is correctly padded or not.

DUHK attack:
- allows attackers to recover secret encryption keys used to secure VPN connections and web browsing sessions.

Pharming: misdirecting users to fraudulent websites, by host or DNS. (Phishing: with bad URL)

Skimming: capture and steal cardholder’s personal payment information.

Pretexting:  social engineering, make story and convince victim to give information.

php.ini: in  'cgi-bin' directory, attackers can find: database logins and passwords and verbose error messages

CVSS Score: (4,7,9)
- None, 0.0
- Low, 0.1 - 3.9
- Medium, 4.0 - 6.9
- High, 7.0 - 8.9
- Critical, 9.0 - 10.0

Cryptojacking Attacks:  hijack a target’s devices to stealthily mine cryptocurrency without the user’s awareness.

STP attack: The Spanning Tree Protocol(STP), the lowest bridge priority means the root bridge. spoof the root bridge in the topology, force an STP recalculation (redirect to his computer).
- victimA---victimB---attacker  -> Va-attacker-Vb

.bashrc:  a script file that's executed when a user logs in
.bash_history: stores a history of user commands 
.profile: run before user login.

hping:
- ``` hping3 -1 {targetIP} ``` ICMP scan
- allows you to create packets effectively from scratch
- set specific individual fields

Bluto: 
- Python-based tool for 
- DNS recon, DNS zone transfer testing, DNS wild card checks, DNS brute-forcing, e-mail enumeration and more.

DNS:
- ``` host -t a google.com ```
- ``` nslookup -recursive www_dot_google.com ```
- A Address record
- AAAA 	IPv6 address record
- CNAME Canonical name record
- NS Name server record
- SOA Start of [a zone of] authority record
- AXFR Authoritative Zone Transfer

IPv6 (and IPSec) allows for header authentication, IPv4 does not.

split-horizon DNS: aka  split-view DNS, split-brain DNS, or split DNS.
-  first DNS server on the internal network and second DNS in DMZ

DNSSEC: 
- cache poisoning prevention tool.
- provide to DNS clients (resolvers) origin authentication, authenticated denial of existence and data integrity
- but not availability or confidentiality

DynDNS: Dynamic DNS, automatically updating a name server

EDNS: Extension Mechanisms for DNS,  expanding the size of several parameters of DNS.

AndroidManifest.xml: basic configuration in an Android application

DroidSheep: Android application, allow intercept unprotected web-browser sessions using WiFi.

Agent Smith attack: a modular malware that exploits Android vulnerabilities to replace legitimate existing apps with a malicious imitation.

Androrat: Android and RAT. 

DroidDream: malware, Trojan, gain root access to Android

Orbot: Tor on Android

Meet-in-the-middle attack: 
- space–time tradeoff cryptographic attack
- the primary reason why Double DES is not used 
- why a Triple DES key (168-bit) can be bruteforced by an attacker with 256 space and 2112 operations.

Triple DES: 64-bit block size that is encrypted three times with 56-bit keys

DES: Data Encryption Standard (DES). fixed block size of 64 bits, and a key size of 56 bits

IDEA: International Data Encryption Algorithm, a symmetric-key block cipher, used in PGP v2.0
- 64-bit blocks using a 128-bit key and consists of a series of 8 identical transformations

RSA: uses 1,024- and 2,048-bit key strengths as asymmetric encryption algorithms

DSA: Digital Signature Algorithm. compares two hash values in order to provide non-repudiation.

AES: The Advanced Encryption Standard (AES).  fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. symmetric.
- selected by NIST as the principal method for providing confidentiality after the DES algorithm
- Rijdael: algorithm name selected.

HMAC: Hash-based message authentication,  verify both the integrity and authenticity of a message

Twofish: a symmetric key block cipher, block size of 128 bits, keys up to 256 bits.

Blowfish: a symmetric-key block cipher

SHA-1: 20-byte/ 40-hex / 160-bit, algorithm same to MD2, MD4, MD5

SHA-256: 

MD5: 128-bit hash value

RC5: symmetric-key block cipher.  The Advanced Encryption Standard (AES) candidate RC6 was based on RC5.

Serpent: symmetric key block cipher,  block size of 128 bits,  finalist in the Advanced Encryption Standard (AES)

CAST-128: 64-bit block size,  key size between 40 and 128 bits, 

RC-4:  stream cipher

PGP, SSL, IKE:  public-key cryptography

PGP: Pretty Good Privacy, Phil Zimmerman create.

A web of trust: a concept used in PGP, GnuPG, and other OpenPGP-compatible systems to establish the authenticity of the binding between a public key and its owner. 

GPG: GNU Privacy Guard, free version of PGP ,encrypt and sign your data and communications, hybrid-encryption

PKI:  certification authority (CA)  issues digital certificates

CR (Certification Request):  the process of obtaining a certificate.

VA (Validation authority): verify the validity of a digital certificate.

KDC (key distribution center):  reduce the risks inherent in exchanging keys.

Cryptcat: communicate between two systems and encrypts with twofish

WEB-STAT: an app, analyzing web traffic, find users` location, search engine, last visit, equipment, and more.

Webroot: an American privately-held cybersecurity software company

WebSite-Watcher: a closed source shareware program, monitor changes to web pages.

WAFW00F:  Python tool, fingerprint and identify Web Application Firewall (WAF) products, active reconnaissance tool

ping: -n count on Windows, -c count on Linux.

three-tier application: 
- presentation tier, aka user interface. HTML, CSS, and JavaScript.
- application tier, aka logic tier. Python, Java, Perl, PHP or Ruby.
- data tier. PostgreSQL, MySQL, MariaDB, Oracle, DB2, Informix or Microsoft SQL Server; or Cassandra, CouchDB, or MongoDB

tier vs layer: tier on different infrasturctures.

windows TTL: 128

linux TTL: 64

five-tier container technology architecture:
- Tier-1: Developer machines
- Tier-2: Testing and accreditation systems
- Tier-3: Registries
- Tier-4: Orchestrators
- Tier-5: Hosts

The Docker daemon:  listens for Docker API requests and manages Docker objects such as images, containers, networks, and volumes.
The Docker client: Docker users interact with Docker.
A Docker registry: stores Docker images.
Docker objects: images, containers, networks, volumes, plugins

Vulnerability Management Life Cycle:
- Discover
- Prioritize Assets
- Assess
- Report
- Remediate
- Verify

iOS Trustjacking:  attackers to exploit the iTunes Wi-Fi sync feature

Trident: a vulnerability, allow espionage of IOS on smartphone.

DNS Tunneling: encodes the data of other programs or protocols in DNS queries and responses, to bypass firewall.

MIB: Management Information Base
- LMMIB2.MIB         workstation and server services
- DHCP.MIB             network traffic between remote hosts and DHCP servers
- HOSTMIB.MIB       host resources
- MIB_II.MIB           managing TCP/IP-based internets
- WINS.MIB             Windows Internet Name Service (WINS)

Doxing: malicious identification and online publication of information about an individual.

Daisy-chaining: same information to gain access to multiple networks and computers.

Shellshock: 
- ``` () {:;}; /bin/cat /etc/passwd ```
- attackers send a malformed environment variable
- aka. Bash Bug
- not on Windows.

bastion host: aka jump box ,a server used to manage access to an internal or private network from an external network

WAF: Web Application Firewall, layer 7 defence.

NAC: Network Access Control

Meltdown & Spectre exploit: critical vulnerabilities in modern processors

Named Pipe Impersonation: named pipes are used to provide legitimate communication between running processes.

Application Shimming: transparently intercepts API calls and changes the arguments passed, may allow malicious acts.

Launch Daemon: Adversaries install a new launch daemon execute at startup.

Single sign-on (SSO):  
- login once and access services without re-entering authentication factors
- disadvantage: a single point of failure for authentication.

SESAME: used for single sign-on.

SOA: Service-oriented architecture.  can be accessed remotely

ISAPI: recommend disable unnecessary ISAPI filters, to defend against webserver attacks.

Sinkhole Attack: compromised node tries to attract network traffic by advertising its fake routing update.

Corporate espionage:
- Wiretapping a competitor
- blackmail, bribery, and technological surveillance to the target company.

blackberry:
- Blackjacking:  hijacking a BlackBerry connection
- BBProxy: allows attacker to use a BlackBerry device as a proxy 
- BBScan:  BlackBerry port scanner

CHNTPW:  
- linux-based tool, 
- change user password, en/disable accounts, 
- on Windows NT, 2000, XP, Vista, 7, 8, 8.1 and 10.
- by editing SAM database.

windows password:
- in Security Account Manager (SAM) file at: 
- C:\Windows\system32\config

SAM security identifier:
- 500.   administrator account (like 0 for root in linux)

PDU on layers:
1. bit (physical)
2. frame (datalink)
3. packet (network)
4. segment(TCP) or datagram(UDP) (transport)
5. data(layer5-layer7) (application)

Rules of engagement (ROE): describes the specifics of the testing, the associated violations and essentially protects both the organization's interest and third-party penetration tester
- The type and scope of testing
- Client contact details
- Client IT team notifications
- Sensitive data handling
- Status meeting and reports

SDLC: Software Development Life Cycle

security testing:
- Automated Tools: Coverage, Efficiency, Qualifications, Reporting, Investment
- Manual Approach: Effectiveness, Validity, Accuracy, Custom Reporting, Investment

3-2-1 backup rule: keep at least three separate versions of data on, two different storage types with at least, one offsite.

Cryptanalysis:
- Global deduction.                 discovers a functionally equivalent algorithm for encryption and decryption, but without learning the key.
- Instance (local) deduction.   discovers additional plaintexts (or ciphertexts) not previously known.
- Information deduction.         gains some Shannon information about plaintexts (or ciphertexts) not previously known.
- Total break.                         deduces the secret key

No ABAC validation: No proper attribute-based access control,  allows attackers to gain unauthorized access to API 

heap spray: put malicious code in different heap(non-executable part) locations, give more chance to hit and execute.
- may not allow for remote code execution.

vendor lock-in problem: customers of a cloud service provider (CSP) cannot easily move to a different vendor without substantial costs or technical incompatibilities
- 1. Data transfer risk
- 2. Application transfer risk
- 3. Infrastructure transfer risk
- 4. Human resource knowledge risk

types-of-threat-intelligence:
- Strategic Threat Intelligence.          long-term, high level.            high level information on changing risks.
- Tactical Threat Intelligence.            long-term, low level              information on attackers` TTPs.
- Operational Threat Intelligence.      short-term, high level            information on specific incoming attack.
- Technical Threat Intelligence.          short-term, low level             Specific IOC(Indicator of compromise )

Key escrow:  
- key is held in escrow by a third party
- hold certificates and keys in case the primary keys or certificates are unavailable

Key whitening:  It consists of steps that combine the data with portions of the key.

Key schedule: an algorithm that calculates all the round keys from the key

Key encapsulation: secure symmetric cryptographic key material for transmission using asymmetric (public-key) algorithms.

Server Side Includes Injection: Another way to discover if the application is vulnerable is to verify the presence of pages with extension .stm, .shtm and .shtml.

Smudge attack: oily smudges produced and left behind by the user's fingers to find the pattern or code

Password spraying attack:  logins based on list of usernames with one default passwords on the application.

unuseful knowledge:
- Syhunt Hybrid:  static and dynamic security scans to detect vulnerabilities like XSS, File Inclusion, SQL Injection, Command Execution.
- AT&T USM Anywhere: centralizes security monitoring of networks and devices in the cloud, on-premises,  in remote locations
- Saleae Logic Analyzer:  record and display signals in your circuit to debug it fast.
- Cisco ASA:  hardware firewalls developed by Cisco Systems

Cisco SPAN port: on a Cisco switch, Switched Port Analyzer. gather traffic

Credential enumerator: 
- a self-extracting RAR file (containing bypass and service components), 
- to retrieve information related to network resources such as writable share drives

NetPass.exe:  recovers all network passwords stored on a system for the current logged-on user

Outlook scraper: scrapes names and email addresses from the victim’s Outlook accounts, for future phishing.

Mail PassView: a password recovery tool that reveals passwords and account details for various email clients such as Microsoft Outlook, Windows Mail, Mozilla Thunderbird, Hotmail, Yahoo! Mail, and Gmail and passes them to the credential enumerator module.

incident handling and response process:
- 1. Preparation
- 2. Incident recording and assignment
- 3. Incident triage
- 4. Eradication

incident handling process phases:
- 1. Preparation
- 2. Identification
- 3. Containment
- 4. Neutralization
- 5. Recovery
- 6. Review

Zero Trust Network Access (ZTNA): providing only the access to services the user has been explicitly granted

``` wget 192.168.0.10 -q -S ```
- -q will suppress the normal output
- -S parameter will print the headers sent by the HTTP or FTP server
- banner grabbing

Kubernetes:
- Kube-scheduler. master component, scans newly generated pods and allocates a node for them
- Kube-apiserver. front-end utility
- Kube-controller-manager.  master component, runs controllers
- cloud-controller-manager. master component, run controllers that communicate with cloud providers.

Key stretching: make weak key more secure, against brute-force.

Key derivation function (KDF): derives one or more secret keys from a secret value

RIR:
- RIPE NCC
- APNIC
- AFRINIC
- LACNIC
- ARIN

ARIN LOOKUP: 
- American Registry for Internet Numbers, <https://mxtoolbox.com/arin.aspx>
- retrieve information like: organization's network range, network topology and operating system used.

SCADA: Supervisory control and data acquisition. industrial 

password-cracking: hashcat, john the ripper, ophcrack

Ophcrack: use rainbow table, crack Windows log-in passwords

CeWL: ruby app, spider find url to build wordlist

Hootsuite: gather information from social media

OSINT framework:
- <https://osintframework.com/>
- contains a set of the most popular tools that facilitate your tasks of collecting information and data from open sources

Spearphone attack: breaches speech privacy

wash: kali tool, identifying WPS enabled access points

sqlmap: 
- --dbs Enumerate DBMS databases

Credential stuffing attack:  attacker uses known username/password combinations

ping to death: first in 1996.

kerberos: allow workstations to authenticate against remote services

Kerberoasting:  
- send requests using Kerberos with the intent of gathering information about accounts that could be used offline.
- look like legitimate traffic

``` net view /domain:<domain_name> ```
- show all the systems within the domain

/var/log/lastlog: the activities of the last user that signed in

CPU instruction:
- 0x90 NOP
- 0x99 ADD
- 0x91 COPY

UDP datagram payload: 65,535 - 8(header) - 20(IP header) = 65507(payload size)

- shared responsibility model: determines who has responsibility for what aspects of a service with a cloud services provider. 
- Bell-LaPadula: data classification and management
- Carnegie Mellon Maturity Model: aka Capability Maturity Model. assess maturity, especially within software development organizations.

IANA: Internet Assigned Numbers Authority

- administrative control: aka soft control. like Security policy.
- technical control: like access control list.
- physical control: mantrap, biometric device

MegaPing: Windows GUI tool, do ping sweeps and port scans

EternalBlue: takes advantage of a vulnerability in the Server Message Block protocol

Clean desk policy: clean off their desk, empty trash, shred sensitive documents

- local area network: rooms
- metropolitan area network: buildings, city blocks
- wide area network: countries, states

RFC 1918: non-routable IP addresses. 10.0.0.0–10.255.255.255, 172.16.0.0–172.31.255.255, and 192.168.0.0–192.168.255.255

Defensible network architecture: includes the ability to isolate systems and detect attacks and may also include preventive measures

EDGAR: 
- Electronic Data Gathering, Analysis, and Retrieval, 
- financial information about a company, including financial reports

The crossover error rate (CER) 
- is the point at which the FRR(false reject rate) and the FAR(false acceptance rate) intersect.
- meaning set at an optimal setting for authenticating subject

windows hide file: attrib +h <filename>

- disassembly: opcodes to assembly language, lower level
- Decompilation: compiled program to source code, higher level

---

last123

software firewall
teardrop
DNSSEC
NTP port
IPSEC layer
802.11a
Obfuscation attack
NIDS

<https://wiki.danielgorbe.com/books/ceh-v10>
