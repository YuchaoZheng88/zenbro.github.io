---
title: Linux for CTF
author: Yuchao
date: 2022-05-23 11:33:00 +0800
categories: [sec]
tags: [linux,htb,thm,ctf]
math: true
mermaid: true
---

# mostly from IPPSEC and 0xdf writeups.

# sshpass, dd, gzip
``` sshpass -p raspberry ssh pi@10.10.10.48 "sudo dd if=/dev/sdb | gzip -1 -" | dd of=usb.gz ```
- ``` sshpass -p raspberry ``` - use the password “raspberry” for the following SSH command (like ssh and scp)
- ``` ssh pi@10.10.10.48 "[command]" ``` - SSH into Mirai and run the command
- ``` sudo dd if=/dev/sdb ``` - read all of /dev/sdb and print it to STDOUT
- ``` | gzip -1 - ``` - compress the file read from STDIN (-) and print the result to STDOUT
- The result of that command run over SSH is now printed to STDOUT on my local VM
- ``` | dd =of=usb.gz ``` - write that output to usb.gz
- ``` gunzip usb.gz ```
- HTB: Mirai

# extundelete 
- data recovery tool
- <http://extundelete.sourceforge.net/>
- ``` extundelete {file} --restore-all ```
- HTB: Mirai

# testdisk
- recovery tool
- HTB: Mirai

# wpscan
-  WordPress Security Scanner
- ``` wpscan --url https://brainfuck.htb --disable-tls-checks --api-token $WPSCAN_API ```

# UDP port scan
- ``` sudo nmap -sU -top-ports=100 panda.htb ``` 100 top most common ports

# feroxbuster
- ``` feroxbuster -u http://10.10.10.34 ```
- ``` feroxbuster -u http://10.10.10.34 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt ```

# showmount & mount
- ``` showmount -e {IP} ``` check from remote
- ``` cat /etc/exports ``` check locally
- ``` sudo mount -t nfs 10.10.10.34:/opt /mnt/opt/ ```

# ls
- ``` ls -ld {directory} ``` list directory information, not content.

# wfuzz
- ``` wfuzz -u http://panda.htb -H "Host: FUZZ.panda.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 33560 ``` fuzz virtual hosts, hide default length.

# SNMP - UDP 161 
- community string: basically a password
- ``` onesixtyone 10.10.10.20 -c /usr/share/doc/onesixtyone/dict.txt  ``` try some community strings
- ``` apt install snmp snmp-mibs-downloader ```
- ``` snmpwalk -v 2c -c public 10.10.11.136 | tee snmp-full ```

