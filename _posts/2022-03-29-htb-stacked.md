---
title: htb stacked
author: Yuchao
date: 2022-03-29 11:33:00 +0800
categories: [sec]
tags: [htb, aws, localstack]
math: true
mermaid: true
---

## recon
```
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.112
nmap -p 22,80,2376 -sCV -oA scans/nmap-tcpscripts 10.10.11.112
```
