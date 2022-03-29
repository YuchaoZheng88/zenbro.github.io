---
title: htb secret
author: Yuchao
date: 2021-10-30 00:00:00 +0000
categories: [sec]
tags: [htb, express, nodejs, dotenv, jwt, nmap, feroxbuster, curl, git]
math: true
mermaid: true
---

## nmap
```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.120
nmap -p 22,80,3000 -sCV -oA scans/nmap-tcpscripts 10.10.11.120
```

## See 80, 3000 port run the same thing:
1. maybe 80 is a reverse proxy of 3000.
2. maybe one developer version, one production version.
3. some misconfiguration

## Directory discovery
```bash
feroxbuster -u http://10.10.11.120
```

## use API by document
```bash
# /api/user/register
curl -d '{"name":"0xdf0xdf","email":"dfdfdfdf@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
# /api/user/login
curl -d '{"email":"dfdfdfdf@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/login -H 'Content-Type: Application/json'
```
- -d data
- -X method
- -H header
- It supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP,  LDAPS,  MQTT,  POP3,  POP3S, RTMP,  RTMPS,  RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET or TFTP.
- after the request, got a JWT.

## nginx
- port 80 is same with port 3000. 3000 does not have NGINX.
- suspect NGINX is just there to proxy for Express.

## analysis the source
- nodejs express application

#### find Token generation
``` javascript
// Dotenv loads environment variables from a .env file into process.env
const dotenv = require('dotenv')
dotenv.config();
```
{: .nolineno file="index.js" }

``` javascript
// create jwt
const jwt = require("jsonwebtoken");
const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
res.header('auth-token', token).send(token);
const verified = jwt.verify(token, process.env.TOKEN_SECRET);
```
{: .nolineno file="/routes/auth.js" }

#### find git information
```bash
git log --oneline
git show 67d8da7
```
get the TOKEN_SECRET from git old version

## Forge JWT


