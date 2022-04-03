---
title: htb stacked
author: Yuchao
date: 2022-04-02 11:33:00 +0800
categories: [sec]
tags: [htb]
math: true
mermaid: true
---

## Brute force Laravel application pin

#### try type juggling
- change content type to application/json
- application/x-www-form-urlencoded, body is ``` name=admin&pin=1234 ```
-  application/json, body is ``` {"name":"admin", "pin":true} ``` try type juggling, php == not === vulnarability, but no on this box.

####

