---
title: cryptography
author: Yuchao
date: 2021-11-13 11:33:00 +0800
categories: [sec]
tags: [cryptography]
math: true
mermaid: true
---

# secret key encryption

``` tr 'a-z' 'A-Z' <  test.txt ``` to upper case


#### Encryption Mode: Electronic Codebook(ECB), Cipher-Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback(OFB)
- ECB no IV, cypher with same pattern if plaintext same.
- CBC with IV.
- CFB stream encryption. plain text XOR with encrypted IV, so can encrypt bit by bit. feed cypher to next block.
- OFB Output Feedback. feed encrypt IV (cypher before XOR) to next block.


#### padding oracle.


# hash


```bash
md5sum file.txt
sha256sum file.txt
openssl dgst -sha256 file.txt
openssl sha256 file.txt
```


```sql
mysql> SELECT SHA2('message', 256) -- SHA-2 family of hash functions (SHA-224, SHA-256, SHA-384, and SHA-512).
```


```python
import hashlib
m = hashlib.sha256()
m.update("message")
m.hexdigest()
```


```php
echo hash('sha256', 'message');
```


```bash
x=$((16#3200))
# x is 3200 in 16
echo $x
# print x in 10
```


#### hash collision:
- hash(A+B1+C) = hash(A+B2+C), if hash(A+B1) = hash(A+B2)
- A+B1+B1+C, benign version
- A+B1+B2+C, malicious version
- C: if(b1=b2) benign code or malicious code.
- benign and malicious version of softwares have same hash value.
 

#### MAC: Hash Length Extension Attack.
- Hash( K || S+MS) = Hash ( Hash( K || S) + MS )
- so we can add Malicious String behind.


#### HMAC: add a layer of hash with opad and ipad.
- avoid Hash Length Extention Attack.
- ``` echo -n "a messsage" | openssl dgst -sha256 -hmac "secretkey" ```
- culculate hmac based on sha256 algorithm


# public-key cryptography

#### diffie-hellman key exchange
- A,B gree on g (can be small), p (very large)
- A keeps X, B keeps Y
- A send B:    g^X mod p, B can not find X
- B send A:    g^Y mod p, A can not find Y
- B culculate: (g^X mod p) ^ Y mod p = g ^ (xy) mod p
- A culculate: (g^Y mod p) ^ X mod p = g ^ (yx) mod p
- get common secret number, through open channel.

#### turn diffie-hellman to public key encrytion
- private key of A: x.
- public key of A: g, p,  g^x mod p.
- B encrypt message by g^xy mod p. y is secret of B.
- B send A: 1. g^y mod p, and 2. secret message.

#### RSA


# PKI

# TLS

# Bitcoin
