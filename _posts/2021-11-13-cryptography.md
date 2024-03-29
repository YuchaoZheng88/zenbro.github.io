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
- ``` Hash( K || S+MS) = Hash ( Hash( K || S) + MS ) ```
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

n = p*q, RSA based on: if know n, can not find p and q.


Euler`s Theorem
- Φ(n): number of positive integer up to n, that are relatively prime to n.
- Φ(p) = p-1, if p is prime.
- Φ(m*n) = Φ(m) * Φ(n), if m,n are co-prime.
- Φ(p*q) = (p-1)*(q-1), if p,q are prime.
- a^Φ(n) = 1 (mod n), if a,n are co-prime.

Example
- 4^100003 mod 33 = ?
- Φ(33) = 2*10 = 20
- 4^20 mod 33 = 1

Extended Euclidean Algorithm
- if a*x + b*y = gcd(a,b) = 1
- then a*x = 1 (mod b)
- x is the inverse of a, in mod b.
- public key, private key, inverse each other.

RSA Algorithm
- find e, a prime. mostly 65537. as public key
- find 2 large prime number: p, q. n=p*q. e and Φ(n) are co-prime.
- find d, e*d = 1 mod Φ(n), d as secret key.
- if know p,q, can easily find d; if only know n, very difficult.
- Message ^ e (mod n) = Cryptedtext.
- e, n are public.
- p, q, Φ(n), d are secret.
- Cryptedtext ^ d (mod n) = Message.

why
- a is M encrypt then decrypt.
- a= M^(ed) mod n
- ed = k * Φ(n) + 1
- a= M ^ (k * Φ(n)) * M mod n
- as M ^ Φ(n) = 1 mod n
- a = M

note
- message can not be longer than n.

openssl and RSA
- generate RSA keys, encrypted by aes128 and encoded by base64
- ``` openssl genrsa -aes128 -out private.pem 1024 ```
- view private key
- ``` openssl rsa -in private.pem -noout -text ```
- get public key
- ``` openssl rsa -in private.pem -pubout > public.pem ```
- view public key
- ``` openssl rsa -in public.epm -pubin -text -noout ```
- encrypt msg.txt to msg.enc
- ``` openssl rsautl -encrypt -inkey public.pem -pubin -in msg.txt -out msg.enc ```
- decrypt
- ``` openssl rsautl -decrypt -inkey private.pem -in msg.enc ```

strength
- 1024-bit RSA keys = 80-bit symmetric keys
- 2048-bit RSA keys = 112-bit symmetric keys
- 3072-bit RSA keys = 128-bit symmetric keys

test speed
- ``` openssl speed rsa ```
- ``` openssl speed aes-128-cbc ```

#### RSA padding
- like IV in symmtric encryption.
- ``` openssl rsautl -encrypt... -pkcs ``` use PKCS padding (default)
- ``` openssl rsautl -decrypt... -raw ``` see the padding information
- better and secure padding, oaep
- ``` openssl rsautl -encrypt... -oaep ```


#### Digital Signature
- ``` openssl sha256 -binary msg.txt > msg.sha256 ```
- ``` openssl rsautl -sign -inkey private.pem -in msg.sha256 -out msg.sig ```
- ``` openssl rsautl -verify -inkey public.pem -in msg.sig -pubin -raw | xxd ```

#### program
cryptography library
- <https://cryptography.io/en/latest/>


Usage
- Key Generation

```python
#!/usr/bin/python3

from Crypto.PublicKey import RSA

key = RSA.generate(2048) # key length
pem = key.export_key(format='PEM', passphrase='ddd')
f = open('private.pem', 'wb')
f.write(pem)
f.close()

pub = key.publickey()
pub_pem = pub.export_key(format='PEM')
f = open('public.pem', 'wb')
f.write(pub_pem)
f.close()
```


- Encryption

```python
#!/usr/bin/python3

from Crypto.Cipher imprt PKCS1_OAEP
from Crypto.PublicKey import RSA

message = b'a secret message\n'

key = RSA.importKey(open('public.pem').read())
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(messagge)
f = open('ciphertext.bin', 'wb')
f.write(ciphertext)
f.close()
```

- Decryption

```python
#!/usr/bin/python3

from Crypto.Cipher imprt PKCS1_OAEP
from Crypto.PublicKey import RSA

ciphertext = open('ciphertext.bin', 'rb').read()
prikey_pem = open('private.pem').read()
prikey = RSA.importKey(prikey_pem, passphrase='ddd')
cipher = PKCS1_OAEP.new(prikey)
message = cipher.decrypt(ciphertext)
print(message)
```

- Sign

```python
# Probabilistic Signature Scheme (PSS) 
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

message = b'this is a message'
key_pem = open('private.pem').read()
key = RSA.import_key(key_pem, passphrase='ddd')
h = SHA256.new(message)
signer = pss.new(key)
signature = signer.sign(h)
open('signature.bin', 'wb').write(signature)
```

- Verify

```python
message = b'this is a message'
signature = open('signature.bin', 'rb').read()
key = RSA.import_key(open('public.pem').read())
h = SHA256.new(message)
verifier = pss.new(key)
try:
	verifier.verify(h, signature)
	print('valid')
except (ValueError, TypeError):
	print('Not Valid')
```

# PKI

``` openssl s_client -help ```


``` openssl s_client -showcerts -connect www.paypal.com:443 ```
- show paypal`s certificate
- return paypal`s certificate, and intermidia CA signs paypal`s certificate


copy paypal`s certificate to paypal.pem


see plain text description of the certificate
``` openssl x509 -in paypal.pem -text -noout ```

show certs on system
``` cd /etc/ssl/certs ```

check DigiCert_High_Assurance_EV_Root_CA.pem in plain text, its self-signed.


#### Revoking
- CRL: Certificate Revocation List
- OCSP: Online Certificate Status Protocol

#### become a CA
- <https://www.udemy.com/course/du-cryptography/learn/lecture/31600238#overview>

#### Apache
- /etc/apache2/sites-available/bank32_apache_ssl.conf

```
<VirtualHost *:443>
	DocumentRoot /var/www/bank32
	ServerName www.bank32.com
	SSLEngine On
	SSLCertificateFile /certs/bank32.crt
	SSLCertificateKeyFile /certs/bank32.key
</VirtualHost>
```
- bank32.crt contain information of CAs, in a list(if many level)
- ban32.key contain private key.

#### certificate
- include: ID, PK, Sig.

#### MITM proxy
- trusted man in the middle.

#### attack on PKI
attack surface:
1. Approve
2. Certificate
3. Verify
4. Confirm

case:
- Comodo Breach
- DigiNotar


# TLS

TLS Layer sits between Application and Transport layer.

TLS sub protocols: #6

#### TLS HandShake
Key Exchange + Authentication
- 1. create TCP connection, first.
- 2. create TLS HandShake. TLS message may be combined in one TCP packet.

TLS 1.3 difference
- eliminate RSA
- Ephemeral Diffie-Hellman is only choice.(Perfect Forward Secrecy)
- one less run of communication, improve perfomance. 

#### TLS Data Transmission
send data over TLS
- 1. Get data from application
- 2. Fragment data to blocks.
- 3. Compress data block. (optional)
- 4. data block + MAC + Padding.
- 5. Encrypt 4.
- 6. TLS Header + Encrypted Data.
- 7. send to TCP Stream with: TLS Header + Encrypted Data + TLS Header + Encrypted Data


TLS Record
- ContentType + Version + Length + Encrypted Data + MAC + Padding

Receiving Data Over TLS
- 1. TCP Buffer.
- 2. TLS Buffer.
- 3. Get m bytes.

#### TLS program

TLS Client

```python
# client.py

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
cadir = '/etc/ssl/certs'

# Set up TLS context
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)   # TLS 1.2
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # 1.3

context.load_verify_locations(capath=cadir) # where to find trusted certificate
context.verify_mode = ssl.CERT_REQUIRED

# hostname if as in certificate , in case DNS redirect and MitM. Many forget it.
context.check_hostname = True 


# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("TCP connected, press to continue")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False) # tell TLS which TCP to use, not do handshake automaticly
ssock.do_handshake()  # do handshake manually
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate: ")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake, Press to continue")

# Send HTTP request
request = b"GET / HTTP/1.0\r\nHost: “ + hostname.encode('utf-8') + b"\r\n\r\n"
ssock.sendall(request)

# Get HTTP response
response = sock.recv(2048)
while response:
	pprint.pprint(response.split(b"\r\n"))
	print('--------------------')
	response = ssock.recv(2048)


# Close TLS connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```


TLS Server

```python
# server.py

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>This is website!</h1></body></html>
"""

SERVER_CERT     = './server-certs/mycert.crt'
SERVER_PRIVATE = './server-certs/mycert.key'

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

# create tcp server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind(('0.0.0.0', 443))
sock.listen(5)

while True:
	newsock, fromaddr = sock.accept()
	try:
		ssock = context.wrap_socket(newsock, server_side=True)
		print('TLS connection established')
		data = ssock.recv(1024)                           # Read data over TLS
		pprint.pprint("Request: {}".format(datat))    # Send data over TLS
		ssock.sendall(html.encode('utf-8'))
		
		# close TLS connection
		ssock.shutdown(socket.SHUT_PDWR)
		ssock.close()
```


#### TLS Proxy

Client should trust proxy`s root CA.
1. Proxy Server sign a root CA
2. The CA is trusted by client.
3. Client talk to google(for example), it talks to Proxy.
4. The proxy gives client the google certificate, generate as client needed.
5. Client think proxy is google, then proxy talks real google.
