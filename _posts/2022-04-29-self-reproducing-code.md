---
title: self reproducing code
author: Yuchao
date: 2022-04-29 11:33:00 +0800
categories: [sec]
tags: [c]
math: true
mermaid: true
---

## How to write a quine

#### self-reproducing code
A quine is a program, takes no input and produces a copy of its own source code as its only output.

original code is:

```
Head is: malicious code + data of line numbers for tail
Body is:  `Head in string` + `Tail in string`
Tail   is:  reproducing code
```

Tail code = print(Body.head) + print(Body) + print(Body.tail)

after execution:
1. execute malicious code
2. print the code it self

usage: XXS worm
