---
title: How to write a post
author: Yuchao
date: 2022-03-27 11:33:00 +0800
categories: [Dev]
tags: [Jekyll, Git]
math: true
mermaid: true
---

## How to write a post

##### Steps:
- Create post(s) at zenbro.github.io/_posts
- ``` git clone https://github.com/YuchaoZheng88/zenbro.github.io.git ```
- ``` cd zenbro.github.io ```
- ``` git submodule init ```
- ``` git submodule update ```
- ``` cd YuchaoZheng88.github.io/ ```
- ``` git checkout main```
- ``` cd .. ```
- ``` bundle update ```
- ``` jekyll build -d YuchaoZheng88.github.io ```
- ``` cd YuchaoZheng88.github.io/ ```
- push the YuchaoZheng88.github.io submodule
- ``` cd .. ```
- push the zenbro.github.io module

##### easy way:

``` bash
#! /bin/bash

git clone https://github.com/YuchaoZheng88/zenbro.github.io.git
cd zenbro.github.io
git submodule init
git submodule update
cd YuchaoZheng88.github.io/
git checkout main
cd ..
bundle update
jekyll build -d YuchaoZheng88.github.io
cd YuchaoZheng88.github.io/
```
{: .nolineno file="quickinit.sh" }
