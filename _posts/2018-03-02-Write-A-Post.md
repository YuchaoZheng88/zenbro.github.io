---
title: How to write a post
author: Yuchao
date: 2022-03-27 11:33:00 +0800
categories: [dev]
tags: [jekyll, git]
math: true
mermaid: true
---

## How to write a post

##### Steps:
1. Create post(s) with .md format at zenbro.github.io/_posts
2. Run the bash
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
3. push YuchaoZheng88.github.io, then push main zenbro.github.io