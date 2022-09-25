---
title: OffSecNotes
author: Yuchao
date: 2022-08-25 11:33:00 +0800
categories: [sec]
tags: [oscp]
math: true
mermaid: true
---

## Linux


- ``` ls /etc/apache2/sites-available/*.conf ``` ls with regular expression
- ``` echo $HISTFILE ``` show environment variable 
- ``` set ``` explore environment variables
- ``` alias ll='ls -la' ``` alias for zsh
- ``` uname -a ``` show kernel information
- ``` ln -s ~/original.txt symlink.txt ``` soft link, like windows link, deleted as rm original
- ``` ln ~/offsec123.txt hardlink.txt ``` hard link, a copy changes content as the original file, can not delete as rm original
- ``` which {file_name} ``` find files in $PATH
- ``` locate {file_name} ``` search in locate.db
- ``` find -name {filename} -iname{case insensitive} -type f/d/l/s(file,directory,link,socket) -size 2M -mtime +1(one day or more) -1(in 24 hours) ``` 
- ``` echo "I need to try hard" | sed 's/hard/harder/' ``` replace
- ``` echo "hello::there::friend" | awk -F "::" '{print $1, $3}' ``` 
- ``` comm -12 scan-a.txt scan-b.txt ``` appear in both file, -1 suppress column 1 (lines unique to FILE1)
- ``` diff -u scan-a.txt scan-b.txt ``` -u unified format; -b ignore blank lines; -d try hard to find a smaller set of changes
- ``` nano -B -l my.txt ``` -l show with line number, -B make backup last changed file named as my.txt~
- ``` chage -l kali ``` show user kali`s password information
- ``` passwd -l kali ``` lock kali by adding ! before shadow hash
- ``` su -l kali -c "whoami" ``` temperary -l login as kali to execute a command
- ``` sudo -i ``` can not login as root when default shell of /bin/false
- ``` ls -ld /tmp ``` letter "t" appears at the end indicating sticky bit is set. only their owner or the owner of the parent directory can delete them.
- ``` jobs && fg %1 ``` show jobs and foreground job No.1
- ``` ps -ef ``` -e all; -f full format
- ``` ps aux | grep leafpad ```
- ``` sudo tail -f /var/log/apache2/access.log ``` -f follow, monitor file change.
- ``` watch -n 5 w ``` execute command w every 5 seconds. command w, show who is loged in and what are they doing.
- ``` sudo dpkg -i man-db_2.7.0.2-5_amd64.deb ``` install a debian package offline.
- ``` sudo tail -3 /var/log/auth.log ```
- ``` who /var/log/wtmp | tail -5 ```
- ``` last ```
- ``` journalctl ``` Query the systemd journal
