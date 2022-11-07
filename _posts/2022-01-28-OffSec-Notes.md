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

- ``` man -k pass ``` find manuals with matched keyword ‘pass’ 
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
- ``` cat file.txt | sed ':a;N;$!ba;s/\n//g' ``` remove newline from file.txt
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
- ``` who ``` who is logged on.
- ``` who /var/log/wtmp | tail -5 ``` another file, default /var/run/utmp
- ``` last ``` show last login users.
- ``` journalctl ``` Query the systemd journal
- ``` free -m ``` information on memory, in mebibytes.
- ``` df -hT ``` disk mounted usage information, in human-readable format, show -T type.
- ``` mount -t ext4 ``` display the partitions formatted as ext4
- ``` fdisk -l ``` can check USB drive
- ``` mkdir /mnt/usb && mount /dev/sdb1 /mnt/usb ``` mount device(eg. a USB) to directory tree
- ``` cd ~ && umount /mnt/usb ``` unmount the device, not in its directory, nor it will be busy.

## Windows

- ``` dir /A ``` dir is a builtin command, ls is not.
- ``` help ``` display all build-in commands.
- ``` systeminfo /? ``` configuration information about the system
- ``` echo %username% ``` %<VARIABLE-NAME>%
- ``` set ``` Display environment variables.
- ``` psinfo ``` vital local system information
- ``` echo "New File" > NewFile.txt ``` standard input to a file.
- ``` echo 2> EmptyFile.txt ``` standard error to a file.
- ``` del EmptyFile.txt ``` delete a file.
- ``` rename NewFile.txt RenamedFile.txt ``` rename a file.
- ``` move RenamedFile.txt .\Music ``` move to different directory.
- ``` mkdir ANewDirectory ``` create folders.
- ``` rmdir ANewDirectory ``` delete folder.
- ``` rmdir /S .\ThisFolder ``` delete folder with files in it.
- ``` copy RenamedFile.txt ThisIsntMusic.txt ``` copy file.
- ``` fc 1.txt 2.txt ``` compare files.
- ``` mklink softlink fileToBeLinkedTo.txt ``` create soft link.
- ``` mklink /h hardlink fileToBeLinkedTo.txt ``` create hard link.
- ``` dir /s trojan.txt ``` search in the given folder and any of its subfolders.
- ``` dir /s *.exe /p ```  search with wildcard; /P Pauses after each screenful of information.
- ``` tree ```
- ``` forfiles /P C:\Windows /S /M notepad.exe /c "cmd /c echo @PATH" ```/S recursive, /M search what, /c command, /P path to search.
- ``` find "password" C:\Users\Offsec\importantfile.txt ``` like Linux grep. find do NOT support regular expressions.
- ``` type importantfile.txt | find "password" ``` like Linux:  ``` cat importantfile.txt | grep password ```
- ``` dir | find "important" ``` like ``` ls | grep <directory> ```
- ``` findstr "Johnny password" importantfile.txt ``` find jonny OR password, findstr support regular expressions.
- ``` sort /R numbers.txt ``` sort from large number to small.
- Everyone. SID: S-1-1-0. . includes all users on the machine.
- Administrator. SID: S-1-5-domain-500. .
- Guests group. SID: SID S-1-5-32-546.
- ``` whoami /user ``` show user,name,SID.
- ``` net user /add Tristan greatpassword ``` create user.
- ``` net user {username} ``` retrieve user information.
- ``` net localgroup Administrators user123 /add ``` add user123 to Administrators group.
- ``` net localgroup Administrators user123 /del ``` remove from group.
- ``` net user /del user123 ``` delete the account.
- ``` cmd /c echo hi ``` run command in another cmd.exe process.
- ``` icacls Music ``` view folder permissions. each line of the output is considered an ACE.
- ``` icacls Music /grant Susan:(OI)(CI)(F) ``` provide rights to folder. /deny to remove rights.
- ``` accesschk.exe "users" c:\ ```  permissions the users group has on the C:\ drive.
- smss.exe(Session Manager Subsystem): the first User mode process started on a Windows machine.
- smss.exe: spawn twitce. 1st spawns winlogon.exe and csrss.exe. 2nd stays alive to watch over the user's session.
- winlogon.exe: listen's for the famous Ctr+Alt+Delete.
- ``` tasklist /fi "USERNAME eq NT AUTHORITY\SYSTEM" /fi "STATUS eq running" ``` filter
- ``` tasklist /fi "imagename eq cmd.exe" ``` filter
- ``` tasklist |find "cmd.exe" ``` anther way to filter
- ``` taskkill /? ``` terminate a process by ID or image name.
- ``` taskkill /PID 84 ``` kill process ID 84
- ``` pslist /? ``` 
- ``` pslist -t |find "cmd" ``` show process tree.
- ``` pskill 6132 ``` terminate PID 6132.
- ``` pssuspend chrome.exe ``` suspend a process.
- ``` pssuspend -r chrome.exe ``` resume.
- ``` listdlls ``` dlls called by processes.
- ``` reg /? ``` registry edit
- ``` reg add hkcu\software\microsoft\windows\currentversion\run /v OneDrive /t REG_SZ /d "C:\Users\Offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe" ``` add one, /v value, /t data type, /d data
- ``` reg export hkcu\environment environment ``` export registry key to a file named "environment".
- ``` type environment ``` show exported registry, in hex format.(can be read when transfered to ascii)
- ``` schtasks /? ``` like Linux cronjobs.
- ``` schtasks /create /sc weekly /d mon /tn runme /tr C:\runme.exe /st 09:00 ``` a scheduled task example.
- ``` fsutil ``` 
- ``` fsutil fsinfo volumeinfo C: ``` 
- ``` echo fileTwo uses the 'offsec' stream > offsecStream.txt:offsec ``` echo to NTFS`s ADS. Alternate Data Streams
- ``` more offsecStream.txt:offsec ``` read from ADS, can not just type out ADS.
- ``` dir /r ``` allow us to detect ADS usage.

## Networking
- TCP/IP Model: L4 software, L3 machines, L2 networks, L1 same physical network.
- DHCP runs on TCP/IP application layer. 

## BASH

Difference between single and double quotes.
```bash
greeting='Hello World'
greeting1='New $greeting'
greeting2="New $greeting"

echo $greeting1
# New $greeting

echo $greeting2
# New Hello World
```

Concatenating strings
```bash
greet1="Hello, my name is "
greet2="Jolinda"
greeting=$greet1$greet2
echo $greeting
# Hello, my name is Jolinda
```

$(...) preferred over `...` (backticks)
```bash
user1="`whoami`"
user=$(whoami)
echo $user1
echo $user
# same results
# why preferred, http://mywiki.wooledge.org/BashFAQ/082
```

(( ... )) construct permits arithmetic expansion and evaluation
```bash
echo $((7+"3"))
g=5
echo $((g--))
echo $((--g))
# variables are within the double parentheses and the values resemble numbers
# variables in bash are strings by default
let a=1+1
# let make variables to number
```

arguments
```bash
# arg.sh
#!/bin/bash
echo "There are $# arguments"
echo "The first two arguments are $1 and $2"
# ./arg.sh who goes there?
```

special variable names
```
$0			The name of the Bash script
$1 - $9	The first 9 arguments to the Bash script
$#		Number of arguments passed to the Bash script
$@		All arguments passed to the Bash script
$?			The exit status of the most recently run process
$$			The process ID of the current script
$USER	The username of the user running the script
$UID		The user identifier of the user running the script
$HOSTNAME		The hostname of the machine
$RANDOM			A random number
$LINENO			The current line number in the script
```

same line read to user, with prompt
```
read -p 'Enter your name: ' user
```

operators
```
OPERATOR                  DESCRIPTION: EXPRESSION TRUE IF...
!EXPRESSION               The EXPRESSION is false.
-n STRING							    STRING length is greater than zero
-z STRING							    The length of STRING is zero (empty)
STRING1 != STRING2		    STRING1 is not equal to STRING2
STRING1 = STRING2			    STRING1 is equal to STRING2
INTEGER1 -eq INTEGER2	    INTEGER1 is equal to INTEGER2
INTEGER1 -ne INTEGER2	    INTEGER1 is not equal to INTEGER2
INTEGER1 -gt INTEGER2	    INTEGER1 is greater than INTEGER2
INTEGER1 -lt INTEGER2		  INTEGER1 is less than INTEGER2
INTEGER1 -ge INTEGER2	    INTEGER1 is greater than or equal to INTEGER 2
INTEGER1 -le INTEGER2	    INTEGER1 is less than or equal to INTEGER 2
-d FILE								    FILE exists and is a directory
-e FILE								    FILE exists
-r FILE								    FILE exists and has read permission
-s FILE								    FILE exists and it is not empty
-w FILE								    FILE exists and has write permission
-x FILE								    FILE exists and has execute permission
```

if
```
read -p "file name: " file
if [ -e $file ]
then
  echo "file exists!"
else
  echo "file does not exist!"
fi
```
