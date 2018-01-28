---
layout: post
title: "[Write-Up] Sec-IT Bad-Auth Challenge"
categories: [write-up]
tags: [pwn]
description: Write-Up on the "Bad auth" Sec-IT challenge, or how to exploit a format strings without having access to the binary. (Blind format strings on an amd64)
---

# Surroundings
[Sec-IT](https://www.sec-it-solutions.fr/) is a French company which is specialized in Cyber-security and particulary in the penetration testing field.

Last year (in 2017), they put online their own CTF challenges to test their futur employees. The challenges are focus on "Binary Exploitation". Currently, the web-site is already online [here](https://pwn.sec-it-solutions.fr/), if you want to test your skills.

![Sec-IT CTF](/assets/media/sec_it_pwn.png)

I did all the challenges and I really like the "Bad auth" challenge. Basically, the challenge was an easy format string and the aim is to get the flag but there is no needed to get a shell to do it. But it is more funny to get a shell so I am going to show you how to exploit a blind format strings on an amd64 architecture to get a shell access.

This write-up is split in multiple parts:

1. [Introduction](/write-up/2018/01/23/write_up_sec_it.html#introduction)
2. [Binary dump](/write-up/2018/01/23/write_up_sec_it.html#binary-dump)
3. [ASLR Defeat](/write-up/2018/01/23/write_up_sec_it.html#aslr-defeat)
4. [Magic gadget](/write-up/2018/01/23/write_up_sec_it.html#magic-gadget)
5. [Format string](/write-up/2018/01/23/write_up_sec_it.html#format-string)
6. [Binary exploitation](/write-up/2018/01/23/write_up_sec_it.html#binary-exploitation)
7. [Correction](/write-up/2018/01/23/write_up_sec_it.html#correction)
8. [Thanks](/write-up/2018/01/23/write_up_sec_it.html#thanks)
9. [References](/write-up/2018/01/23/write_up_sec_it.html#references)

# Introduction
As you can see on the last screenshot, compare to the other challenges, this one was given without binary access. We only have the IP address and the port to connect to the service.

So let's start by connecting to the service and see what's happening.

![Connect to service](/assets/media/blind_fmt.png)

It seems to be a basic authentication system. The vulnerability is very easy to find. When we type a wrong password, the service display on its output the input password followed by " is a wrong password!". I think the C code looks like this:
```c
printf(password);                   // Vulnerable to format strings
printf(" is a wrong password!");
```

The developer forgot to hard-code the format string of printf(), this means that we have fully control on the format argument.

The variadic list passed in the second argument of printf() represent the variable which the developer wants to display. Before one call to printf(), this list is fully move to the stack. So we can say that printf() will display one part of the stack. But if the developer let the control to the first printf() argument to the user, it will be able to send as much format strings as he wants and so on, read or write any value in the memory.

The password of the service is easy to find but I will not show you how to do it because it represent the solution to the challenge. So don't be confused if I used it later.

Let summarize what we have here:
- We have a remote service without the binary file (ELF).
- Our service got a format strings vulnerability.
- This is only a supposition but, as every binary of the website is compiled like this, I think our service has the following protections: ASLR / No eXecutable / PARTIAL RELocation Read-Only.
- We also suppose that the binary used the same LibC than the given one for the other challenges.

To exploit this kind of situation, we are going to dump the binary to perform static analysis, leak Libc address and overwrite a function pointer from the GOT to call system().

# Binary dump
As the Global Offset Table is writable, the first step is to dump our binary. Our aim is to read the GOT entries to overwrite one of them.

To do it, we are going to use the "%s" printf format which is used to dereference an address and so read its content. The idea is to make a loop which iterate all over the memory address's to read the binary sections we need. Our format strings payload look like this:
```bash
+------------+------------+
|            |            |
|    %7$s    |    ADDR    |
|            |            |
+------------+------------+
```

The format string is composed of two parts. The first part is going to dereference the 7th address of the stack which represent our address and the second part is the 7th address of the stack so it's going to be the memory address that we want to look at.

An ELF binary file is composed of many sections but they are not all mapped into memory by "ld.so". (See References for details)

We are going to get more section as we can but the most interesting for us are the following one:
- ".text" because it contain the assembly code of the service so it going to help us to understand how the service work and it also going to help us to leak the next section.
- ".plt" to know where are stored the ".got" section.
- ".got" this section stored the LibC function address's. (After the dynamic resolve)

Now we have to choose the memory address which we are going to use to iterate over the memory. We first need to leak the ".text" section to be able to leak the ".plt" one. To do it we are going to search the following bytes:
```bash
7f 45 4c 46
```

They represent the first bytes of the ELF header. (In ASCII the last 3 bytes represent "ELF")

Basically, the default memory address for an ELF binary is something like "0x400000" and after trying, our bytes are exactly stored at this address! After some random test, we have to leak "0x1000" bytes from the last memory address we have found. 

So now we have all the assembly code and we can read it but we can't do our exploit because we have not yet the Global Offset Table addresses. I have chosen to leak different Data section like the ".data" because they are very close to the section we needed, the ".got". These sections are often loaded somewhere into memory at the address "0x600000". After some random try, the beginning of the first data section is "0x600e08" and I have to leak 0x250 bytes to get all the sections mapped at this addresses.

So now we can run our script! (Sorry but I can't show you the script because it is going to give you one part of the challenge solution)

![Binary leaked](/assets/media/binary_leaked.png)

Now that we dump all the binary we are able to read the code! As the binary don't have many ELF sections, we can't open it using the basic GNU tools like objdump, GDB, NM... But this is not a problem for IDA! (I just added many symbols to make the code more understandable)

![Binary code](/assets/media/binary_code.png)

This function is the one which is used for the authentication. The function begin by read 0x63 bytes on its input, then compares the input with the final password using strcmp() and the function returns either "1" if the password is equal or "0" if they are not equal. If the password is not equal, the function also makes two calls to printf() function. (you can see the calls at the address 0x4008A5) This is the first call to printf() which is vulnerable to the format strings attack. (As I explain earlier)

# ASLR Defeat
Now that we have access to our binary, we need to defeat the Address Space Layout Randomization in order to be able to run our exploit. 

Little remind: The Address Space Layout Randomization is a system protection. Its aim is to randomize different memory segments like the stack, the heap or the library loading space. Because of this protection we can't make a simple call to system() because we can't predict its address before running the binary. In order to defeat this protection, we are going to leak another LibC function address's (like puts() for example) and then we are going to be able to calculate the difference between both functions and get the address of system().

To do it, we are going to leak one entry of the Global Offset Table but we need to choose one entry which has already been called otherwise the function address's will not been resolved and so on we will not been able to leak the function address's. So I choose to leak the address of puts(). This function is called at the beginning of main() so its address should already been resolved when the format strings will occur.

Let's check in the Global Offset Table what is the address of puts().

![Global Offset Table](/assets/media/global_offset_table.png)

As you can see, the puts() address's is the first entry of the Global Offset Table. So to get the function address we have to check what is the content of the address "0x601018". One more time we are going to use the same tricks that we used to leak the binary in order to dereferenced this address.

![Leak puts](/assets/media/leak_puts.png)

After a check, it seems to be the right address.

Now, as we are able to calculate every LibC function, the ASLR is being useless.

# Magic gadget
To exploit this binary, my first idea was to overwrite the GOT entry of printf() with the address of system() and then send the string "/bin/sh" to system() but as you can see on the precedent image, between the call to bzero() and fflush(), there is a call to printf() so if we overwrite this function address with the one of system(), the binary is going to Segmentation Fault when it will call printf() because we don't control its argument.

To bypass this problem, I used the solution of the Magic Gadget. We are going to overwrite one of the GOT entry with the address of one Magic gadget contained in the LibC to get a shell.

But first, what is a Magic Gadget?

A Magic Gadget is a piece of assembly code in the LibC which make a call to execve() with the string "/bin/sh" as argument. (see References for details) There are several Magic Gadget in the LibC but for this exploit I have chosen this one:

![Magic Gadget](/assets/media/magic_gadget.png)

But to execute a Magic Gadget, we need to fulfill many conditions. In this case, you can see the following instruction:
```nasm
lea rsi, [rsp+0x30]
```

This instruction load the address contain at "rsp+0x30" into the register "rsi" which represent the second argument of the call to execve(). The second argument of execve() is for the argument which are send to our command. ("/bin/sh" in our case) This value must be equal to zero otherwise the call to execve() will fail.

# Format string
Now we only have to build the format strings which we are going to use to write in memory.

Compare to an x86 architecture, on an x64 architecture, that's a little bit harder to exploit a format strings because the memory address contain some null bytes ("\x00"). So we can't used a basic payload like:
```bash
+------------+------------+------------+------------+------------+------------+
|            |            |            |            |            |            |
|   ADDR+4   |    ADDR    |   %1234c   |   %8$hn    |   %1234c   |   %9$hn    |
|            |            |            |            |            |            |
+------------+------------+------------+------------+------------+------------+
```
This payload can't work because the ADDRess's contain some NULL bytes so the binary is going to stop reading when it get a NULL bytes and our payload will be cut. To bypass this problem, I have reverse the format part and the address part. The final payload look like this:
```bash
+------------+------------+------------+------------+------------+------------+------------+------------+------------>
|            |            |            |            |            |            |            |            |            >
|   %1234c   |   %8$hn    |   %1234c   |   %9$hn    |   %1234c   |   %10$hn   |   %1234c   |   %11$hn   |    ADDR    >
|            |            |            |            |            |            |            |            |            >
+------------+------------+------------+------------+------------+------------+------------+------------+------------>

<------------+------------+------------+
<            |            |            |
<   ADDR+2   |   ADDR+4   |   ADDR+6   |
<            |            |            |
<------------+------------+------------+
```

I have choosen to write my address 2 bytes by 2 bytes because I would like to be able to write the address in only one loop tour. But after did it, it would be better to write my address byte by byte in many loop tour because the exploit is not very optimized and if the bytes of the address that I have to write don't make a cascade, the exploit will fail. So that's needed to run multiple times the exploit to make it works. (One improvement for this exploit should be to improve this part)

For the address overwrite, I have chosen to overwrite the "fclose" GOT entry. fclose() is called when the password authentication is good so the binary open/read the file which contain the flag and then close it using fclose(). After many test, this function was one of these who respect the condition: [rsp+0x30] == 0
For example the following functions don't respect this condition: puts, fread, fopen.

# Binary exploitation
To summarize the final exploit, we are going to:
- Leak the puts() address,
- Calculate the Magic Gadget address's thanks to the leaked one,
- Overwrite the "fclose" GOT entry with the Magic Gadget entry,
- Send the good password to the service to trigger the exploit,
- Have fun!

Let's test the result:

![Exploit test](/assets/media/exploit_test.png)

Done.

Ps: One more time, I can't give you the exploit because it will leak the solution.

# Correction
To correct the whole vulnerability it is very simple, the developer has only to add a format to the call to printf(), like this:
```c
printf(password);           // Bad
printf("%s", password);     // Good
```

# Thanks
I would like to thanks the Sec-IT company for allowing me to post this write-up and also thanks you very much to the author of this very interesting challenge. :)

# References
- More details about ELF file format, how binary's are loaded into memory, etc.

[https://www.cs.stevens.edu/~jschauma/810/elf.html](https://www.cs.stevens.edu/~jschauma/810/elf.html)

- More details about LibC Magic Gadgets.

[https://kimiyuki.net/blog/2016/09/16/one-gadget-rce-ubuntu-1604/](https://kimiyuki.net/blog/2016/09/16/one-gadget-rce-ubuntu-1604/)