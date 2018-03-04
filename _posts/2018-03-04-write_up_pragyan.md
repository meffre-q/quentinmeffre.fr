---
layout: post
title: "[Write-Up] Pragyan CTF - Old school hack"
categories: [write-up]
tags: [pwn]
---
**Points:** 200 **Category:** Pwn **Description:**  Chris is trying out to be a police officer and the applications have just been sent into the police academy. He is really eager to find out about his competition. Help it him back the system and view the other applicant’s applications.

# Surroundings
This week-end took place the [Pragyan CTF](https://www.pragyan.org/18/home/). This Write-Up is going to show you how to solve the "Old school hack" pwnable challenges. This challenge was interesting because it was a mix between a wargame challenge and a classic exploit.

# Challenge
This challenge is provided with a binary and an pair of IP/port. After a quick test, the binary is running into the given server.

Let first begin by recover many informations of our binary:

![Check_binary](/assets/media/pragyan_infos.png)

We can get the following informations:
- The binary is an ELF, compiled for x86_64 architecture,
- It is linked dynamically,
- It is not stripped,

The following protections are enabled:
- Partial REad onLy RelOcation,
- Stack smash protection (canary),
- No eXec stack.

Let's try to execute it now:

![First try](/assets/media/pragyan_first_try.png)

The binary start by asking a password. Using ltrace command, we can find the password: kaiokenx20

Now let's taking a look at the assembly code using IDA:

![First ida](/assets/media/pragyan_first_ida.png)

The last image represent the main() function. We can see two important informations:
- The service password is well the one we get using ltrace,
- There is a buffer overflow at the call of scanf().

We can't exploit the buffer overflow because the binary has canary and so on we are going to have a stack smash error if we overflow it.

But as you can see on the last image, we can overflow some data which are one the stack using our buffer overflow. Especially we can overwrite the "var_30" of the stack which represent the name of a file which is going to be read later by the binary.

Using this vulnerability, we are able to read every file that we know the name. But before being able to do this, we have several condition to bypass:

- Firstly, we don't know the name of the file which contain our flag.
- Secondly, we are going to see that the data that we overwrite are overwrite later by the binary.
- Thirdly, the filename must has a size equal to 36.

But all this condition are easy to bypass! :)

The first one:

![First condition](/assets/media/pragyan_first_condition.png)

As you can see on the last image, the binary display some text on its output which represent different entry of a menu, then ask for a number on its input and then it jump to a piece of code depending of the user input. (Like a switch statement in C language) Every piece of code overwrite the filename we write using our buffer overflow so we must not enter in this function. The switch has a default value, if the user input doesn't match with a number between the value '1' and '7' the binary jump to next step without overwriting our filename!

So we just have to enter a value which respect this conditon: value >= 8

It's ok for the first step.

Now the second step is very easy. If we check the assembly code, we can see the following:

![Second condition](/assets/media/pragyan_second_condition.png)

If the user enter 7 for the menu entry, the binary set the filename to "txt.galf" (which is flag.txt in reverse) then display something on the output and finish by a call to exit().

Let's try to used "flag.txt" as filename.

But before getting the flag, we have a last condition to fulfill:

![Third condition](/assets/media/pragyan_third_condition.png)

The last image represent the beginning of the function which display the content of the filename we overwrite. As you can see, there is a comparaison between the size of our filename. If our filename doesn't has a size equal to 36 bytes, the binary raise an error.

As our filename "flag.txt" only has a size of 8 bytes, we have a problem....

But we can simply bypass it using the "./" path which represent the current directory on a Linux system.

So our filename is going to look like this: ././././././././././././././flag.txt

Here is the very little "exploit" (aka command) I used to solve this challenge:
```bash
#!/bin/sh
python -c 'print "kaiokenx20\x00"+"A"*5+"././././././././././././././flag.txt\x00\n"+"123"'|nc 128.199.224.175 13000
```

Now let's try it:

![Done](/assets/media/pragyan_flag.png)

Done.
