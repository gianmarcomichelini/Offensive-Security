## Neon Dinner - ret2plt

The first practical examination of these concepts involves the Neon Diner challenge, which is located at the directory path `lab_03_ret2libc/materiale/challenges/00_ret2plt/`. This specific directory contains both the executable binary named `ret2plt` and its corresponding source code file `main.c`. The vulnerability within this program stems from reading a customer order into a localized 64 byte stack buffer while erroneously accepting an input of up to 256 bytes, thereby enabling a substantial buffer overflow. The primary objective of this exercise is to construct a payload that invokes the `system("/bin/sh")` command utilizing the existing Procedure Linkage Table, given that the `system` function is already present in the table and the string `/bin/sh` is securely embedded within the data section of the binary.

### Dynamic Buffer Analysis and Instruction Pointer Corruption

A comprehensive dynamic analysis of the Neon Diner binary requires utilizing the GNU Debugger augmented with the `pwndbg` extension to observe the exact memory corruption process during execution. An analyst initiates this procedure by generating a deterministic, non repeating sequence of characters using the `cyclic 200` command. This specific De Bruijn sequence is subsequently provided to the standard input stream when the application presents its prompt, deliberately exceeding the allocated 64 byte stack buffer. Because the program utilizes an insecure function to process the customer order, it continues writing the cyclical data linearly up the stack, sequentially overwriting adjacent memory structures, including the saved base pointer and the critical return address.

When the vulnerable function concludes its execution and executes the final `ret` instruction, the processor attempts to pop the saved return address from the stack into the instruction pointer register, designated as RIP. By examining the debugger output at the precise moment of the segmentation fault, one observes that the RIP register has been corrupted with the hexadecimal value `0x6161617461616173`, which corresponds directly to the ASCII substring `saaataaa`. The processor triggers a `SIGSEGV` because it attempts to fetch executable instructions from this invalid, unmapped memory region. Concurrently, the base pointer register, designated as RBP, contains the value `0x6161617261616171`, corresponding to the preceding substring `qaaaraaa`. Furthermore, the stack pointer register, designated as RSP, now points to the memory address `0x7fffffffe340`, which holds the subsequent continuation of the injected cyclic pattern beginning with `uaaavaaawaaa`.

> The exact point of control flow hijacking is mathematically determined by passing the corrupted instruction pointer value into the `cyclic -l <RIP-value>` algorithm, which precisely calculates the required padding length to reach the return address.

Given that the substring `saaataaa` caused the instruction pointer violation, passing this value into the calculation algorithm yields an exact offset of 72 bytes. This foundational metric dictates the structural padding required for the final exploit payload.

### ROP Chain Assembly and Execution Strategy

Having successfully calculated the exact offset required to seize control of the instruction pointer, an attacker must assemble a Return Oriented Programming chain utilizing the internal structures of the binary. Because the No eXecute mitigation strictly forbids the execution of shellcode injected into the data buffers, the payload must pivot execution toward the existing Procedure Linkage Table. The `checksec` utility confirms that the Position Independent Executable mitigation is disabled, ensuring that the memory addresses of the Procedure Linkage Table, the internal binary symbols, and the statically embedded data strings remain absolutely fixed and reliable across multiple executions.

The exploitation strategy relies on locating three specific memory addresses within the executable file, utilizing tools such as `nm`, `objdump`, and the `ELF` module provided by the `pwntools` framework. The first essential component is a `pop rdi; ret` gadget, which is conveniently provided in this specific binary as a helper symbol, serving the purpose of loading the subsequent stack value into the first argument register according to the System V calling convention. The second component is the fixed memory address of the `/bin/sh` string, securely embedded within the read only data section of the binary. The third component is the address of the `system` function stub located directly within the Procedure Linkage Table. Finally, an analyst must append an isolated `ret` gadget immediately before the `pop rdi; ret` sequence to ensure the stack remains strictly aligned to a 16 byte boundary, thereby preventing unexpected crashes within the standard C library during the invocation of the `system` function.

```Python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./ret2plt', checksec=False)
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

OFFSET_TO_RIP = 72

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── gadget discovery ──────────────────────────────────────────────────────
    pop_rdi = exe.sym.pop_rdi_ret
    binsh = next(exe.search(b'/bin/sh\x00'))
    ret = ROP(exe).find_gadget(['ret']).address

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(ret),
        p64(pop_rdi),
        p64(binsh),
        p64(exe.plt.system)
    )

    r.recvuntil(b'order?\n')
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```
