#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((naked)) void pop_rdi_ret(void) {
    __asm__("pop %rdi; ret");
}

__attribute__((naked)) void pop_rsi_ret(void) {
    __asm__("pop %rsi; ret");
}

__attribute__((naked)) void pop_rdx_ret(void) {
    __asm__("pop %rdx; ret");
}

__attribute__((naked)) void ret_gadget(void) {
    __asm__("ret");
}

char shellcode[0x400];

static void ensure_mprotect_is_linked(void) {
    uintptr_t page = (uintptr_t)shellcode & ~(uintptr_t)0xfff;
    (void)mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE);
}

static void vuln(void) {
    char buf[64];

    puts("[forge] Input:");
    (void)read(STDIN_FILENO, buf, 512);
    puts("[forge] Done.");
}

int main(void) {
    setup();
    ensure_mprotect_is_linked();

    puts("[forge] Send shellcode:");
    (void)read(STDIN_FILENO, shellcode, sizeof(shellcode));

    vuln();
    return 0;
}
