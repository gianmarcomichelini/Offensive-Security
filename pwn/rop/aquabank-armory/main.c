#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((naked, used)) void pop_rdi_ret(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked, used)) void pop_rsi_ret(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked, used)) void pop_rdx_ret(void) { __asm__("pop %rdx; ret"); }
__attribute__((naked, used)) void syscall_ret(void) { __asm__("syscall; ret"); }

static void vuln(void) {
    char buf[64];

    puts("[armory] Storeroom open -- pick your weapons:");
    (void)read(STDIN_FILENO, buf, 512);
    puts("[armory] Locking down.");
}

int main(void) {
    setup();
    vuln();
    return 0;
}
