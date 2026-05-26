#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}


char vault[256];

__attribute__((naked, used)) void pop_rdi_ret(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked, used)) void pop_rsi_ret(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked, used)) void pop_rdx_ret(void) { __asm__("pop %rdx; ret"); }
__attribute__((naked, used)) void ret_gadget(void)  { __asm__("ret"); }

__attribute__((naked, used))
void add_what_where(void) {
    __asm__("add %rsi, (%rdi); ret");
}

static void vuln(void) {
    char buf[64];

    printf("[padlock] Decimal combination: ");
    (void)read(STDIN_FILENO, buf, 512);

    int n = atoi(buf);
    printf("[padlock] In hex that is 0x%x. Click.\n", (unsigned)n);
}

int main(void) {
    setup();
    printf("[padlock] Welcome to the vault. No leaks today.\n");
    vuln();
    return 0;
}
