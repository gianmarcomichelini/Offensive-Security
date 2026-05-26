#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((naked)) void pop_rdi_ret(void) {
    __asm__("pop %rdi; ret");
}

static const char *binsh = "/bin/sh";

static void vuln(void) {
    char buf[64];

    puts("What book are you looking for?");
    (void)read(STDIN_FILENO, buf, 256);
    puts("Let me check the catalog...");
}

int main(void) {
    setup();

    puts("Welcome to the Tiny Library!");
    vuln();

    if (binsh == NULL) {
        puts("impossible");
    }

    return 0;
}
