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

static void keep_system_imported(void) {
    volatile char *x = getenv("DONT_RUN");
    if (x) {
        system("/bin/true");
    }
}

static const char *binsh = "/bin/sh";

static void vuln(void) {
    char buf[64];

    puts("What would you like to order?");
    (void)read(STDIN_FILENO, buf, 256);
    puts("Coming right up!");
}

int main(void) {
    setup();
    keep_system_imported();

    puts("Welcome to the Cosmic Cafe!");
    vuln();
    return 0;
}
