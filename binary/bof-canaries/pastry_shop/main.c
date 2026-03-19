#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((noreturn)) static void win(void) {
    puts("You found the secret recipe! Here's your prize:");
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    _exit(0);
}

static void greet(void) {
    char name[128];

    puts("What's your name, dear customer?");
    if (!fgets(name, sizeof(name), stdin)) {
        exit(1);
    }

    printf(name);
}

static void vuln(void) {
    char buf[64];

    puts("And what would you like to order?");

    (void)read(STDIN_FILENO, buf, 256);

    puts("Thanks for your order!");
}

int main(void) {
    setup();
    puts("Welcome to the Pastry Shop!");
    greet();
    vuln();
    return 0;
}
