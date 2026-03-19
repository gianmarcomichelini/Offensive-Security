#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((noreturn)) static void win(void) {
    puts("Nice! You found the secret admin page!");
    system("/bin/sh");
    _exit(0);
}

static void vuln(void) {
    char buf[64];

    puts("What's your name?");

    (void)read(STDIN_FILENO, buf, 256);

    puts("Thanks!");
}

int main(void) {
    setup();
    puts("Welcome to the guestbook!");
    vuln();
    return 0;
}
