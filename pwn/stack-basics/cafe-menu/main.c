#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((noreturn)) static void win(void) {
    puts("Chef's special unlocked!");
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    _exit(0);
}

static void vuln(void) {
    struct {
        char menu[48];
        volatile unsigned int idx;
    } data;

    data.idx = 0;

    printf("Enter today's specials (send 0xff to finish):\n");

    while (data.idx < 200) {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) break;
        if ((unsigned char)c == 0xff) break;
        data.menu[data.idx] = c;
        data.idx++;
    }

    printf("Menu updated!\n");
}

int main(void) {
    setup();
    printf("Welcome to the Cafe!\n");
    vuln();
    return 0;
}
