#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

__attribute__((noinline))
void win(void) {
    char *flag = getenv("FLAG");
    puts(flag);
    fflush(stdout);
    _exit(0);
}

__attribute__((noinline))
void vuln(void) {
    char buf[64];

    puts("=== Polly's Parrot Cage ===\n"
         "Polly repeats everything you say!\n"
         "Type a message and Polly will squawk it back.\n"
         "Say 'bye' when you're done chatting.\n");
    fflush(stdout);

    for (;;) {
        ssize_t n = read(STDIN_FILENO, buf, 0x200);
        if (n < 0) {
            perror("read");
            exit(1);
        }
        if (n == 0) {
            break;
        }
        if (n >= 3 && buf[0] == 'b' && buf[1] == 'y' && buf[2] == 'e') {
            break;
        }
        puts(buf);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    puts("Polly says goodbye! *squawk*");
    return 0;
}
