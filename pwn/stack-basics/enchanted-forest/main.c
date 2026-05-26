#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void default_spell(void) {
    puts("Poof! A tiny spark flies out... not very impressive.");
}

__attribute__((noreturn)) static void win(void) {
    puts("Ancient magic awakens! The forest bows to you.");
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    _exit(0);
}

static void vuln(void) {
    struct {
        char incantation[64];
        void (*cast)(void);
    } spell;

    spell.cast = default_spell;

    printf("Whisper your incantation:\n");
    read(STDIN_FILENO, spell.incantation, 128);

    printf("Casting spell...\n");
    spell.cast();
}

int main(void) {
    setup();
    printf("Welcome to the Enchanted Forest!\n");
    vuln();
    return 0;
}
