#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

struct Slot {
    void (*display)(struct Slot *);
    char  label[24];
};

static void default_display(struct Slot *s) {
    printf("[slot] %.*s\n", 24, s->label);
}

void win(struct Slot *s) {
    (void)s;
    char *env = getenv("FLAG");
    if (env) puts(env);
    else     puts("FLAG env var not set");
    _exit(0);
}

int main(void) {
    setup();

    char        *note = malloc(64);
    struct Slot *slot = malloc(sizeof(struct Slot));
    slot->display = default_display;
    strncpy(slot->label, "default-slot", sizeof(slot->label));

    puts("== Inventory Slot ==");
    printf("content: ");
    (void)read(STDIN_FILENO, note, 0xC0);      

    slot->display(slot);
    return 0;
}
