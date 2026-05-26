#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void banner(void) {
    puts("=== AquaBank Safe Deposit Vault ===");
    puts("Insert your card to issue a receipt or open the vault.");
}

static void print_receipt(void) {
    char buf[64];

    puts("Type the receipt header (up to 64 chars):");
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) return;

    puts("--- RECEIPT ---");
    fwrite(buf, 1, 256, stdout);
    puts("");
    puts("---------------");
}

static void open_vault(void) {
    char combo[128];

    puts("Enter your combination:");
    (void)read(STDIN_FILENO, combo, 512);
    printf("Combination registered: %.32s ...\n", combo);
}

static void menu(void) {
    char line[16];
    while (1) {
        puts("");
        puts("=== AquaBank Vault ===");
        puts("1) Print receipt");
        puts("2) Open vault");
        puts("3) Exit");
        printf("> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        switch (atoi(line)) {
            case 1: print_receipt(); break;
            case 2: open_vault();    return;
            case 3: puts("Bye");     return;
            default: puts("?");
        }
    }
}

int main(void) {
    setup();
    banner();
    menu();
    return 0;
}
