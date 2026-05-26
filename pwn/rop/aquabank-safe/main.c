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
    puts("=== AquaBank Premium Safe ===");
    puts("PIE-protected vault.  No leaks. (Or are there?)");
}

char vault[0x4000];

static void deposit(void) {
    int n;
    printf("[deposit] Vault deposit size (bytes): ");
    if (scanf("%d", &n) != 1) return;
    int c; while ((c = getchar()) != '\n' && c != EOF) {}
    if (n < 0 || n > (int)sizeof(vault)) { puts("bad size"); return; }
    printf("[deposit] Send %d bytes:\n", n);
    (void)read(STDIN_FILENO, vault, n);
    puts("[deposit] Deposit registered.");
}

static void diagnostics(void) {
    printf("[diag] printf @ %p\n", (void*)printf);
    printf("[diag] entry  @ %p\n", (void*)&diagnostics);
}

static void open_safe(void) {
    char buf[8];
    puts("[safe] Enter the 24-byte combination:");
    (void)read(STDIN_FILENO, buf, 24);
}

static void menu(void) {
    char line[16];
    while (1) {
        puts("");
        puts("=== AquaBank Premium Safe ===");
        puts("1) Diagnostics");
        puts("2) Vault deposit");
        puts("3) Open safe");
        puts("4) Exit");
        printf("> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        switch (atoi(line)) {
            case 1: diagnostics(); break;
            case 2: deposit();     break;
            case 3: open_safe();   return;
            case 4: puts("Bye");   return;
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
