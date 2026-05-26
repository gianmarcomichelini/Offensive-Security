#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NOTE_MAX 96

static char note[NOTE_MAX];

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void banner(void) {
    puts("=== Welcome to AquaBank ATM, v4.0 ===");
    puts("Set a customer note, then withdraw at your convenience.");
}

static void set_note(void) {
    printf("Type your customer note: ");
    fflush(stdout);
    if (!fgets(note, sizeof(note), stdin)) return;
    note[strcspn(note, "\n")] = 0;
    puts("Saved.");
}

static void print_note(void) {
    puts("--- Your customer note ---");
    printf(note);
    puts("");
    puts("--------------------------");
}

static void withdraw(void) {
    char from[32];
    char amount[32];
    char memo[64];

    printf("From account: ");  fflush(stdout); fgets(from,   sizeof(from),   stdin);
    printf("Amount: ");        fflush(stdout); fgets(amount, sizeof(amount), stdin);
    puts("Withdrawal memo (be brief):");

    fgets(memo, 256, stdin);

    printf("Queued withdrawal from %samount %s\n", from, amount);
}

static void menu(void) {
    char line[16];
    while (1) {
        puts("");
        puts("=== AquaBank ATM ===");
        puts("1) Set customer note");
        puts("2) Print customer note");
        puts("3) Withdraw");
        puts("4) Exit");
        printf("> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        switch (atoi(line)) {
            case 1: set_note();    break;
            case 2: print_note();  break;
            case 3: withdraw();    break;
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
