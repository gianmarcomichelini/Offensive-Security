#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

#define N_ITEMS 8

struct Item {
    void (*action)(struct Item *);
    char  data[24];
};

static struct Item *items[N_ITEMS] = {0};

static void default_action(struct Item *it) {
    printf("[item] %.*s\n", 24, it->data);
}

void win(struct Item *it) {
    (void)it;
    char *env = getenv("FLAG");
    if (env) puts(env);
    else     puts("FLAG env var not set");
    _exit(0);
}

static int read_choice(void) {
    char line[32] = {0};
    if (!fgets(line, sizeof(line), stdin)) _exit(0);
    return atoi(line);
}

static int read_index(void) {
    printf("index: ");
    int i = read_choice();
    if (i < 0 || i >= N_ITEMS) return -1;
    return i;
}

int main(void) {
    setup();

    puts("== Recycler ==");

    while (1) {
        puts("");
        puts("1. create");
        puts("2. free");
        puts("3. edit");
        puts("4. invoke");
        puts("5. exit");
        printf("> ");

        switch (read_choice()) {
        case 1: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            items[i] = malloc(sizeof(struct Item));
            items[i]->action = default_action;
            printf("data: ");
            (void)read(STDIN_FILENO, items[i]->data, sizeof(items[i]->data));
            puts("[+] created.");
            break;
        }
        case 2: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            free(items[i]);                      
            puts("[+] freed.");
            break;
        }
        case 3: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            printf("payload: ");
            (void)read(STDIN_FILENO, items[i], sizeof(struct Item));
            puts("[+] edited.");
            break;
        }
        case 4: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            if (items[i]) items[i]->action(items[i]);
            else          puts("[-] empty slot.");
            break;
        }
        case 5:
            return 0;
        default:
            puts("[-] invalid choice.");
        }
    }
}
