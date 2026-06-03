#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

struct User {
    void (*action)(struct User *);
    char  name[24];
};

static void lose(struct User *u) {
    printf("[*] Goodbye, %.*s.\n", 24, u->name);
}

void win(struct User *u) {
    (void)u;
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

int main(void) {
    setup();

    struct User *user = NULL;
    char *data = NULL;

    puts("== Account Vault ==");

    while (1) {
        puts("");
        puts("1. Allocate User");
        puts("2. Free User");
        puts("3. Allocate Data");
        puts("4. Execute Action");
        puts("5. Exit");
        printf("> ");

        switch (read_choice()) {
        case 1:
            user = malloc(sizeof(struct User));
            user->action = lose;
            strncpy(user->name, "Guest", sizeof(user->name));
            puts("[+] User allocated.");
            break;
        case 2:
            free(user);                              
            puts("[+] User freed.");
            break;
        case 3:
            data = malloc(sizeof(struct User));
            printf("data: ");
            read(STDIN_FILENO, data, sizeof(struct User));
            puts("[+] Data allocated.");
            break;
        case 4:
            if (user) user->action(user);
            else      puts("[-] No user.");
            break;
        case 5:
            return 0;
        default:
            puts("[-] Invalid choice.");
        }
    }
}
