#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

#define N_NOTES   8
#define NOTE_SIZE 0x60   

static char *notes[N_NOTES] = {0};

void (*global_handler)(const char *) = NULL;

static void default_handler(const char *s) {
    printf("[handler] %s\n", s);
}

void win(const char *s) {
    (void)s;
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
    if (i < 0 || i >= N_NOTES) return -1;
    return i;
}

int main(void) {
    setup();
    global_handler = NULL;
    (void)default_handler;

    puts("== Notebook ==");

    while (1) {
        puts("");
        puts("1. create");
        puts("2. free");
        puts("3. edit");
        puts("4. show");
        puts("5. trigger");
        puts("6. exit");
        printf("> ");

        switch (read_choice()) {
        case 1: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            notes[i] = malloc(NOTE_SIZE);
            printf("data: ");
            (void)read(STDIN_FILENO, notes[i], NOTE_SIZE);     
            puts("[+] created.");
            break;
        }
        case 2: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            free(notes[i]);                                  
            puts("[+] freed.");
            break;
        }
        case 3: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            printf("data: ");
            (void)read(STDIN_FILENO, notes[i], NOTE_SIZE);    
            puts("[+] edited.");
            break;
        }
        case 4: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            (void)write(STDOUT_FILENO, notes[i], 0x10);        
            puts("");
            break;
        }
        case 5:
            if (global_handler) global_handler("hello");
            else                puts("[-] no handler set.");
            break;
        case 6:
            return 0;
        default:
            puts("[-] invalid choice.");
        }
    }
}
