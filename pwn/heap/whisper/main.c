#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

#define N_NOTES 16

struct Note {
    char  *content;
    size_t size;
};

static struct Note notes[N_NOTES] = {0};

static int read_int(void) {
    char line[32] = {0};
    if (!fgets(line, sizeof(line), stdin)) _exit(0);
    return atoi(line);
}

static int read_index(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= N_NOTES) return -1;
    return i;
}

int main(void) {
    setup();

    puts("== Whisper ==");
    puts("A vault of notes. Whispers leak when chunks fall into the wrong bin.");

    while (1) {
        puts("");
        puts("1. create");
        puts("2. delete");
        puts("3. edit");
        puts("4. show");
        puts("5. exit");
        printf("> ");

        switch (read_int()) {
        case 1: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            printf("size: ");
            size_t sz = (size_t)read_int();
            if (sz == 0 || sz > 0x800) { puts("[-] bad size"); break; }
            notes[i].content = malloc(sz);
            notes[i].size    = sz;
            printf("data: ");
            (void)read(STDIN_FILENO, notes[i].content, sz);    
            puts("[+] created.");
            break;
        }
        case 2: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            free(notes[i].content);                        
            puts("[+] deleted.");
            break;
        }
        case 3: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            printf("data: ");
            (void)read(STDIN_FILENO, notes[i].content, notes[i].size);
            puts("[+] edited.");
            break;
        }
        case 4: {
            int i = read_index();
            if (i < 0) { puts("[-] bad index"); break; }
            (void)write(STDOUT_FILENO, notes[i].content, 0x10);  
            puts("");
            break;
        }
        case 5:
            return 0;
        default:
            puts("[-] invalid choice.");
        }
    }
}
