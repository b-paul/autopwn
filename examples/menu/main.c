#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *gets(char *s);

void win(void) {
    system("cat flag.txt");
}

int menu(void) {
    puts("");
    puts("== Menu ==");
    puts("1) Greet");
    puts("2) Change username");
    puts("3) Exit");

    int choice = 0;
    while (choice < 1 || choice > 3) {
        printf("Choice: ");
        fflush(stdout);
        while (scanf("%d", &choice) != 1) {
            printf("Choice: ");
            fflush(stdout);
        }
    }

    return choice;
}

int main(void) {
    char name[100];

    printf("Name: ");
    fflush(stdout);
    fgets(name, 100, stdin);
    name[strlen(name) - 1] = 0;

    int choice;
    while ((choice = menu()) != 3) {
        if (choice == 1) {
            printf("Hello, ");
            printf(name);
            puts("!");
        } else if (choice == 2) {
            printf("Name: ");
            getchar();
            gets(name);
        }
    }

    puts("Cya!");
    return 0;
}
