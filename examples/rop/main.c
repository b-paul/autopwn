#include <stdio.h>
#include <stdlib.h>

#define PASSWORD "password"

char name[100];

char *gets(char *s);

int main(void) {
    char buf[100];

    printf("My magic number is %d\n", 0xc35f);

    puts("Checking permissions...");
    printf("You are logged in as ");
    fflush(stdout);
    system("whoami");

    printf("Enter your full name: ");
    fflush(stdout);
    fgets(name, 100, stdin);

    printf("Enter your request: ");
    fflush(stdout);
    gets(buf);

    puts("Your feedback has been forwarded");

    return 0;
}
