#include <stdio.h>
#include <stdlib.h>

#define PASSWORD "password"

char *gets(char *s);

int main(void) {
    char buf[100];

    puts("Checking permissions...");
    printf("You are ");
    fflush(stdout);
    system("whoami");

    printf("Enter your request: ");
    fflush(stdout);
    gets(buf);

    puts("Your feedback has been forwarded");

    return 0;
}
