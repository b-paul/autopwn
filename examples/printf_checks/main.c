#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *gets(char *s);

void win(void) {
    system("cat flag.txt");
}

int main(void) {
    char buf[100];

    printf("Username: ");
    fflush(stdout);
    gets(buf);

    printf("Welcome ");
    printf(buf);
    puts("!");

    printf("Password: ");
    gets(buf);

    if (strcmp(buf, "s3cr3t_p4s5w0rd") != 0) {
        puts("Unauthorized access detected!");
        exit(1);
    } else {
        puts("Authenticated successfully");
    }

    return 0;
}
