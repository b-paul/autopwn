#include <stdio.h>
#include <stdlib.h>

char *gets(char *s);

void win(void) {
    system("cat flag.txt");
}

int main(void) {
    char buf[100];

    fgets(buf, 100, stdin);

    int size = atoi(buf);

    fgets(buf, size, stdin);
    return 0;
}
