#include <stdio.h>
#include <stdlib.h>

char *gets(char *s);

int win(void) {
    system("cat flag.txt");
}

int main(void) {
    char buf[80];

    gets(buf);
}
