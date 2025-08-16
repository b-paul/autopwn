#include <stdio.h>
#include <stdlib.h>

char *gets(char *s);

void win(void) {
    system("cat flag.txt");
}

int main(void) {
    char buf[100];
    gets(buf);
    return 0;
}
