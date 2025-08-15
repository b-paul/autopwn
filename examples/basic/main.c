#include <stdio.h>
#include <stdlib.h>

int win(void) {
    system("cat flag.txt");
}

int main(void) {
    char buf[80];

    fgets(buf, 200, stdin);
}
