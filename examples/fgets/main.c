#include <stdio.h>
#include <stdlib.h>

void win(void) {
    system("cat flag.txt");
}

int main(void) {
    char buf[80];
    fgets(buf, 200, stdin);
    return 0;
}
