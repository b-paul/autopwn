#include <stdio.h>

void print_flag() {
        FILE *f = fopen("flag.txt", "r");
        char flag[200];
        fgets(flag, 199, f);
        puts(flag);
}

int main() {
        char buf[200];
        fgets(buf, 199, stdin);
        if (buf[0] == 'f' && buf[1] == 'l' && buf[2] == 'a' && buf[3] == 'g') {
                print_flag();
        }
        return 0;
}
