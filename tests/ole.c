#include <stdio.h>

int main() {
    for (int i = 0; i < 100000; ++i) {
        printf("line %d: abcdefghijklmnopqrstuvwxyz0123456789\n", i);
    }
    return 0;
}
