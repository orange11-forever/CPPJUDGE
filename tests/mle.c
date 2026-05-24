#include <stdlib.h>
#include <string.h>

int main() {
    size_t sz = 128 * 1024 * 1024;  /* 128 MB */
    void *p = malloc(sz);
    if (p) memset(p, 0, sz);
    return 0;
}
