#include <sys/socket.h>

int main() {
    socket(AF_INET, SOCK_STREAM, 0);  /* blocked by seccomp */
    return 0;
}
