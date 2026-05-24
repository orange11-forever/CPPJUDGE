int main() {
    int *p = (int*)0xDEADBEEF;
    *p = 42;
    return 0;
}
