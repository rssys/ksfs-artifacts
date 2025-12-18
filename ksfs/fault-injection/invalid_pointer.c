int main() {
    *(volatile int *)(-1) = 0;
    return 0;
}