int main() {
    volatile int a = 1, b = 0;
    volatile int c = a / b;
    return 0;
}