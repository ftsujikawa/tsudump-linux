#include <stdio.h>

extern void func();

int main() {
    char str[] = "Hello, World!";
    printf("%s\n", str);
    func();
    return 0;
}