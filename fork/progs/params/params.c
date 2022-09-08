#include <stdio.h>

int myfunc(int a, int b) {
    return a + b;
}

int main(int argc, char ** argv) {
    int res = myfunc(argc, argc);
    printf("%s: params * 2 = %d", argv[0], res);
    return 0;
}