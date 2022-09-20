#include <stdio.h>

typedef struct A {
    int a;
    char b;
    int arr[5];
} A;

typedef struct B {
    int x;
    A inner;
} B;

int main() {
    B myarr[5];

    printf("%ld\n%ld\n", (unsigned long) &myarr[0].inner.b, (unsigned long) &myarr[0].inner.arr);

    return 0;
}