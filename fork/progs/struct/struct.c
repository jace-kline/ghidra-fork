#include <stdio.h>

struct A {
    int a;
    char b;
    int c;
};

struct B {
    char x;
    int y;
    char z;
};

int main() {
    struct A myA;
    struct B myB;

    myA.a = myA.c = 10;
    myA.b = 'A';

    myB.x = myB.z = 'A';
    myB.y = 10;

    printf("myA = { a=%d, b=%c, c=%d }\n", myA.a, myA.b, myA.c);
    printf("myB = { x=%c, y=%d, z=%c }\n", myB.x, myB.y, myB.z);

    return 0;
}