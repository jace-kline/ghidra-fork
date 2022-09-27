
struct A;
struct B;
struct C;
union U;

typedef struct A {
    int x;
    int y;
    int z;
    struct B * b;
} A;

typedef struct B {
    char q;
    char r;
    char s;
    struct A * a;
} B;

typedef struct C {
    int n1;
    struct C ** c;
} C;

typedef union U {
    int x;
    int y;
    int z;
    union U * u;
} U;

int main() {
    struct A a;
    a.x = a.y = a.z = 0;

    struct B b;
    b.q = b.r = b.s = 'a';

    a.b = &b;
    b.a = &a;

    struct C c;
    c.n1 = 0;
    struct C * cptr = &c;
    c.c = &cptr;

    union U u0;
    u0.x = 0;

    union U u1;
    u1.u = &u0;

    return 0;
}