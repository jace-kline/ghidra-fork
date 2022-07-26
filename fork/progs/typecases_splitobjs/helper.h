#ifndef HELPER_H
#define HELPER_H

#define BUFSIZE 32
#define ARRSIZE 10

// structs (recursive)
struct mystruct {
    int a;
    int b;
    int c;
    struct mystruct * next;
};

// unions
union myunion {
    int x;
    char c;
    double f;
    char msg[BUFSIZE];
};

// enums
enum myenum { A, B, C };

// void typedefs
typedef void myvoid;
typedef myvoid myvoid2;

// type defs with multiple levels of aliasing
typedef int int_t;
typedef int_t int_t2;

// function declarations
myvoid hello(int_t);
myvoid2 hello2(int_t2);
int myrecfunc(struct mystruct *);

#endif