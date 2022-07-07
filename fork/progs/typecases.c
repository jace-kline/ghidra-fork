#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#define BUFSIZE 32
#define ARRSIZE 10

// globals
int globalvar_uninit;
int globalvar_init = 0;

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

// void return function
// typedef argument
// void typedef return
myvoid hello(int_t v) {
    printf("Hello, World! Number is %d\n", v);
}

myvoid2 hello2(int_t2 v) {
    printf("Hello, World! (2) Number is %d\n", v);
}

// recursive function with struct pointer as arg
int myrecfunc(struct mystruct * s) {
    if(s == NULL) {
        return 0;
    }

    // recursively add
    int_t2 sum = s->a + s->b + s->c + myrecfunc(s->next);
}

int main(int argc, char* argv[]) {

    if(argc < 3) {
        printf("Usage: %s <num> <msg>", argv[0]);
        exit(1);
    }

    // instantiate union, enum
    union myunion u;
    enum myenum e = A;

    // recursive struct
    struct mystruct s_next2 = { A*B, A*C, B*C, NULL };
    struct mystruct s_next = { C, B, A, &s_next2 };
    struct mystruct s = { A, B, C, &s_next };

    // 1D array
    int my1Darr[ARRSIZE];

    // 2D array
    int my2Darr[ARRSIZE][ARRSIZE];

    // fill arrays
    for (int i = 0; i < ARRSIZE; i++) {
        my1Darr[i] = i;
        for (int j = 0; j < ARRSIZE; j++) {
            my2Darr[i][j] = i * j;
        }
    }


    if(strlen(argv[2]) > BUFSIZE) {
        printf("Input message too long!");
        exit(1);
    }

    // copy the <msg> string to the union
    strcpy(u.msg, argv[2]);

    // store the <num> input to all int locations
    int stackvar = 0;

    // pointer type
    int * heapint = (int *) malloc(sizeof(int));
    stackvar = *heapint = globalvar_init = globalvar_uninit = s.a = s.b = s.c = atoi(argv[1]);

    printf("num = %d\n", stackvar);
    printf("msg = '%s'\n", u.msg);

    // call a recursive function
    // typedef result
    int_t sum = myrecfunc(&s);
    printf("sum of mystructs = %d\n", sum);

    // call void function
    hello(stackvar);

    free(heapint);

    return 0;
}