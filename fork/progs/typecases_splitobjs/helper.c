#include <stdio.h>
#include <stdlib.h>

#include "helper.h"

// function implementations

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