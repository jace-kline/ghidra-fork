#include <stdio.h>

#define ARRSIZE 10

int main(int argc, char ** argv) {

    int _1darray[ARRSIZE] = { 0 };

    int _2darray[ARRSIZE][ARRSIZE] = { 0 };

    int _3darray[ARRSIZE][ARRSIZE][ARRSIZE] = { 0 };

    printf("Size of _1darray = %ld\n", sizeof(_1darray));
    printf("Size of _2darray = %ld\n", sizeof(_2darray));
    printf("Size of _3darray = %ld\n", sizeof(_3darray));

    return 0;
}