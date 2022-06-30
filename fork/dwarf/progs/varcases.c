#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#define BUFSIZE 32

int globalvar_uninit;
int globalvar_init = 0;

struct mystruct {
    int a;
    int b;
    int c;
};

union myunion {
    int x;
    char c;
    double f;
    char msg[BUFSIZE];
};

int main(int argc, char* argv[]) {

    if(argc < 3) {
        printf("Usage: %s <num> <msg>", argv[0]);
        exit(1);
    }

    union myunion u;
    struct mystruct s = { 1, 2, 3 };

    if(strlen(argv[2]) > BUFSIZE) {
        printf("Input message too long!");
        exit(1);
    }

    // copy the <msg> string to the union
    strcpy(u.msg, argv[2]);

    // store the <num> input to all int locations
    int stackvar = 0;
    int * heapint = (int *) malloc(sizeof(int));
    stackvar = *heapint = globalvar_init = globalvar_uninit = s.a = s.b = s.c = atoi(argv[1]);

    printf("num = %d\n", stackvar);
    printf("msg = '%s'", u.msg);
    free(heapint);

    return 0;
}