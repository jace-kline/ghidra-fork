#include <stdio.h>
#include <stdbool.h>

#define ARRSIZE 10

void swap(int * l, int * r);
void reverse_arr(int * arr, int size);

int main() {
    int myarr[ARRSIZE];

    for(int i = 0; i < ARRSIZE; i++) {
        myarr[i] = i;
    }

    reverse_arr(myarr, ARRSIZE);

    for(int i = 0; i < ARRSIZE; i++) {
        printf("%d ", myarr[i]);
    }
}

void reverse_arr(int* arr, int size) {
    bool odd = size % 2 != 0;
    int i = 0;
    int j = size - 1;
    while(i < j) {
        swap(&arr[i], &arr[j]);
        i++;
        j--;
    }
}

void swap(int* l, int* r) {
    int tmp = *l;
    *l = *r;
    *r = tmp;
}