#include <stdio.h>
#include <stdlib.h>

int main(char argc, char ** argv) {

    const int size = 10;
    int arr[10];

    for(int i = 0; i < size; i++) {
        arr[i] = i;
        printf("arr[%d] = %d\n", i, arr[i]);
    }

    int sum = 0;
    for(int i = 0; i < size; i++) {
        sum += arr[i];
    }

    printf("sum(arr) = %d\n", sum);

    return 0;
}
