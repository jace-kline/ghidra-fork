#include <stdio.h>
#include <stdlib.h>

int main(char argc, char ** argv) {

    if(argc != 2) {
        printf("Usage: %s <arrsize>", argv[0]);
        exit(1);
    }

    int size = atoi(argv[1]);

    if(size < 1) {
        printf("Error: size input must be positive");
        exit(1);
    }

    int arr[size];

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