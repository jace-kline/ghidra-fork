#include <stdio.h>

int count_number_calls() {
    static int count = 0;
    return ++count;
}

#define CALLS 10

int main() {
    // random stuff
    int x, y, z;
    x = y = z = 0;
    char c = 'A';

    // count function calls via static local variable
    int counts[CALLS];
    for (int i = 0; i < CALLS; i++) {
        counts[i] = count_number_calls();
    }

    for (int i = 0; i < CALLS; i++) {
        counts[i] = count_number_calls();
        printf("%d\n", counts[i]);
    }

    return 0;
}