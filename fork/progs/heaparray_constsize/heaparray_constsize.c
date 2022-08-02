#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

int main(char argc, char ** argv) {

    size_t size = 10;

    int * arr = malloc(size * sizeof(int));

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

// undefined8 main(void)

// {
//   void *pvVar1;
//   uint local_24;
//   uint local_20;
//   uint local_1c;
  
//   pvVar1 = malloc(0x28);
//   for (local_24 = 0; local_24 < 10; local_24 = local_24 + 1) {
//     *(uint *)((long)(int)local_24 * 4 + (long)pvVar1) = local_24;
//     printf("arr[%d] = %d\n",(ulong)local_24,(ulong)*(uint *)((long)pvVar1 + (long)(int)local_24 * 4)
//           );
//   }
//   local_20 = 0;
//   for (local_1c = 0; local_1c < 10; local_1c = local_1c + 1) {
//     local_20 = local_20 + *(int *)((long)pvVar1 + (long)(int)local_1c * 4);
//   }
//   printf("sum(arr) = %d\n",(ulong)local_20);
//   return 0;
// }