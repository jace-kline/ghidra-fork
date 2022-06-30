#include <stdio.h>
#include <stdlib.h>

int main(char argc, char ** argv) {

    size_t size = 10;

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

// undefined8 main(undefined param_1,undefined8 param_2)

// {
//   uint uVar1;
//   undefined8 *puVar2;
//   ulong uVar3;
//   long in_FS_OFFSET;
//   undefined8 local_58;
//   undefined local_4c;
//   int local_44;
//   uint local_40;
//   uint local_3c;
//   ulong local_38;
//   undefined8 local_30;
//   undefined *local_28;
//   long local_20;
  
//   local_58 = param_2;
//   local_4c = param_1;
//   local_20 = *(long *)(in_FS_OFFSET + 0x28);
//   local_38 = 10;
//   local_30 = 9;
//   for (puVar2 = &local_58; puVar2 != &local_58; puVar2 = (undefined8 *)((long)puVar2 + -0x1000)) {
//     *(undefined8 *)((long)puVar2 + -8) = *(undefined8 *)((long)puVar2 + -8);
//   }
//   *(undefined8 *)((long)puVar2 + -8) = *(undefined8 *)((long)puVar2 + -8);
//   local_28 = (undefined *)((long)puVar2 + -0x30);
//   for (local_3c = 0; (ulong)(long)(int)local_3c < local_38; local_3c = local_3c + 1) {
//     *(uint *)(local_28 + (long)(int)local_3c * 4) = local_3c;
//     uVar1 = *(uint *)(local_28 + (long)(int)local_3c * 4);
//     uVar3 = (ulong)local_3c;
//     *(undefined8 *)((long)puVar2 + -0x38) = 0x101285;
//     printf("arr[%d] = %d\n",uVar3,(ulong)uVar1);
//   }
//   local_40 = 0;
//   for (local_44 = 0; (ulong)(long)local_44 < local_38; local_44 = local_44 + 1) {
//     local_40 = local_40 + *(int *)(local_28 + (long)local_44 * 4);
//   }
//   uVar3 = (ulong)local_40;
//   *(undefined8 *)((long)puVar2 + -0x38) = 0x1012d9;
//   printf("sum(arr) = %d\n",uVar3);
//   if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
//     return 0;
//   }
//                     /* WARNING: Subroutine does not return */
//   __stack_chk_fail();
// }