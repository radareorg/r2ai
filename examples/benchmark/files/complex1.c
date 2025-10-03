#include <stdio.h>
#include <stdlib.h>

int main() {
    int n = 5;
    int *arr = (int *)malloc(n * sizeof(int));
    if (arr == NULL) return 1;
    for (int i = 0; i < n; i++) {
        arr[i] = i * i;
    }
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
        for (int j = 0; j < i; j++) {
            sum -= j;
        }
    }
    printf("Sum: %d\n", sum);
    free(arr);
    return 0;
}