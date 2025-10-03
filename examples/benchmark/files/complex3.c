#include <stdio.h>

int main() {
    int x = 42;
    int y = 0;
    switch (x & 15) {
        case 0:
            y = x << 1;
            break;
        case 1:
            y = x >> 1;
            break;
        case 2:
            y = x ^ 255;
            break;
        case 3:
            y = ~x;
            break;
        default:
            y = x | 128;
            break;
    }
    if ((y & 1) == 0) {
        y += 10;
    } else {
        y -= 5;
    }
    for (int i = 0; i < 5; i++) {
        y = (y << 2) | (y >> 30);
    }
    printf("Result: %d\n", y);
    return 0;
}