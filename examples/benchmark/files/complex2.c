#include <stdio.h>
#include <stdlib.h>

struct Node {
    int data;
    struct Node *next;
};

int main() {
    struct Node *head = NULL;
    struct Node *tail = NULL;
    for (int i = 0; i < 10; i++) {
        struct Node *newNode = (struct Node *)malloc(sizeof(struct Node));
        if (newNode == NULL) return 1;
        newNode->data = i * 2;
        newNode->next = NULL;
        if (head == NULL) {
            head = newNode;
            tail = newNode;
        } else {
            tail->next = newNode;
            tail = newNode;
        }
    }
    struct Node *current = head;
    int sum = 0;
    while (current != NULL) {
        sum += current->data;
        current = current->next;
    }
    printf("Sum: %d\n", sum);
    current = head;
    while (current != NULL) {
        struct Node *temp = current;
        current = current->next;
        free(temp);
    }
    return 0;
}