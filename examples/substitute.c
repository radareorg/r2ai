#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

// Function to perform substitution (both encryption and decryption)
void substitute(const char *input, const char *substitution, char *output, int reverse) {
    char mapping[ALPHABET_SIZE];

    if (reverse) {
        // Create reverse substitution table for decryption
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            mapping[substitution[i] - 'A'] = 'A' + i;
        }
    } else {
        // Use the direct substitution table for encryption
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            mapping[i] = substitution[i];
        }
    }

    for (int i = 0; input[i] != '\0'; i++) {
        char c = input[i];

        // Handle uppercase letters
        if (isupper(c)) {
            output[i] = mapping[c - 'A'];
        }
        // Handle lowercase letters
        else if (islower(c)) {
            output[i] = tolower(mapping[c - 'a']);
        }
        // Leave non-alphabet characters unchanged
        else {
            output[i] = c;
        }
    }

    output[strlen(input)] = '\0';  // Null-terminate the output string
}

int main() {
    char input[256];
    char output[256];

    // Configurable substitution key (A-Z)
    const char *substitution = "QWERTYUIOPASDFGHJKLZXCVBNM";  // Example substitution key

    // Get input from the user
    printf("Enter text to encrypt: ");
    fgets(input, sizeof(input), stdin);

    // Remove newline character from input if it exists
    input[strcspn(input, "\n")] = 0;

    // Perform encryption (forward substitution)
    substitute(input, substitution, output, 0);
    printf("Encrypted text: %s\n", output);

    // Perform decryption (reverse substitution)
    substitute(output, substitution, input, 1);
    printf("Decrypted text: %s\n", input);

    return 0;
}
