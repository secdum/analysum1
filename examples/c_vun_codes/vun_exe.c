#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// - Vulnerability 1: Buffer Overflow 
void vulnerable_copy(char *input) {
    char buffer[10];
    strcpy(buffer, input); // strcpy without bounds checking
    printf("Buffer: %s\n", buffer);
}

// - Vulnerability 2: Gets (dangerous function) 
void vulnerable_input() {
    char name[50];
    gets(name); // gets is always dangerous
    printf("Name: %s\n", name);
}

// - Vulnerability 3: Format String 
void vulnerable_format(char *user_input) {
    printf(user_input); // format string without a specifier
}

// - Vulnerability 4: Memory Leak 
void memory_leak() {
    int *ptr = malloc(sizeof(int) * 100);
    ptr[0] = 42; // free() is never called
    printf("Value: %d\n", ptr[0]);
}

// - Safe function (for testing) 
void safe_copy(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1); // safe
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Safe buffer: %s\n", buffer);
}

int main() {
    printf("=== Static Analysis Test ===\n");

    // Call test functions
    vulnerable_copy("test");
    vulnerable_format("Hello world\n");
    memory_leak();
    integer_overflow();
    safe_copy("ok");

    return 0;
}
