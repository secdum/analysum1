#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Node {
    int value;
    struct Node* next;
} Node;

// 1) - CWE-120: Classic buffer overflow via strcpy-like operation
void copy_to_fixed_buffer(const char* src) {
    char dest[24];
    // vulnerable: does not check length
    strcpy(dest, src); // CWE-120
    printf("dest=%s\n", dest);
}

// 2) - CWE-416: Use-after-free
char* allocate_and_free(int trigger) {
    char* p = (char*)malloc(16);
    if (!p) return NULL;
    strcpy(p, "hello_world_16!");
    free(p);
    // use after free if trigger is 1
    if (trigger) {
        // CWE-416
        return p; // invalid pointer
    }
    return p;
}

// 3) - CWE-476: NULL pointer dereference
void print_len_of_ptr(const char* s) {
    // CWE-476
    printf("len=%zu\n", strlen(s)); // may dereference NULL
}

// 4) - CWE-134: Format string vulnerability
void vulnerable_printf(const char* user) {
    // CWE-134
    printf(user); // unsafe if user-controlled
    printf("\n");
}

// 5) - CWE-124: Buffer underread via negative index emulation
void underread_example(int idx) {
    int arr[4] = {1,2,3,4};
    if (idx < 0) idx = -idx;
    // access may be out of bounds (if idx >= 4)
    int v = arr[idx]; // CWE-126 could occur, but here it demonstrates out-of-bounds
    printf("arr[%d]=%d\n", idx, v);
}

int main(void) {
    const char* long_input = "A very long input that will overflow the destination buffer";
    copy_to_fixed_buffer(long_input);

    // Use-after-free: trigger = 1 to obtain invalid pointer usage
    char* p = allocate_and_free(1);
    (void)p; // avoid warning, but preserve behavior

    // NULL deref
    print_len_of_ptr(NULL);

    // Format string
    vulnerable_printf("SAFE: ok\n");
    vulnerable_printf(NULL); // to demonstrate unsafe behavior

    // Underread
    underread_example(-2);

    // Basic cleanup (if allocations occurred above)
    return 0;
}
