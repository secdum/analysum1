#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1) - CWE-122 / CWE-119: Heap-based overflow during write
void heap_overflow_write() {
    char* h = (char*)malloc(32);
    if (!h) return;
    // intentional overflow
    memset(h, 'X', 64);
    printf("heap_overflow: %.*s\n", 64, h);
    free(h);
}

// 2) - CWE-476: NULL pointer dereference in a otherwise safe function receiving a pointer
void safe_use(char* s) {
    // CWE-476 if s == NULL
    printf("first: %c\n", s[0]); // possible NULL deref
}

// 3) - CWE-416: Use-after-free with a function returning a pointer
char* create_and_free_copy() {
    char* a = (char*)malloc(8);
    if (!a) return NULL;
    strcpy(a, "abc123");
    free(a);
    // return pointer after free
    return a;
}

// 4) - CWE-415: Double free
void double_free_demo() {
    char* b = (char*)malloc(10);
    strcpy(b, "hello");
    free(b);
    // intentional double free
    free(b);
}

int main(void) {
    // perform heap overflow
    heap_overflow_write();

    // NULL pointer deref
    safe_use(NULL);

    // use-after-free
    char* after = create_and_free_copy();
    // attempt use after free
    if (after) {
        printf("after=%s\n", after);
        // may be invalid
    }

    // double free
    double_free_demo();

    return 0;
}
