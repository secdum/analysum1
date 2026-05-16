/*
 * vuln.c - Intentionally vulnerable C code for SecDojo scanner testing
 * DO NOT USE IN PRODUCTION
 *
 * Vulnerabilities included:
 *   CWE-120 - Buffer overflow (strcpy, gets)
 *   CWE-416 - Use after free
 *   CWE-476 - NULL pointer dereference
 *   CWE-134 - Format string injection
 *   CWE-190 - Integer overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* CWE-120: Buffer overflow via strcpy */
void buffer_overflow(char *user_input) {
    char buf[16];
    strcpy(buf, user_input); /* cppcheck: bufferOverflow */
    printf("Input: %s\n", buf);
}


/* CWE-416: Use after free */
int use_after_free() {
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) return -1;
    *ptr = 99;
    free(ptr);
    return *ptr; /* cppcheck: deallocuse */
}

/* CWE-476: NULL pointer dereference */
void null_pointer_deref() {
    int *ptr = NULL;
    *ptr = 10; /* cppcheck: nullPointer */
}

/* CWE-134: Format string injection */
void format_string_bug(char *user_input) {
    printf(user_input); /* cppcheck: invalidPrintfArgType */
}

/* CWE-190: Integer overflow */
void integer_overflow() {
    int x = INT_MAX;
    int y = x + 1;
    printf("Overflow result: %d\n", y);
}

int main() {
    printf("=== Vulnerable C Test Program ===\n");

    buffer_overflow("this_string_is_way_too_long_for_the_16_byte_buffer_above");
    use_after_free();
    format_string_bug("hello %s %s\n");
    integer_overflow();
    null_pointer_deref();

    return 0;
}