#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// - Vulnerabilidade 1: Buffer Overflow -----
void vulnerable_copy(char *input) {
    char buffer[10];
    strcpy(buffer, input); // strcpy sem verificação de tamanho
    printf("Buffer: %s\n", buffer);
}

// - Vulnerabilidade 2: Gets (função perigosa) -----
void vulnerable_input() {
    char name[50];
    gets(name); // gets é sempre perigosa
    printf("Nome: %s\n", name);
}

// - Vulnerabilidade 3: Format String -----
void vulnerable_format(char *user_input) {
    printf(user_input); // format string sem especificador
}

// - Vulnerabilidade 4: Memory Leak -----
void memory_leak() {
    int *ptr = malloc(sizeof(int) * 100);
    ptr[0] = 42; // nunca é feito free()
    printf("Valor: %d\n", ptr[0]);
}

// - Função segura (para teste) -----
void safe_copy(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1); // seguro
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Buffer seguro: %s\n", buffer);
}

int main() {
    printf("=== Teste de Análise Estática ===\n");

    // Chamar funções de teste
    vulnerable_copy("teste");
    vulnerable_format("Olá mundo\n");
    memory_leak();
    integer_overflow();
    safe_copy("ok");

    return 0;
}
