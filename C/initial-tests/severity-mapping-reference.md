# Severity Mapping Reference

## 1. Overview

Este documento define o mapeamento entre os níveis de severidade específicos de cada ferramenta e o formato unificado usado no projeto `secdojo-scan`.

---

## 2. Unified Severity Levels

O formato unificado define 5 níveis de severidade (do mais grave ao menos grave):

| Level | Priority | Description | Action Required |
|-------|----------|-------------|-----------------|
| **CRITICAL** | 4 | Vulnerabilidades confirmadas com impacto severo | Correção imediata |
| **HIGH** | 3 | Problemas graves com alto potencial de exploração | Correção urgente |
| **MEDIUM** | 2 | Problemas relevantes que requerem atenção | Correção planeada |
| **LOW** | 1 | Problemas menores ou de qualidade de código | Correção opcional |
| **INFO** | 0 | Informativo, sem impacto de segurança | Apenas conhecimento |

---

## 3. Cppcheck Severity Mapping

### 3.1 Native Severity Levels

Cppcheck usa os seguintes níveis:

| Cppcheck Severity | Description |
|-------------------|-------------|
| `error` | Bugs definitivos, comportamento undefined |
| `warning` | Problemas prováveis que podem causar bugs |
| `style` | Problemas de estilo de código |
| `performance` | Sugestões de otimização de performance |
| `portability` | Problemas de portabilidade entre plataformas |
| `information` | Mensagens informativas |

### 3.2 Mapping to Unified Format

| Cppcheck | Unified | Rationale |
|----------|---------|-----------|
| `error` | **CRITICAL** | Bugs confirmados (null pointer deref, buffer overflow, use-after-free) |
| `warning` | **MEDIUM** | Problemas prováveis mas não confirmados |
| `style` | **LOW** | Não afeta segurança diretamente |
| `performance` | **LOW** | Sem impacto de segurança |
| `portability` | **LOW** | Sem impacto de segurança |
| `information` | **INFO** | Apenas informativo |

### 3.3 Examples

```
error (CRITICAL):
  - Null pointer dereference
  - Memory leak
  - Buffer overflow
  - Use after free
  - Array index out of bounds

warning (MEDIUM):
  - Uninitialized variable usage
  - Suspicious pointer arithmetic
  - Possible null pointer dereference
  - Unchecked return value

style (LOW):
  - Variable naming conventions
  - Unused variables
  - Redundant code
```

---

## 4. Flawfinder Severity Mapping

### 4.1 Native Risk Levels

Flawfinder usa um sistema de 0-5 baseado no risco da função:

| Level | Description | Example Functions |
|-------|-------------|-------------------|
| 5 | Extremely risky | `gets()` |
| 4 | High risk | `strcpy()`, `strcat()`, `sprintf()` |
| 3 | Medium risk | `strlen()`, `strcmp()` |
| 2 | Low risk | `printf()` (format string) |
| 1 | Very low risk | Minor issues |
| 0 | Informational | Suggestions |

### 4.2 Mapping to Unified Format

| Flawfinder Level | Unified | Rationale |
|------------------|---------|-----------|
| `5` | **CRITICAL** | Funções extremamente perigosas (buffer overflow garantido) |
| `4` | **HIGH** | Funções perigosas se mal usadas |
| `3` | **MEDIUM** | Funções potencialmente perigosas |
| `2` | **LOW** | Baixo risco, contexto dependente |
| `1` | **LOW** | Risco muito baixo |
| `0` | **INFO** | Informativo |

### 4.3 Examples

```
Level 5 (CRITICAL):
  - gets() - No bounds checking, always vulnerable
  - Direct use of dangerous functions

Level 4 (HIGH):
  - strcpy(dest, src) - No bounds checking
  - strcat(dest, src) - No bounds checking
  - sprintf(buf, fmt, ...) - No bounds checking
  - scanf("%s", buf) - No bounds checking

Level 3 (MEDIUM):
  - strlen() - Can be used in vulnerable ways
  - strcmp() - Timing attacks possible
  - strtok() - Not thread-safe

Level 2 (LOW):
  - printf() with user-controlled format string
  - access() - Race condition potential

Level 1 (LOW):
  - Minor coding issues
```

---

## 5. Semgrep Severity Mapping

### 5.1 Native Severity Levels

Semgrep usa 3 níveis base:

| Semgrep Severity | SARIF Level | Description |
|------------------|-------------|-------------|
| `ERROR` | `error` | High confidence security issues |
| `WARNING` | `warning` | Medium confidence issues |
| `INFO` | `note` | Low priority suggestions |

### 5.2 Base Mapping to Unified Format

| Semgrep | Unified | Rationale |
|---------|---------|-----------|
| `ERROR` | **CRITICAL** | Vulnerabilidades confirmadas |
| `WARNING` | **MEDIUM** | Problemas prováveis (pode subir para HIGH baseado em CWE) |
| `INFO` | **LOW** | Sugestões e best practices |

### 5.3 CWE-Based Refinement

O nível unificado pode ser **aumentado** (nunca reduzido) baseado no CWE:

| CWE Category | Unified Override | Example CWEs |
|--------------|------------------|--------------|
| **Critical** | **CRITICAL** | CWE-78 (Command Injection), CWE-89 (SQL Injection), CWE-120 (Buffer Overflow), CWE-416 (Use-After-Free) |
| **High** | **HIGH** | CWE-119 (Buffer Errors), CWE-190 (Integer Overflow), CWE-476 (NULL Deref) |
| **Medium** | **MEDIUM** | CWE-252 (Unchecked Return), CWE-401 (Memory Leak) |

### 5.4 Examples

```
ERROR + CWE-78 (CRITICAL):
  - system(user_input) - Command injection
  - exec(user_controlled) - Code execution

WARNING + CWE-120 (upgrades to CRITICAL):
  - Potential buffer overflow
  - Unsafe string operations

WARNING without critical CWE (MEDIUM):
  - Unchecked return value
  - Resource leak

INFO (LOW):
  - Use safer alternatives
  - Code quality suggestions
```

---

## 6. CWE-Based Severity Override Table

Independente da ferramenta, alguns CWEs sempre mapeiam para severidades específicas:

### 6.1 Critical CWEs (Always CRITICAL)

| CWE | Name | Why Critical |
|-----|------|--------------|
| CWE-78 | OS Command Injection | Remote code execution |
| CWE-89 | SQL Injection | Database compromise |
| CWE-120 | Buffer Copy without Checking Size | Memory corruption, RCE |
| CWE-416 | Use After Free | Memory corruption, exploitation |
| CWE-787 | Out-of-bounds Write | Memory corruption |
| CWE-22 | Path Traversal | Arbitrary file access |

### 6.2 High CWEs (Always at least HIGH)

| CWE | Name | Why High |
|-----|------|----------|
| CWE-119 | Buffer Errors | Potential memory corruption |
| CWE-190 | Integer Overflow | Can lead to buffer overflow |
| CWE-476 | NULL Pointer Dereference | Denial of service, potential exploitation |
| CWE-134 | Format String Vulnerability | Information disclosure, RCE |
| CWE-131 | Incorrect Buffer Size Calculation | Buffer overflow |
| CWE-415 | Double Free | Memory corruption |

### 6.3 Medium CWEs

| CWE | Name |
|-----|------|
| CWE-252 | Unchecked Return Value |
| CWE-401 | Memory Leak |
| CWE-457 | Use of Uninitialized Variable |
| CWE-563 | Unused Variable |