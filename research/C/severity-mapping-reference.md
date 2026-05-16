# Severity Mapping Reference

## 1. Overview

This document defines the mapping between tool-specific severity levels and the unified format used in `secdojo-scan`.

All findings are normalized to SARIF-style levels: `error`, `warning`, and `note`.
This applies to both the Rust and C pipelines, ensuring consistent output across all tools.

---

## 2. Unified Severity Levels

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **error** | Confirmed vulnerabilities, memory corruption, unsound code | Fix immediately |
| **warning** | Probable issues, unmaintained crates, unsafe patterns | Fix planned |
| **note** | Informational, low-risk suggestions, style issues | Awareness only |

---

## 3. Cppcheck Severity Mapping

### 3.1 Native Severity Levels

| Cppcheck Severity | Description |
|-------------------|-------------|
| `error` | Definite bugs - undefined behaviour, null pointer deref, buffer overflow |
| `warning` | Probable issues that may cause bugs |
| `style` | Code style issues |
| `performance` | Performance suggestions |
| `portability` | Cross-platform portability issues |
| `information` | Informational messages |

### 3.2 Mapping to Unified Format

| Cppcheck | Unified | Rationale |
|----------|---------|-----------|
| `error` | **error** | Confirmed bugs with security impact |
| `warning` | **warning** | Probable but unconfirmed issues |
| `style` | **note** | No direct security impact |
| `performance` | **note** | No security impact |
| `portability` | **note** | No security impact |
| `information` | **note** | Informational only |

### 3.3 Examples

```
error:
  - Null pointer dereference
  - Memory leak
  - Buffer overflow
  - Use after free
  - Array index out of bounds

warning:
  - Uninitialized variable usage
  - Suspicious pointer arithmetic
  - Possible null pointer dereference
  - Unchecked return value

note:
  - Variable naming conventions
  - Unused variables
  - Redundant code
```

---

## 4. Flawfinder Severity Mapping

### 4.1 Native Risk Levels

Flawfinder uses a 0–5 numeric risk scale based on the danger of the function used:

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
| `5` | **error** | Guaranteed buffer overflow - always dangerous |
| `4` | **error** | Dangerous functions with no bounds checking |
| `3` | **warning** | Potentially dangerous depending on context |
| `2` | **warning** | Low risk, context-dependent |
| `1` | **note** | Very low risk |
| `0` | **note** | Informational |

### 4.3 Examples

```
error (levels 4–5):
  - gets()         — no bounds checking, always vulnerable
  - strcpy()       — no bounds checking
  - strcat()       — no bounds checking
  - sprintf()      — no bounds checking
  - scanf("%s")    — no bounds checking

warning (levels 2–3):
  - strlen()       — can be misused
  - printf()       — format string risk if user-controlled
  - access()       — race condition potential

note (levels 0–1):
  - Minor coding issues
  - Informational suggestions
```

---

## 5. Semgrep Severity Mapping

### 5.1 Native Severity Levels

| Semgrep Severity | Unified | Description |
|------------------|---------|-------------|
| `ERROR` | **error** | High-confidence security issues |
| `WARNING` | **warning** | Medium-confidence issues (may be promoted based on CWE) |
| `INFO` | **note** | Low-priority suggestions |

### 5.2 CWE-Based Promotion

A finding's level can be **promoted** (never demoted) based on its CWE tag:

| CWE Category | Unified Override | Example CWEs |
|--------------|------------------|--------------|
| Critical | **error** | CWE-78, CWE-89, CWE-120, CWE-416 |
| High | **error** | CWE-119, CWE-190, CWE-476, CWE-134, CWE-415 |
| Medium | **warning** | CWE-252, CWE-401 |

### 5.3 Examples

```
error:
  - system(user_input)        — CWE-78 command injection
  - strcpy without bounds     — CWE-120 buffer overflow
  - use after free            — CWE-416

warning:
  - unchecked return value    — CWE-252
  - memory leak               — CWE-401

note:
  - use safer alternatives
  - code quality suggestions
```

---

## 6. Cargo-Audit Severity Mapping

### 6.1 Vulnerability Advisories (with CVSS)

| CVSS Score | Unified |
|------------|---------|
| >= 7.0 | **error** |
| >= 4.0 | **warning** |
| < 4.0 | **note** |
| No score | **error** (conservative fallback) |

### 6.2 Informational Warnings

| Advisory Kind | Unified | Rationale |
|---------------|---------|-----------|
| `unsound` | **error** | Memory-unsafe behaviour confirmed |
| `unmaintained` | **warning** | No active CVE, but supply chain risk |

---

## 7. Cargo-Geiger Severity Mapping

Cargo-geiger counts unsafe code constructs per crate (functions, expressions, traits, impls, methods).

| Unsafe Count | Unified | Rationale |
|--------------|---------|-----------|
| > 50 | **error** | High unsafe surface area |
| > 10 | **warning** | Moderate unsafe usage |
| <= 10 | **note** | Minimal unsafe usage |
| 0 | *(skipped)* | Not reported |

---

## 8. CWE Reference Table

### 8.1 CWEs that map to `error`

| CWE | Name |
|-----|------|
| CWE-78 | OS Command Injection |
| CWE-89 | SQL Injection |
| CWE-120 | Buffer Copy without Checking Size |
| CWE-416 | Use After Free |
| CWE-787 | Out-of-bounds Write |
| CWE-22 | Path Traversal |
| CWE-119 | Buffer Errors |
| CWE-190 | Integer Overflow |
| CWE-476 | NULL Pointer Dereference |
| CWE-134 | Format String Vulnerability |
| CWE-415 | Double Free |

### 8.2 CWEs that map to `warning`

| CWE | Name |
|-----|------|
| CWE-252 | Unchecked Return Value |
| CWE-401 | Memory Leak |
| CWE-457 | Use of Uninitialized Variable |
| CWE-563 | Unused Variable |