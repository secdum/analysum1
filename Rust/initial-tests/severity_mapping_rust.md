# Severity Mapping Reference (Rust)

## 1. Overview

Este documento define o mapeamento entre os outputs das ferramentas Rust e o formato unificado usado no projeto `secdojo-scan`.

As ferramentas consideradas são:

* `cargo-audit`
* `cargo-geiger`
* `cargo-clippy`

---

## 2. Unified Severity Levels

O formato unificado define 5 níveis de severidade (do mais grave ao menos grave):

| Level        | Priority | Description                                     | Action Required     |
| ------------ | -------- | ----------------------------------------------- | ------------------- |
| **CRITICAL** | 4        | Vulnerabilidades confirmadas com impacto severo | Correção imediata   |
| **HIGH**     | 3        | Problemas graves com potencial elevado          | Correção urgente    |
| **MEDIUM**   | 2        | Problemas relevantes                            | Correção planeada   |
| **LOW**      | 1        | Problemas menores ou de qualidade de código     | Correção opcional   |
| **INFO**     | 0        | Informativo, sem impacto direto                 | Apenas conhecimento |

---

## 3. cargo-audit Severity Mapping

### 3.1 Native Output

`cargo-audit` identifica vulnerabilidades conhecidas com base na base de dados RustSec.

Output típico:

* JSON estruturado
* Inclui advisory ID, package, description e severidade

### 3.2 Mapping to Unified Format

| cargo-audit                    | Unified      | Rationale                                         |
| ------------------------------ | ------------ | ------------------------------------------------- |
| Vulnerability found            | **CRITICAL** | Vulnerabilidades confirmadas (RustSec advisories) |
| Warning (yanked, unmaintained) | **HIGH**     | Dependências problemáticas                        |
| Informational                  | **INFO**     | Apenas aviso                                      |

### 3.3 Examples

```
CRITICAL:
  - Dependency with known CVE
  - RustSec advisory affecting package

HIGH:
  - Unmaintained crate
  - Yanked dependency

INFO:
  - Advisory without impact
```

---

## 4. cargo-geiger Severity Mapping

### 4.1 Native Output

`cargo-geiger` mede o uso de `unsafe`:

* Número de blocos `unsafe`
* Funções `unsafe`
* Dependências com unsafe

⚠️ Não reporta vulnerabilidades diretamente.

### 4.2 Mapping to Unified Format

| Geiger Finding                        | Unified    | Rationale                                                         |
| ------------------------------------- | ---------- | ----------------------------------------------------------------- |
| Unsafe usage detected                 | **LOW**    | Código potencialmente inseguro mas não necessariamente vulnerável |
| High unsafe concentration (heuristic) | **MEDIUM** | Maior risco potencial                                             |
| No unsafe usage                       | **INFO**   | Código seguro                                                     |

### 4.3 Examples

```
LOW:
  - unsafe block usage
  - unsafe fn declarations

MEDIUM (contextual):
  - High unsafe usage across dependencies

INFO:
  - No unsafe detected
```

---

## 5. cargo-clippy Severity Mapping

### 5.1 Native Output

`cargo-clippy` produz lints:

| Level     | Description      |
| --------- | ---------------- |
| `error`   | Problemas graves |
| `warning` | Problemas comuns |
| `note`    | Informativo      |
| `help`    | Sugestões        |

Output pode ser:

* texto
* JSON (`--message-format=json`)

### 5.2 Mapping to Unified Format

| Clippy Level | Unified    | Rationale                                                 |
| ------------ | ---------- | --------------------------------------------------------- |
| `error`      | **MEDIUM** | Problemas sérios mas não necessariamente vulnerabilidades |
| `warning`    | **LOW**    | Problemas de qualidade de código                          |
| `note`       | **INFO**   | Informativo                                               |
| `help`       | **INFO**   | Sugestões                                                 |

### 5.3 Examples

```
MEDIUM:
  - Incorrect logic patterns
  - Potential bugs

LOW:
  - needless_borrow
  - redundant code
  - style issues

INFO:
  - suggestions
  - improvements
```

---

## 6. Rust-Specific Severity Considerations

### 6.1 Absence of CWE

Ao contrário das ferramentas C:

* Rust tools raramente fornecem CWE diretamente
* A análise baseia-se em:

  * vulnerabilidades conhecidas (`cargo-audit`)
  * uso de unsafe (`geiger`)
  * qualidade de código (`clippy`)

### 6.2 Security Model Implications

Rust garante:

* Memory safety (sem unsafe)
* Proteção contra buffer overflow
* Ausência de use-after-free

Logo:

* `unsafe` ≠ vulnerabilidade
* maioria dos findings = qualidade de código

---

## 7. Unified Mapping Summary

| Tool         | Native Output | Unified Severity |
| ------------ | ------------- | ---------------- |
| cargo-audit  | Vulnerability | CRITICAL         |
| cargo-audit  | Warning       | HIGH             |
| cargo-geiger | Unsafe usage  | LOW / MEDIUM     |
| cargo-clippy | error         | MEDIUM           |
| cargo-clippy | warning       | LOW              |
| cargo-clippy | note/help     | INFO             |

---

## 8. Key Differences from C Analysis

| Aspect          | C Tools | Rust Tools             |
| --------------- | ------- | ---------------------- |
| Memory safety   | Manual  | Guaranteed (safe Rust) |
| CWE mapping     | Direct  | Rare                   |
| Vulnerabilities | Common  | Rare                   |
| Main findings   | Bugs    | Lints / unsafe usage   |

---

## 9. Conclusion

* Rust tools focus more on **code quality and safety guarantees**
* `cargo-audit` is the only tool detecting real vulnerabilities
* `cargo-geiger` indicates **risk exposure via unsafe**
* `cargo-clippy` focuses on **code quality**

This justifies:

* Different severity mapping compared to C tools
* Need for unified normalization logic
