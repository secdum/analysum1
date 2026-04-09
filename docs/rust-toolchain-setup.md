## 1. Overview

Rust provides strong memory safety guarantees, eliminating common vulnerabilities such as buffer overflows and use-after-free errors. However, security risks may still arise from:

- **Vulnerable dependencies** — known CVEs in third-party crates
- **Unsafe code usage** — explicit bypass of Rust safety guarantees
- **Poor coding practices** — patterns that introduce bugs or weaken security posture

To address these risks, the `secdojo-scan` project integrates static analysis and dependency auditing tools. Results are normalized and exported in **SARIF (Static Analysis Results Interchange Format)**.

---

## 2. Toolchain Components

### 2.1 Core Toolchain

| Tool | Description |
|------|-------------|
| `rustup` | Rust toolchain manager |
| `cargo` | Build system and dependency manager |

### 2.2 Security & Analysis Tools

| Tool | Description | Security Role |
|------|-------------|---------------|
| `cargo-audit` | Detects known vulnerabilities (RustSec DB) | High |
| `cargo-geiger` | Measures usage of unsafe code | Medium |
| `clippy` | Linter for code quality and risky patterns | Low |

---

## 3. Installation

### 3.1 Install Rust Toolchain

```bash
curl https://sh.rustup.rs -sSf | sh
```

### 3.2 Install Security Tools

```bash
cargo install cargo-audit
cargo install cargo-geiger
rustup component add clippy
```

---

## 4. Verification

### 4.1 Commands Executed

```bash
cargo --version
cargo audit --version
cargo geiger --version
cargo clippy --version
```

### 4.2 Installed Versions (Verified)

| Tool | Version |
|------|---------|
| `cargo` | 1.94.1 |
| `cargo-audit` | 0.22.1 |
| `cargo-geiger` | 0.13.0 |
| `clippy` | 0.1.94 |

---

## 5. Tool Analysis

### 5.1 `cargo-audit`

**Purpose:** Detects known security vulnerabilities (CVEs) in dependencies.

**How it works:**
- Reads `Cargo.lock`
- Compares dependencies against the RustSec Advisory Database
- Reports vulnerabilities with IDs and recommended fixes

**Usage:**

```bash
cargo audit --json
```

**Output includes:**
- Vulnerability ID (`RUSTSEC-XXXX`)
- Affected crate
- Severity
- Fixed version

**Security relevance:** High — detects real, known vulnerabilities.

---

### 5.2 `cargo-geiger`

**Purpose:** Measures usage of `unsafe` code across dependencies.

**How it works:**
- Scans the full dependency tree
- Counts unsafe blocks and functions
- Produces a per-crate breakdown

**Usage:**

```bash
cargo geiger
```

**Security relevance:** Medium — unsafe code increases risk but is not a vulnerability by itself.

---

### 5.3 `clippy`

**Purpose:** Provides linting and detects code quality issues.

**How it works:**
- Runs as a compiler plugin
- Reports warnings and suggestions for risky or non-idiomatic patterns

**Usage:**

```bash
cargo clippy
```

**Security relevance:** Low — primarily code quality, but may expose risky patterns.

---

## 6. Output Characteristics

| Tool | Format | Parsing Strategy |
|------|--------|-----------------|
| `cargo-audit` | JSON | Direct parsing |
| `cargo-geiger` | Plain text | Pattern matching |
| `clippy` | Compiler-style text | Pattern matching |

---


## 7. Limitations

- `cargo-audit` only detects **known** vulnerabilities — no zero-day detection
- `cargo-geiger` flags unsafe code but does **not** confirm vulnerabilities
- `clippy` is **not** a dedicated security tool
- Parsing text output may break if tool output formats change in future versions

---
