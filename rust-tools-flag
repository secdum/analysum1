---

## 1. Purpose

This document describes the most relevant command-line flags for the Rust tools used in `secdojo-scan`.

It has four goals:

1. document the most useful flags for each tool
2. explain what each flag does
3. provide practical usage examples
4. define which flags will be used in the project and why

This helps keep the Rust analysis pipeline consistent, reproducible, and easier to integrate into SARIF-based reporting.

---

## 2. Tooling Scope

The Rust tools currently considered in the project are:

- `cargo-audit`
- `cargo-geiger`
- `cargo clippy`

These tools do not play the same role:

- `cargo-audit` is the main dependency vulnerability scanner
- `cargo-geiger` is a risk-visibility tool focused on `unsafe` usage
- `clippy` is a complementary quality and linting tool

Because of that, the selected flags also serve different purposes.

---

## 3. Selection Principles

Flags are considered relevant when they help with one or more of the following:

- structured output
- automation
- wider code coverage
- reproducibility
- integration into Python wrappers
- compatibility with SARIF conversion

The project prefers flags that produce predictable output and avoid unnecessary complexity in the first implementation.

---

## 4. cargo-audit

### 4.1 Purpose

`cargo-audit` checks Rust dependencies against the RustSec Advisory Database and reports known security advisories.

This includes:

- vulnerable crates
- unmaintained crates
- unsound crates
- yanked crates

---

### 4.2 Relevant Flags

| Flag | Explanation | Practical Use |
|------|-------------|---------------|
| `--json` | Outputs findings in JSON format | Best option for parser integration |
| `--quiet` | Suppresses non-essential output | Useful in CI and automation |
| `--ignore <ID>` | Ignores a specific advisory ID | Useful for temporary suppression |
| `--db <path>` | Uses a local advisory database | Useful in offline or controlled environments |
| `--stale` | Fails if the advisory database is outdated | Useful for CI validation |
| `--all-features` | Enables all features during dependency resolution | Improves dependency coverage |
| `--no-default-features` | Disables default features | Useful for narrower scans |
| `--features <list>` | Enables selected features only | Useful for targeted scans |

---

### 4.3 Explanation of Key Flags

#### `--json`

This is the most important flag for the project.

Why:

- JSON is structured
- parsing is easier and more reliable
- conversion to SARIF becomes straightforward

Without `--json`, the scanner would need text parsing, which is more fragile.

#### `--quiet`

This reduces noise in automated runs.

Useful when:

- running in CI
- writing logs
- integrating into larger pipelines

It is optional for the MVP, but useful later.

#### `--ignore <ID>`

This allows temporary suppression of a known advisory.

Example use cases:

- accepted risk
- false positive handling policy
- pending upgrade in a dependency

#### `--all-features`

This expands coverage by enabling all dependency features.

Useful when:

- dependencies change depending on enabled features
- broader scans are needed

This is potentially useful later, but the MVP can start without it.

---

### 4.4 Examples of Use

#### Standard machine-readable scan

```bash
cargo audit --json
```

#### Quiet JSON output

```bash
cargo audit --json --quiet
```

#### Ignore a specific advisory

```bash
cargo audit --json --ignore RUSTSEC-2020-0001
```

#### Audit with all features enabled

```bash
cargo audit --json --all-features
```

#### Audit using a local advisory database

```bash
cargo audit --json --db ./rustsec-db
```

---

### 4.5 Selected Usage for secdojo-scan

For the first implementation:

```bash
cargo audit --json
```

Why this was selected:

- easiest to parse
- most stable for automation
- directly useful for SARIF generation

Possible future extension:

```bash
cargo audit --json --quiet --all-features
```

---

### 4.6 Implementation Notes

The parser should expect:

- advisory identifiers
- affected crate information
- severity-related metadata
- suggested fix version

Each advisory can be converted into one SARIF result.

---

## 5. cargo-geiger

### 5.1 Purpose

`cargo-geiger` measures the amount of unsafe code used in a Rust project and its dependency graph.

It does not prove the existence of a vulnerability. Instead, it helps identify:

- crates with unsafe exposure
- dependency trees with higher risk
- areas that may require manual inspection

In `secdojo-scan`, it should be treated as a risk signal, not as direct vulnerability evidence.

---

### 5.2 Relevant Options and Usage Patterns

`cargo-geiger` is less flag-oriented than `cargo-audit`, so some relevant items are usage patterns rather than classic command-line flags.

| Option / Pattern | Explanation | Practical Use |
|------------------|-------------|---------------|
| standard execution | Runs geiger on the current crate | Main usage mode |
| workspace execution | Can be run inside a Cargo workspace | Useful for larger repositories |
| feature-aware execution | Results may vary with enabled features | Relevant for broader scans |
| output redirection | Save text output to file | Useful for parser testing |
| project-directory execution | Run from a selected repository path | Useful in wrappers and automation |

---

### 5.3 Explanation of Relevant Usage

#### Standard execution

```bash
cargo geiger
```

This is the main mode of operation and the simplest starting point for integration.

#### Output redirection

```bash
cargo geiger > geiger-output.txt
```

Useful when:

- studying the output format
- designing a parser
- keeping sample outputs in `docs/` or test assets

#### Feature-aware analysis

If a project enables different dependency trees depending on features, `cargo-geiger` output may change. This matters for coverage, even if the exact flags vary by version and setup.

---

### 5.4 Examples of Use

#### Basic execution

```bash
cargo geiger
```

#### Save output to a file

```bash
cargo geiger > geiger-output.txt
```

#### Run inside a target repository

```bash
cd path/to/rust-project
cargo geiger
```

---

### 5.5 Selected Usage for secdojo-scan

For the first implementation:

```bash
cargo geiger
```

Why this was selected:

- simplest integration path
- enough for initial parser design
- avoids premature complexity

---

### 5.6 Implementation Notes

Important implementation decision:

- `cargo-geiger` findings should not automatically be treated as confirmed vulnerabilities
- they should usually map to `warning` or `note`
- parser logic should remain conservative

Because the output is text-based:

- parsing is more fragile
- parser should focus only on stable and useful fields
- the first version should extract only essential information

---

## 6. cargo clippy

### 6.1 Purpose

`cargo clippy` is a linting tool for Rust code.

It detects:

- style issues
- bad practices
- suspicious patterns
- possible bugs

It is not a dedicated security scanner, but it can still help reveal risky code patterns.

In `secdojo-scan`, clippy should be treated as complementary analysis, not as the main Rust security source.

---

### 6.2 Relevant Flags

| Flag | Explanation | Practical Use |
|------|-------------|---------------|
| `--all-targets` | Runs analysis on all targets | Improves code coverage |
| `--all-features` | Enables all features | Increases analysis coverage |
| `--fix` | Automatically applies some lint suggestions | Useful locally, not for scanner mode |
| `-- -D warnings` | Treats warnings as errors | Useful in strict CI |
| `-- -A <lint>` | Allows a specific lint | Useful to suppress noisy lints |
| `-- -W <lint>` | Enables a specific lint | Useful for focused analysis |
| `-- -D <lint>` | Treats a specific lint as an error | Useful for strict policies |

---

### 6.3 Explanation of Key Flags

#### `--all-targets`

This tells Clippy to analyze more than the default target set.

Useful because:

- improves scan coverage
- includes more project code paths
- better for realistic repository analysis

#### `--all-features`

This enables all optional features.

Useful because:

- some code is only compiled under certain features
- broader analysis can reveal additional findings

#### `--fix`

This automatically changes code.

Important project decision:

- this flag **should not be used** in `secdojo-scan`
- the scanner must analyze code, not modify it

#### `-- -D warnings`

This makes warnings fail as errors.

Useful in strict CI, but may be too aggressive for early versions of the scanner.

#### `-- -A <lint>`

This suppresses a specific lint.

Useful later if:

- output becomes too noisy
- certain lints are not relevant to the project
- suppression support is added

---

### 6.4 Examples of Use

#### Standard execution

```bash
cargo clippy
```

#### Broader analysis

```bash
cargo clippy --all-targets --all-features
```

#### Strict mode

```bash
cargo clippy -- -D warnings
```

#### Suppress one lint

```bash
cargo clippy -- -A clippy::needless_return
```

#### Enable a specific lint

```bash
cargo clippy -- -W clippy::pedantic
```

---

### 6.5 Selected Usage for secdojo-scan

For the first implementation:

```bash
cargo clippy --all-targets --all-features
```

Why this was selected:

- improves analysis coverage
- avoids modifying code
- keeps execution straightforward

---

### 6.6 Implementation Notes

The parser should extract, where possible:

- file path
- line number
- message
- lint identifier

Important SARIF decision:

- many Clippy findings should map to `note`
- only selected patterns may justify `warning`
- Clippy should not dominate the final security report

---

## 7. Summary Table

| Tool | Relevant Flags / Modes | Examples | Initial secdojo-scan Usage |
|------|------------------------|----------|---------------------------|
| `cargo-audit` | `--json`, `--quiet`, `--ignore`, `--all-features` | `cargo audit --json` | `cargo audit --json` |
| `cargo-geiger` | standard execution, output redirection, project-directory execution | `cargo geiger` | `cargo geiger` |
| `cargo clippy` | `--all-targets`, `--all-features`, `-- -D warnings`, `-- -A <lint>` | `cargo clippy --all-targets --all-features` | `cargo clippy --all-targets --all-features` |

---

## 8. Final Command Set for the MVP

The initial Rust integration in `secdojo-scan` should use the following commands:

```bash
cargo audit --json
cargo geiger
cargo clippy --all-targets --all-features
```

These commands were selected because they provide the best balance between:

- useful output
- parser feasibility
- automation readiness
- scan coverage

