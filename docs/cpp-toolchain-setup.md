## 1. Overview

C and C++ are powerful languages but prone to memory safety issues and security vulnerabilities such as:

- **Buffer overflows** — writing beyond allocated memory boundaries
- **Use-after-free** — accessing freed memory
- **Format string vulnerabilities** — improper handling of format specifiers
- **Integer overflows** — arithmetic operations exceeding type limits
- **Injection attacks** — SQL, command injection via unsafe input handling

To address these risks, the `secdojo-scan` project integrates static analysis tools for C/C++ code. Results are normalized and exported in **SARIF (Static Analysis Results Interchange Format)**.

---

## 2. Toolchain Components

### 2.1 Security & Analysis Tools

| Tool | Description | Security Role |
|------|-------------|---------------|
| `cppcheck` | Static analysis tool for C/C++ | Detects bugs and unsafe coding issues |
| `flawfinder` | Security scanner for C/C++ source code | Finds risky functions and common weaknesses |
| `semgrep` | Rule-based static analysis tool | Detects insecure patterns and supports CI/CD checks |

---

## 3. Installation

### 3.1 Install Cppcheck

**Ubuntu/Debian:**
```bash
sudo apt install -y cppcheck
```

**macOS:**
```bash
brew install cppcheck
```

### 3.2 Install Flawfinder

**Ubuntu/Debian:**
```bash
sudo apt install -y flawfinder
```

**macOS:**
```bash
pipx install flawfinder
```

### 3.3 Install Semgrep

**Ubuntu/Debian:**
```bash
sudo apt install -y semgrep
```

**macOS:**
```bash
pipx install semgrep
```

---

## 4. Verification

### 4.1 Commands Executed

```bash
cppcheck --version
flawfinder --version
semgrep --version
```

### 4.2 Installed Versions 

| Tool | Version |
|------|---------|
| `cppcheck` | 2.20.0 |
| `flawfinder` | 2.0.19 |
| `semgrep` | 1.159.0 |

---

## 5. Tool Analysis

### 5.1 `cppcheck`

**Purpose:** Static analysis tool for C/C++ that detects bugs, undefined behaviour, dangerous coding constructs, portability problems, performance issues, and style-related issues.

**How it works:**
- Performs static source code analysis without executing the program
- Uses its own parser and internal preprocessor to inspect code paths, configurations, macros, and includes
- Focuses on finding likely real defects while keeping the false positive rate relatively low

**Key Flags:**

```bash
cppcheck [FLAGS] <source-file-or-directory>
```

| Flag | Description |
|------|-------------|
| `--enable=<checks>` | Enables categories such as warning, style, performance, portability, information, or all |
| `--xml` | Writes results in XML format to stderr |
| `--output-file=<file>` | Selects the XML output version. Commonly used with --xml-version=2 |
| `--suppress=<id>` | Suppresses a specific warning or message id |
| `--inconclusive` | Includes findings that are possible but not certain; may increase false positives |
| `--platform=<platform>` | Sets the target platform model, e.g. Unix or Windows, improving type-size assumptions |
| `--inline-suppr` | Enables inline suppression comments in source code|
| `--project=<file>`| Imports build/project information, e.g. compile_commands.json, .sln, .vcxproj |
| `--addon=<addon>` | Runs extra analysis addons such as MISRA-related checks |
| `-i <path>` | Ignores files or directories during analysis |
| `-j <jobs>` | Runs checks in parallel using multiple threads |

**Basic Usage:**

```bash
cppcheck src/
```

**What it detects:**
- Out-of-bounds access and buffer misuse
- Null pointer dereferences
- Use of uninitialized variables
- Memory leaks and resource-management bugs
- Integer/logic issues and undefined behaviour
- Portability and API misuse issues

**Security relevance:** Medium to High. It is not a dedicated vulnerability scanner, but it is very useful for finding implementation bugs that often become security vulnerabilities in C/C++ projects.

---

### 5.2 `flawfinder`

**Purpose:** Security-focused static analysis tool for C/C++ that quickly scans source code for potentially dangerous functions and insecure coding patterns.

**How it works:**
- Performs lexical scanning of source code rather than deep semantic analysis
- Matches code against a built-in database of risky functions and constructs
- Assigns risk levels from 0 to 5 and associates many findings with CWE identifiers
- Adjusts some results based on context, for example whether parameters are constant or variable

**Key Flags:**

```bash
flawfinder [FLAGS] <source-files-or-directory>
```

| Flag | Description |
|------|-------------|
| `--minlevel=<level>` | Shows only findings at or above the chosen risk level (0–5) |
| `--html` | Formats output as HTML |
| `--sarif` | Produces output in SARIF format |
| `--csv` | Produces output in CSV format for further processing |
| `--quiet` | Hides status/progress messages during analysis |
| `--context` | Includes the relevant source line/context in the output |
| `--inputs` | Focuses onfunctions that receive external input |
| `--falsepositive` | Helps reduce reports caused by misleading variable names |
| `--neverignore` | Disables ignore comments and reports everything anyway |

**Basic Usage:**

```bash
flawfinder src/
```

**What it detects:**
- Use of dangerous C library functions such as strcpy, sprintf, gets, etc.
- Buffer overflow risks
- Format string issues
- Race-condition related temporary file usage
- Weak input validation patterns
- Other common insecure coding constructs mapped to CWE categories

**Security relevance:**  High. It is directly focused on security weaknesses in C/C++ and is especially useful for quickly flagging risky APIs and patterns that deserve manual review.

---

### 5.3 `semgrep`

**Purpose:** Rule-based static analysis tool that detects insecure code patterns, vulnerabilities, and project-specific anti-patterns across many languages, including C and C++.

**How it works:**
- Uses structural pattern matching over parsed source code rather than plain text grep
- Applies rules defined in YAML, local files, remote configs, or registry rulesets
- Supports built-in/community rulesets and custom rules tailored to the project
- Can be used locally with `scan` or in CI with `ci`

**Key Flags:**

```bash
semgrep scan [FLAGS] --config=<rules> <target>
```

| Flag | Description |
|------|-------------|
| `--config=<config>` | Loads rules from a YAML file, directory, URL, or Semgrep registry entry such as auto or p/default |
| `--sarif` | Outputs results in SARIF format |
| `--json` | Outputs results in Semgrep JSON format |
| `--severity=<level>` | Outputs results in Semgrep JSON format |
| `--exclude=<pattern>` | Excludes files or folders matching the given pattern |
| `--sarif-output=<file>` | Writes SARIF output to a file or URL |
| `--error`| Returns a failing exit code when findings are detected |

**Basic Usage:**

```bash
semgrep --config=auto src/
```

**What it detects:**
- Insecure coding patterns covered by chosen rulesets
- API misuse and unsafe function usage
- Injection-prone patterns
- Hardcoded secrets or dangerous configurations, depending on rules
- Project-specific anti-patterns through custom rules

**Security relevance:** High. Semgrep is very flexible, integrates well into CI/CD, supports custom security rules, and can detect both generic and organization-specific coding issues.

---

## 6. Output Characteristics

| Tool | Native Format | SARIF Support | Parsing Strategy |
|------|---------------|---------------|------------------|
| `cppcheck` | Text output and XML output | No native SARIF output documented; typically XML must be converted externally | Parse XML (`--xml --xml-version=2`) or structured text templates |
| `flawfinder` | Text output, HTML, CSV | Yes, native via `--sarif` | Prefer SARIF directly; CSV is also convenient for automation |
| `semgrep` | Text output, JSON, SARIF, JUnit XML, GitLab SAST | Yes, native via `--sarif` | Prefer SARIF or JSON depending on the pipeline |

---

## 7. Limitations

### 7.1 Cppcheck
- May miss vulnerabilities that depend heavily on runtime behaviour or full program intent
- Requires proper configuration or project import for best results, especially in complex builds
- Security findings are often indirect, because many warnings are framed as bugs or dangerous constructs rather than explicit “vulnerabilities”

### 7.2 Flawfinder
- Higher false positive rate, since it is primarily lexical and pattern-based
- Limited semantic understanding of control flow and data flow
- Can flag dangerous functions even when surrounding validation makes them safe

### 7.3 Semgrep
- Quality depends heavily on the selected ruleset
- Can miss issues that are outside the expressiveness of available rules or require deeper whole-program analysis
- `--config auto` is convenient, but rule selection may vary and should be reviewed for consistency in academic or reproducible work

---

## 8. Notes

During installation, it is preferable to keep Python-based CLI tools in isolated environments. In practice, `flawfinder` and `semgrep` are good candidates for installation with `pipx`, while `cppcheck` is usually installed with the system package manager such as `apt` or `brew`.

