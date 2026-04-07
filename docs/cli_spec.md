# CLI Specification: secdojo-scan

This document defines the interface, flags, and usage examples for the `secdojo-scan` tool, ensuring consistency between the C and Rust analysis modules.

## 1. Base Command
The tool is executed via Python and should be invoked as follows:
```bash
python secdojo_scan.py [FLAGS]
```

## 2. Arguments and Flags
The CLI uses the argparse module to manage the following parameters:

| Flag | Description | Values | Required |
| :--- | :--- | :--- | :--- |
| `--lang` | Defines the language/ecosystem to analyze. | `c`, `rust`, `all` | Yes |
| `--target` | Path to the local directory or repository to be scanned. | File/dir path | Yes |
| `--timeout` | Maximum execution time per tool. | Seconds (e.g., 60) | No |
| `--max-files` | Limit of files to analyze in large repositories. | Integer | No |

## 3. Flag Behavior
* **`--lang all`**: Sequentially executes the C module (`scan_c.py`) and the Rust module (`scan_rust.py`), aggregating the results into a single report. 
* **`--target`**: If the directory does not contain files of the selected language, the tool should warn the user and exit with an appropriate error code.

## 4. Usage Examples

### Analyze a C project and generate SARIF output
```bash
python secdojo_scan.py --lang c --target ./repos/curl-master
```

### Analyze a Rust project
```bash
python secdojo_scan.py --lang rust --target ./projects/my_rust_app
```

### Full scan (C and Rust) with a time limit
```bash
python secdojo_scan.py --lang all --target ./monorepo --timeout 300
```

## 5. Exit Codes
For integration into CI/CD pipelines, the tool follows this convention:
* **`0`**: Scan completed successfully and no vulnerabilities found.
* **`1`**: Scan completed successfully, but vulnerabilities were found.
* **`2`**: Execution error (e.g., invalid target, missing permissions, base tools not installed).