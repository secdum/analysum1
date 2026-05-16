# Security Policy

The **SecDojo Scanner** team takes the security of our software and the trust of our users very seriously. If you believe you have found a security vulnerability in our orchestrator, parsers, or CLI pipeline, we encourage you to let us know right away. We will investigate all legitimate reports and do our best to quickly fix the problem.

## Supported Versions

We currently provide security updates for the following versions of SecDojo Scanner:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | Yes              |
| < 1.0   | No (Deprecated)  |

*Note: As an orchestrator, we also rely on the security of the underlying tools (Cppcheck, Flawfinder, Semgrep, Cargo-audit, etc.). We highly recommend keeping your local toolchains and Docker images up to date.*

## Scope and Exclusions

Please note the distinction between vulnerabilities in **SecDojo Scanner** itself and vulnerabilities in the **tools we orchestrate**:

*   **In Scope:** Bugs in our Python orchestrator, parser logic flaws (e.g., arbitrary code execution via crafted tool output), path traversal in our directory chunking, or vulnerabilities in our Dockerfile configurations.
*   **Out of Scope:** Vulnerabilities in the underlying third-party static analysis tools (e.g., a bug in `semgrep` or `cppcheck`). These should be reported directly to the respective upstream maintainers.
*   **Out of Scope:** Vulnerabilities found in *your* code or third-party repositories scanned by SecDojo Scanner. Please follow the responsible disclosure guidelines of the affected repository.

## Reporting a Vulnerability

**PLEASE DO NOT CREATE A PUBLIC ISSUE FOR SECURITY VULNERABILITIES.**

If you discover a security vulnerability within SecDojo Scanner, please follow these steps:

1.  **Email us directly:** Send your report privately to `pg60244@alunos.uminho.pt`, `pg60283@alunos.uminho.pt` or `pg58716@alunos.uminho.pt`.
2.  **Use GitHub Security Advisories (Alternative):** If enabled on this repository, you can go to the **Security** tab -> **Vulnerabilities** -> **Report a vulnerability** to submit a report privately.

### What to include in your report:
To help us triage and resolve the issue quickly, please include the following information:
*   **Description:** A clear description of the vulnerability and its potential impact.
*   **Steps to Reproduce:** Detailed steps, including any specific CLI flags, environment setup, or crafted files required to trigger the vulnerability.
*   **Environment Details:** OS, Python version, Docker usage, and the version of SecDojo Scanner you are using.
*   **Potential Remediation:** (Optional) Any insights you have on how to fix the issue.

## Our Resolution Process

Once you submit a report, here is what you can expect from us:

1.  **Acknowledgment:** We will acknowledge receipt of your vulnerability report within **48 hours**.
2.  **Triage:** We will investigate and confirm the vulnerability, providing you with an estimated timeline for a fix.
3.  **Resolution:** We will develop a patch and test it securely.
4.  **Release & Disclosure:** We will publish a new release containing the fix. Once the patch is available, we will publish a security advisory and publicly credit you for the discovery (unless you prefer to remain anonymous).

We ask that you maintain confidentiality and avoid public disclosure until we have had a reasonable timeframe to release a patch.

---

*Thank you for helping keep SecDojo Scanner and the open-source community secure!*