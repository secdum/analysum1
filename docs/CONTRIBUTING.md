# Contributing Guide - secdojo-scan

This document details the technical workflow for all group members. We follow a simplified **Git Flow** model to ensure the stability of the main branch.

## 1. Preparation and Issues
Before coding, ensure the task is registered on GitHub.
1. Choose an open Issue or create a new one.
2. Move the Issue to "In Progress" and assign it to yourself.
3. Document important decisions or doubts in the Issue comments to maintain a history.

## 2. Git Workflow (Step-by-Step)

### Step 1: Update the Base
Before creating a new feature, ensure your local `develop` branch is synchronized:
```bash
git checkout develop
git pull origin develop
```

### Step 2: Create a Feature Branch
Create a specific branch for your task from develop:
```bash
# Format: feature/task-name
git checkout -b feature/implement-c-parser
```

### Step 3: Development and Commits
Make incremental changes, each commit should be focused.

**Important:** Use messages that reference the Issue for automation, with prefixes like feat:, fix:, or docs:, and always include the Issue number in the commit to close it automatically:
```bash
git add .
git commit -m "feat: implement parser for cppcheck closes #1"
```

### Step 4: Publish and Open a Pull Request (PR)
Push your branch to GitHub:
```bash
git push origin feature/implement-c-parser
```
Then, go to GitHub and open a **Pull Request** from your branch to develop.

## 3. Acceptance Requirements (Merge)
For the code to be integrated into `develop`, it must meet the following criteria:

* **Code Review**: At least one other colleague must review the code and approve the PR.
* **Validation Prints**: You must attach a screenshot or log of the tool's output (e.g., generated JSON/SARIF file) to the PR.
* **CI Status**: GitHub Actions must pass successfully (Docker build and smoke tests).
* **Tests**: You must ensure that the scan runs correctly on the test files (`fixtures`).

## 4. Ethics and Security (Responsible Disclosure)
If during tests on real repositories (ex: `curl`, `openssl`, `tokio`) you find a critical vulnerability or exposed secrets:
1.  **Do not publish the details** in the README or in open issues.
2.  Consult the `SECURITY.md` file of the affected repository.
3.  Inform the group so we can decide the next step following the responsible disclosure process.