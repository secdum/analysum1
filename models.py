# File: models.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    tool: str        # Name of the tool that ran the scan (e.g., "cppcheck")
    type: str        # Category, CWE, or vulnerability ID (e.g., "buffer_overflow")
    severity: str    # Severity level (e.g., "HIGH")
    message: str     # Human-readable description of the issue
    file: str        # Path of the file where the issue is located
    line: int        # Line number of the issue (int - DO NOT use string)
    cwe: Optional[str] = None  # Optional CWE (defaults to None if not provided)