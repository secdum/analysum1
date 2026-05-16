import pytest
import json
from secdojo.models import Finding

# Import Rust parser functions (which return Finding dataclass objects)
from scanners.Rust.rust_parser import parse_clippy, parse_audit
# Import C parser functions (which return standard Python dictionaries)
from scanners.C.c_parser import parse_cppcheck, parse_semgrep, parse_flawfinder

# ==========================================
# 1. RUST MOCK DATA
# ==========================================
# Mocking real JSON output from the 'cargo clippy' tool.
# We use a raw string here to simulate the exact terminal output format.
MOCK_CLIPPY_JSON = """
{"reason":"compiler-message","message":{"code":{"code":"clippy::ptr_arg"},"level":"warning","message":"writing `&String` instead of `&str` avoids allocation","spans":[{"file_name":"src/main.rs","line_start":15}]}}
"""

# Mocking real JSON output from the 'cargo audit' tool.
MOCK_AUDIT_JSON = """
{
  "vulnerabilities": {
    "list": [
      {
        "advisory": {"id": "RUSTSEC-2020-0071", "title": "Potential buffer overflow", "categories": ["memory_corruption"]},
        "package": {"name": "time", "version": "0.1.43"}
      }
    ]
  }
}
"""

# ==========================================
# 2. C MOCK DATA
# ==========================================
# Mocking real XML output from the 'cppcheck' tool.
MOCK_CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <errors>
        <error id="bufferAccessOutOfBounds" severity="error" msg="Buffer is accessed out of bounds." cwe="119">
            <location file="src/main.c" line="42"/>
        </error>
    </errors>
</results>
"""

# Mocking real JSON/SARIF output from the 'semgrep' tool.
MOCK_SEMGREP_JSON = """
{
  "results": [
    {
      "check_id": "c.lang.security.use-after-free",
      "path": "src/utils.c",
      "start": {"line": 100},
      "extra": {"severity": "ERROR", "message": "Use after free vulnerability detected"}
    }
  ]
}
"""

# ==========================================
# 3. RUST TESTS (Expected to return 'Finding' objects)
# ==========================================
def test_clippy_parser_with_real_data():
    """
    Validates that the Clippy parser correctly maps a raw JSON message
    into our unified Finding dataclass schema.
    """
    # SETUP: The parser expects a dictionary with a 'messages' key containing parsed JSON
    mock_dict = {"messages": [json.loads(MOCK_CLIPPY_JSON)]}
    
    # EXECUTE: Run the parsing function
    findings = parse_clippy(mock_dict)
    
    # VERIFY: Ensure the output list is not empty and fields are correctly mapped
    assert len(findings) > 0, "Parser failed to extract the vulnerability"
    assert isinstance(findings[0], Finding), "Output must be a Finding dataclass object"
    assert findings[0].tool == "clippy", "Tool name was not set correctly"
    assert findings[0].file == "src/main.rs", "File path was not extracted correctly"
    assert findings[0].line == 15, "Line number was not extracted correctly"

def test_audit_parser_with_real_data():
    """
    Validates that the Cargo Audit parser correctly processes vulnerability lists
    and assigns correct severity levels and message details.
    """
    # SETUP: The parser expects a dictionary with a 'parsed' key
    mock_dict = {"parsed": json.loads(MOCK_AUDIT_JSON)}
    
    # EXECUTE: Run the parsing function
    findings = parse_audit(mock_dict)
    
    # VERIFY: Check core attributes mapping
    assert len(findings) > 0
    assert findings[0].tool == "cargo-audit"
    assert findings[0].type == "memory_corruption", "Vulnerability type mismatch"

# ==========================================
# 4. C TESTS (Expected to return standard dictionaries)
# ==========================================
def test_cppcheck_parser_with_real_data():
    """
    Validates that the Cppcheck XML parser correctly extracts attributes
    like CWE, severity, and file locations into a standard dictionary format.
    """
    # EXECUTE: The C parser directly accepts the raw XML string (no JSON loading needed)
    findings = parse_cppcheck(MOCK_CPPCHECK_XML)
    
    # VERIFY: Note that the current C parser implementation returns dicts, not Finding objects
    assert len(findings) > 0
    assert isinstance(findings[0], dict), "C parser currently returns a dict, not a Finding object"
    assert findings[0]["ruleId"] == "CWE-119", "CWE ID was not properly formatted"
    assert findings[0]["level"] == "error", "Severity level was not mapped correctly"
    assert findings[0]["uri"] == "src/main.c", "File path (URI) is incorrect"
    assert findings[0]["startLine"] == 42, "Line number is incorrect"

def test_semgrep_parser_with_real_data():
    """
    Validates that the Semgrep JSON parser correctly drills down into
    the 'results' array and extracts line numbers and file paths.
    """
    # EXECUTE: The Semgrep parser takes the raw JSON string
    findings = parse_semgrep(MOCK_SEMGREP_JSON)
    
    # VERIFY: Ensure the nested JSON fields are correctly flattened
    assert len(findings) > 0
    assert isinstance(findings[0], dict)
    assert findings[0]["ruleId"] == "c.lang.security.use-after-free"
    assert findings[0]["uri"] == "src/utils.c"
    assert findings[0]["startLine"] == 100