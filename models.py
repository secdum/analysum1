# Ficheiro: models.py
from dataclasses import dataclass

@dataclass
class Finding:
    tool: str        # Ex: "cppcheck", "bandit", "cargo-audit"
    type: str        # Ex: "buffer_overflow"
    severity: str    # Ex: "HIGH", "MEDIUM", "LOW", "INFO"
    message: str     # A descrição legível do erro
    file: str        # O caminho do ficheiro com o erro
    line: int        # A linha do erro
    cwe: Optional[str] = None
