import json
from collections import defaultdict
from typing import List
from models import Finding

def export_to_sarif(findings: List[Finding], output_path: str = "rust_report.sarif") -> None:
    """
    Converte uma lista de Findings para o formato SARIF 2.1.0
    seguindo o standard do projeto SecDojo/Analysum.
    """
    runs = []
    
    # Agrupar os erros por ferramenta (ex: clippy, cargo-audit, etc.)
    findings_by_tool = defaultdict(list)
    for f in findings:
        findings_by_tool[f.tool].append(f)
        
    # Se não houver erros (O equivalente ao empty-log.sarif do teu colega)
    if not findings_by_tool:
        runs.append({
            "tool": {
                "driver": {
                    "name": "SecDojo Scanner"
                }
            },
            "results": []
        })
    
    # Gerar uma "run" para cada ferramenta que encontrou problemas
    for tool_name, tool_findings in findings_by_tool.items():
        results = []
        for f in tool_findings:
            # Mapear as severidades da vossa dataclass para os níveis oficiais do SARIF
            level = "note"
            if f.severity in ("CRITICAL", "HIGH"):
                level = "error"
            elif f.severity == "MEDIUM":
                level = "warning"
                
            # Garantir que a linha é válida para o SARIF (não pode ser 0)
            valid_line = f.line if f.line > 0 else 1
                
            results.append({
                "ruleId": f.type,
                "level": level,
                "message": { "text": f.message },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.file },
                            "region": { "startLine": valid_line }
                        }
                    }
                ]
            })
            
        runs.append({
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/secdum/analysum",
                    "rules": [] # Pode ser preenchido no futuro
                }
            },
            "results": results
        })
        
    # Estrutura principal do SARIF
    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs
    }
    
    # Guardar no disco
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(sarif_data, file, indent=2)
        
    print(f"[*] Relatório SARIF gerado com sucesso em: {output_path}")