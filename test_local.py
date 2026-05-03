# teste_local.py
from scanners import rust_scan
from scanners import rust_parser
from scanners import rust_sarif

def testar_rust():
    caminho_teste = "C:\\Users\\matil\\ripgrep"
    
    print(f"[*] A executar scanner no diretório: {caminho_teste} ...")
    
    # 1. Testa o Scanner
    dados_raw = rust_scan.scan_raw(caminho_teste)
    
    # 2. Testa o Parser
    resultados_limpos = rust_parser.parse_all_rust(dados_raw)
    
 
    print("\n--- RESULTADOS ---")
    print(f"Total de problemas encontrados: {len(resultados_limpos)}")
    
    # para ver detalhes de cada finding
    # for finding in resultados_limpos:
    #     print(f"[{finding.severity}] {finding.tool} - {finding.message}")

    # Exporta para o ficheiro final
    rust_sarif.export_to_sarif(resultados_limpos, "rust_wrapper_results.sarif")

if __name__ == "__main__":
    testar_rust()