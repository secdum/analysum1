from scanners.Rust import rust_scan
from scanners.Rust import rust_parser
from scanners.Rust import rust_sarif

def testar_rust():
    caminho_teste = "C:\\Users\\matil\\ripgrep"
    
    print(f"[*] A executar scanner no diretório: {caminho_teste} ...")
    
    # 1. Test the rust scanner
    dados_raw = rust_scan.scan_raw(caminho_teste)
    
    # 2. Test the rust parser
    resultados_limpos = rust_parser.parse_all_rust(dados_raw)
    
 
    print("\n--- RESULTADOS ---")
    print(f"Total de problemas encontrados: {len(resultados_limpos)}")

    # Export to SARIF
    rust_sarif.export_to_sarif(resultados_limpos, "rust_wrapper_results.sarif")

if __name__ == "__main__":
    testar_rust()