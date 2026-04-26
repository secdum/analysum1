# Rust Security Tools Testing Guide

## 1. Repositórios Rust Selecionados para Teste

| Repositório | Descrição | Motivo da Escolha | URL |
|-------------|-----------|------------------|-----|
| **ripgrep** | Ferramenta de pesquisa rápida em ficheiros escrita em Rust | Repositório real com dependências que apresentam advisories, útil para testar `cargo-audit` e `cargo-clippy` | `https://github.com/BurntSushi/ripgrep` |
| **tokio** | Runtime assíncrono amplamente utilizado no ecossistema Rust | Repositório grande baseado em workspace, com versões mais antigas que apresentam advisories no `Cargo.lock` | `https://github.com/tokio-rs/tokio` |
| **rustls** | Biblioteca TLS escrita em Rust | Projeto de segurança real baseado em workspace, útil para observar limitações de tooling e dependências externas | `https://github.com/rustls/rustls` |

---

## 2. Ferramentas Analisadas

Foram analisadas três ferramentas do ecossistema Rust:

| Ferramenta | Objetivo | Tipo de Output |
|-----------|----------|----------------|
| **cargo-audit** | Detetar vulnerabilidades e advisories em dependências através do `Cargo.lock` | JSON |
| **cargo-geiger** | Medir e localizar uso de `unsafe` code em crates Rust e suas dependências | Texto |
| **cargo-clippy** | Detetar lints, warnings e problemas de qualidade e correção de código | JSON / Texto |

---

## 3. Metodologia

Após a seleção dos repositórios, foi realizada uma análise manual com as três ferramentas em cada um deles. Sempre que necessário, foi gerado um `Cargo.lock` com:

```powershell
cargo generate-lockfile
```

Os comandos utilizados para cada ferramenta foram:

```powershell
# cargo-audit
cargo audit --json | Set-Content -Encoding utf8 <repo>_audit.json

# cargo-clippy
cargo clippy --all-targets --all-features --message-format=json --manifest-path ".\<repo>\Cargo.toml" | Set-Content -Encoding utf8 <repo>_clippy.jsonl

# cargo-geiger
cargo geiger --manifest-path ".\<repo>\Cargo.toml" *> <repo>_geiger.txt
```

Os outputs recolhidos foram posteriormente processados com um **script Python** desenvolvido para uniformizar os resultados das três ferramentas num formato consistente, facilitando a comparação entre repositórios.

---

## 4. Fluxo de Trabalho

1. Seleção dos repositórios Rust;
2. Geração do `Cargo.lock` quando necessário;
3. Execução manual das três ferramentas em cada repositório;
4. Recolha e armazenamento dos outputs gerados;
5. Processamento dos resultados com o script Python para uniformização;
6. Geração dos relatórios de sumário por repositório.

---

## 5. Objetivo

O objetivo desta abordagem foi garantir uma análise comparável entre ferramentas diferentes, apesar de cada uma produzir resultados em formatos e estruturas distintas. A uniformização dos outputs permitiu consolidar os findings num único ficheiro JSON por repositório, com campos normalizados como severidade, categoria, ferramenta de origem e localização.

---

## 6. Resumo dos Resultados

Após a execução das três ferramentas nos três repositórios selecionados, verificou-se que os resultados variaram consideravelmente entre projetos, refletindo tanto as diferenças nas bases de código como as limitações de cada ferramenta.

### 6.1 Resultados por Repositório

| Repositório | Total Findings | HIGH | MEDIUM | LOW | INFO |
|-------------|---------------|------|--------|-----|------|
| **ripgrep** | 238 | 15 | 206 | 14 | 3 |
| **tokio** | 223 | 10 | 6 | 207 | 0 |
| **rustls** | 1 | 1 | 0 | 0 | 0 |

O repositório com mais findings foi o **ripgrep** com **238 ocorrências**, seguido do **tokio** com **223**. O **rustls** apresentou apenas **1 finding**, o que se deveu a uma limitação de tooling — a ausência do NASM no ambiente de teste impediu a compilação de `aws-lc-sys`, bloqueando a execução do `cargo-clippy` e do `cargo-geiger`.

#### ripgrep (238 findings)

A análise do ripgrep revelou **223 findings do cargo-clippy** e **15 do cargo-audit**. A grande maioria das ocorrências clippy concentrou-se na dependência `simd 0.2.5`, uma crate antiga que gerou sozinha cerca de 165 findings distribuídos pelos seus ficheiros internos (`sse2.rs`, `lib.rs`, `common.rs`, `sse3.rs`, `v256.rs`). A rule mais frequente foi `clippy-or-rustc` com **110 ocorrências**, seguida de erros de compilação como `E0076` (37), `E0512` (32) e `E0044` (22), que refletem incompatibilidades desta crate com versões mais recentes do compilador Rust.

Do lado do `cargo-audit`, foram identificadas **15 advisories**, incluindo:

- **RUSTSEC-2019-0011** — falha de soundness no `memoffset 0.2.1` que pode causar SIGILL e drops de memória não inicializada
- **RUSTSEC-2020-0070** — data race possível em guard objects do `lock_api 0.1.5`
- **RUSTSEC-2021-0071** — o `grep-cli 0.1.1` pode executar binários arbitrários no Windows
- **RUSTSEC-2018-0017** e **RUSTSEC-2020-0077** — crates `tempdir` e `memmap` classificadas como unmaintained

#### tokio (223 findings)

No tokio, a distribuição foi de **213 findings do cargo-clippy** e **10 do cargo-audit**. Ao contrário do ripgrep, os findings clippy estão distribuídos pelo próprio código do projeto, não por dependências antigas. As rules mais frequentes foram `unexpected_cfgs` (49), `clippy::needless_lifetimes` (37) e `clippy::needless_borrow` (16), indicando oportunidades de simplificação de código e configurações de compilação condicional não reconhecidas.

Os ficheiros com mais findings foram `async_read_ext.rs` e `async_write_ext.rs` (18 cada), e `macros/cfg.rs` (9), o que sugere que as extensões de I/O assíncrono e a camada de macros de configuração são as áreas com mais oportunidades de melhoria.

Do lado do `cargo-audit`, os 10 findings incluem advisories relevantes como:

- **RUSTSEC-2020-0071** — potencial segfault na crate `time 0.1.45`
- **RUSTSEC-2021-0124** — data race no `tokio 0.2.25` ao usar canais `oneshot` após fechar
- **RUSTSEC-2020-0151** — data race em generators com tipos não-Send

#### rustls (1 finding)

O único finding identificado foi reportado pelo `cargo-audit`: a advisory **RUSTSEC-2024-0436**, relativa à dependência `paste 1.0.15`, classificada como **unmaintained**. Apesar de não ser uma vulnerabilidade explorável diretamente, representa um risco de supply chain — se uma vulnerabilidade futura for descoberta nesta dependência, não existirá correção disponível. O `cargo-clippy` e o `cargo-geiger` não produziram resultados devido à falha de build causada pela ausência do NASM.

### 6.2 Cobertura por Ferramenta

| Ferramenta | ripgrep | tokio | rustls | Total |
|------------|---------|-------|--------|-------|
| **cargo-audit** | 15 | 10 | 1 | 26 |
| **cargo-clippy** | 223 | 213 | 0 | 436 |
| **cargo-geiger** | 0 | 0 | 0 | 0 |

O **cargo-clippy** foi a ferramenta com mais findings nos repositórios onde o build teve sucesso, dominando claramente o output com **436 ocorrências no total**. O **cargo-audit** foi a ferramenta mais consistente, funcionando em todos os repositórios independentemente do estado de compilação, com **26 advisories identificadas**. O **cargo-geiger** não produziu findings parseable em nenhum dos repositórios, o que se deveu a limitações de ambiente (NASM no rustls) e possivelmente a avisos de *dependency matching* nos restantes.

### 6.3 Limitações Observadas

Durante os testes, foram identificadas as seguintes limitações:

- **rustls** — A ausência do NASM impediu a compilação de `aws-lc-sys`, bloqueando completamente o `cargo-clippy` e o `cargo-geiger`. Apenas o `cargo-audit` produziu resultados.
- **ripgrep** — Grande parte dos findings clippy provém da dependência `simd 0.2.5`, uma crate desatualizada e incompatível com compiladores Rust recentes, o que infla artificialmente o número de ocorrências.
- **cargo-geiger** — Não produziu findings parseable em nenhum repositório. Em alguns casos emitiu avisos de *dependency matching*, tornando a extração de unsafe findings potencialmente incompleta.
- **cargo-clippy** — Requer um build bem-sucedido, tornando-o sensível a dependências externas do ambiente como compiladores e assemblers.

### 6.4 Tipos de Findings Identificados

Os findings encontrados nos repositórios distribuíram-se pelas seguintes categorias:

- **Advisories de dependências** (`vulnerability` / `warning`) — crates unmaintained ou com vulnerabilidades conhecidas de soundness e data races, detetadas pelo `cargo-audit`. Representam **26 findings** no total.
- **Lints e qualidade de código** (`lint`) — warnings de estilo, lifetimes desnecessários, borrows redundantes e incompatibilidades com versões recentes do compilador, detetados pelo `cargo-clippy`. Representam **436 findings** no total.
- **Uso de `unsafe` code** — não foi possível extrair findings parseable do `cargo-geiger` em nenhum dos repositórios testados.

---

## 7. Conclusão

Os testes demonstram que nenhuma ferramenta, isoladamente, oferece cobertura completa sobre um projeto Rust. O **cargo-audit** destacou-se como a ferramenta mais robusta e independente do ambiente — foi a única a produzir resultados nos três repositórios, incluindo o rustls onde o build falhou. Identificou **26 advisories** relevantes, incluindo casos de soundness e potenciais data races em versões antigas de crates amplamente utilizadas.

O **cargo-clippy** foi a ferramenta com maior volume de output nos repositórios onde o build teve sucesso, com **436 findings** no total. No entanto, a sua utilidade varia consoante o contexto: no ripgrep, grande parte das ocorrências provém de uma dependência obsoleta (`simd 0.2.5`), enquanto no tokio os findings reflectem oportunidades reais de melhoria no próprio código do projeto.

O **cargo-geiger** não produziu resultados utilizáveis nesta série de testes, o que limita a capacidade de avaliar o risco associado ao uso de `unsafe` code. A sua eficácia depende diretamente de um build funcional e de uma resolução correta das dependências.

O uso combinado das três ferramentas, com uniformização dos outputs, permite obter uma visão mais abrangente e comparável do estado de segurança de projetos Rust. Para trabalho futuro, recomenda-se a instalação do NASM no ambiente de teste e a reanálise do rustls para obter resultados completos do clippy e do geiger.