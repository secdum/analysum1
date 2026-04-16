# C/C++ Security Tools Testing Guide

## 1. Repositórios Vulneráveis para Teste

| Repositório | Descrição | Vulnerabilidades Conhecidas | URL |
|-------------|-----------|----------------------------|-----|
| **vulnerable-c-and-cpp** | Coleção de exemplos vulneráveis em C e C++ para treino e análise de segurança | Buffer overflow, format string, integer overflow, memory corruption | `https://github.com/lirantal/vulnerable-c-and-cpp` |
| **Damn_Vulnerable_C_Program** | Conjunto de programas em C deliberadamente inseguros para estudo de falhas clássicas | Buffer overflow, segmentation faults, unsafe input handling, memory issues | `https://github.com/hardik05/Damn_Vulnerable_C_Program` |
| **seeve** | Projeto focado em vulnerabilidades de memória e exploração em C/C++ | Heap overflow, stack overflow, use-after-free, memory corruption | `https://github.com/conikeec/seeve` |
| **SecureCodingDojo** | Projeto OWASP com exemplos inseguros e exercícios de secure coding | Multiple CWEs, input validation flaws, memory safety issues, insecure coding patterns | `https://github.com/OWASP/SecureCodingDojo` |

---

## 2. Metodologia

Após a seleção dos repositórios vulneráveis, foi realizada uma análise manual a cada um deles com três ferramentas de segurança estática: **Cppcheck**, **Flawfinder** e **Semgrep**.

Cada repositório foi testado individualmente com as três ferramentas, de forma a recolher os respetivos resultados e perceber que tipo de vulnerabilidades cada uma conseguia identificar.

Numa fase posterior, os outputs gerados foram processados com um **script desenvolvido em Python**, criado para **uniformizar os resultados**. Este script permitiu organizar a informação produzida pelas diferentes ferramentas num formato consistente, facilitando a comparação entre os resultados obtidos.

## 3. Fluxo de Trabalho

1. Seleção dos repositórios vulneráveis;
2. Execução manual das três ferramentas em cada repositório;
3. Recolha dos outputs gerados;
4. Processamento dos resultados com um script Python para uniformização.

## 4. Objetivo

O objetivo desta abordagem foi garantir uma análise comparável entre ferramentas diferentes, apesar de cada uma produzir resultados em formatos e estruturas distintas.

## 5. Resumo dos Resultados

Após a execução manual das três ferramentas (**Cppcheck**, **Flawfinder** e **Semgrep**) nos quatro repositórios selecionados, verificou-se que todas conseguiram identificar problemas de segurança, embora com comportamentos bastante diferentes entre si.

No total, o repositório que apresentou mais findings foi o **Damn_Vulnerable_C_Program**, com **325 ocorrências**, seguido do **seeve**, com **174**, do **SecureCodingDojo**, com **163**, e do **vulnerable-c-and-cpp**, com **52**.
Em termos de cobertura por ferramenta, o **Cppcheck** foi a que apresentou mais resultados nos repositórios **seeve** (**118**), **Damn_Vulnerable_C_Program** (**191**) e **vulnerable-c-and-cpp** (**33**), mostrando maior capacidade para detetar problemas ligados a memória, variáveis não inicializadas e acessos fora de limites. Já no **SecureCodingDojo**, a ferramenta com mais findings foi o **Semgrep**, com **86 ocorrências**, superando o Cppcheck (**31**) e o Flawfinder (**46**).

De forma geral, o **Cppcheck** parece ter sido a ferramenta mais eficaz neste conjunto de testes, porque foi a que mais findings gerou na maioria dos repositórios e a que identificou vários problemas críticos concretos, como **double free**, **use-after-free**, **variáveis não inicializadas** e **out-of-bounds access**. O **Flawfinder** também mostrou utilidade, mas com uma abordagem mais centrada em funções inseguras e padrões de risco conhecidos. O **Semgrep** teve um desempenho mais limitado na maioria dos repositórios, embora tenha sido particularmente relevante no **SecureCodingDojo**, onde encontrou o maior número de resultados.

Relativamente à severidade, os resultados mostram que a maior parte dos findings ficou concentrada nos níveis **LOW** e **INFO**, o que indica uma presença significativa de problemas de menor impacto ou de natureza mais informativa. Ainda assim, foram também identificados vários casos **CRITICAL**, nomeadamente **23** no **seeve**, **20** no **Damn_Vulnerable_C_Program**, **8** no **SecureCodingDojo** e **6** no **vulnerable-c-and-cpp**.

No conjunto dos testes, os tipos de problemas mais frequentes incluíram **variáveis não inicializadas** (**CWE-457**), **use-after-free** (**CWE-416**), **double free** (**CWE-415**), **null pointer dereference** (**CWE-476**) e **acessos fora de limites** como **CWE-788** e **CWE-786**.

Em resumo, os testes mostram que nenhuma ferramenta, isoladamente, oferece cobertura completa. No entanto, o **Cppcheck** destacou-se como a ferramenta mais consistente e útil para este conjunto de repositórios, enquanto o uso combinado das três permitiu obter uma visão mais abrangente das vulnerabilidades existentes.

