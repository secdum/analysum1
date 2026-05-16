## Comparison of Cppcheck, Flawfinder, and Semgrep

Based on the tests performed on the selected vulnerable repositories, it was possible to compare **Cppcheck**, **Flawfinder**, and **Semgrep** across four main aspects: types of vulnerabilities detected, level of detail, false positives, and ease of use.

| Criterion | Cppcheck | Flawfinder | Semgrep |
|----------|----------|------------|---------|
| **Types of vulnerabilities detected** | Stronger at finding concrete code-level issues, especially **memory leaks**, **double free**, **use-after-free**, **null pointer dereference**, **uninitialized variables**, and **out-of-bounds access** | More focused on **unsafe functions** and classic risky patterns, such as dangerous library calls and known insecure practices | More oriented toward **semantic patterns** and rule-based matches, with results depending heavily on the applied rules |
| **Level of detail** | High. Usually reports the file, line, and exact type of issue, with useful messages for understanding the problem | Medium. Provides enough context, but often flags potential risk based mainly on the function used rather than confirmed exploitability | Variable. In some cases it provides useful structured information, but in others the findings are more generic and rule-dependent |
| **False positives** | Generally lower in the observed tests, since many findings were concrete and technically meaningful | More prone to false positives, because detections often rely on the presence of functions considered unsafe | Can generate false positives or less relevant matches, especially when automatic rules are not well aligned with the project context |
| **Ease of use** | Easy to run, although outputs may require extra processing for comparison | Very easy to run and interpret, especially for quick initial triage | Also easy to run, but more dependent on configuration and rule quality |
| **Observed performance in the tests** | Stood out in most of the analyzed repositories | Complemented the analysis well, especially for identifying known unsafe coding patterns | Had less overall impact, although in **SecureCodingDojo** it produced more findings than the other tools |

## Analysis

Overall, **Cppcheck** was the most effective tool in this set of tests because it detected a higher number of concrete and technically relevant vulnerabilities, especially in **seeve**, **Damn_Vulnerable_C_Program**, and **vulnerable-c-and-cpp**.
**Flawfinder** proved useful as a complementary tool, mainly for quickly identifying unsafe patterns and calls to functions that are widely associated with insecure coding. However, its approach is more superficial, so the results require more manual validation.

**Semgrep** showed less consistent performance across the full test set. Even so, it performed better in **SecureCodingDojo**, where it produced more findings than the other tools, suggesting that it can be useful in cases where its semantic rules fit the analyzed code more effectively.

## Conclusion

None of the tools is sufficient on its own. **Cppcheck** stood out for detecting more concrete vulnerabilities with greater technical detail, **Flawfinder** was useful for quickly spotting unsafe coding patterns, and **Semgrep** showed value in specific cases. Therefore, using the three tools together provided a broader and more balanced view of the vulnerabilities present in the tested codebases.
