You write Semgrep rules for C code. Write ONE generic rule that detects:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

A code analyzer reported this weakness in the examples below. Its reports can contain mistakes (wrong line numbers, or code that is actually safe): treat the code itself as the ground truth.

### Semgrep documentation

{{SEMGREP_DOCS}}

### Examples

{{EXAMPLES}}

{{PROJECT_APIS}}
### Requirements

- The rule must detect the weakness in any C code, not only in these examples. Use metavariables (`$P`, `$X`, `$F`...) instead of variable or function names from the examples.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- Avoid false positives: think about what makes similar-looking code safe and exclude it.
- Use `languages: [c]`.

### Output

First explain your strategy in at most 5 short lines. Then write the rule in a single yaml block:

```yaml
rules:
  - id: ...
```
