You fix Semgrep rules for C code. The rule below should detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

It was tested against vulnerable and safe C code and failed. Fix it.

### Semgrep documentation

{{SEMGREP_DOCS}}

### Current rule

```yaml
{{RULE}}
```

### Test result

{{FEEDBACK}}

{{HISTORY}}
### Vulnerable code the rule does not detect

{{MISSED_CODE}}

{{PROJECT_APIS}}
### Requirements

- The rule must detect the weakness in any C code, not only in this code. Use metavariables (`$P`, `$X`, `$F`...) instead of variable or function names from the code.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- It must not match the safe code listed as false positives.
- Use `languages: [c]`.

### Output

First explain in at most 5 short lines what was wrong and what you change. Then write the complete corrected rule in a single yaml block:

```yaml
rules:
  - id: ...
```
