You fix ONE field of a Semgrep rule for C code; everything else in the rule stays exactly as it is. The rule should detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

It was tested against vulnerable and safe C code and failed.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

A pattern may be several statements: write them in one quoted line separated by `\n`, and put `...` between two statements to match any statements in between (`"int $X;\n...\nuse($X);"`).

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
### The field you fix

{{FIELD_DESCRIPTION}}. Its current value is:

{{FIELD_VALUE}}

### Requirements

- Change only this field. Everything else in the rule - how many alternatives/sinks/sanitizers there are, the other patterns, the message - stays as it is.
- The rule must detect the weakness in any C code, not only in this code. Use metavariables (`$X`, `$F`, `$T`, `$E`...) instead of variable or function names from the code.
- Standard C library functions that are part of the weakness can be matched by name.
- It must not match the safe code listed as false positives.

### Output

Write only the new value of this field, as a single double-quoted line, and nothing else.
