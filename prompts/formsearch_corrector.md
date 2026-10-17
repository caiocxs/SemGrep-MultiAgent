You fix a Semgrep rule for C code. The rule is a form with blanks that you fill in; it should detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

It was tested against vulnerable and safe C code and failed. Fix it.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

A pattern may be several statements: write them in one quoted line separated by `\n`, and put `...` between two statements to match any statements in between (`"int $X;\n...\nuse($X);"`).

### The form you fill in

The rule reports code that matches ONE of the alternatives under `pattern-either` (one to four), unless that code also matches a `pattern-not` (zero to four) or lies inside code that matches a `pattern-not-inside` (zero to two). The metavariable `$X` must appear in every alternative. Every pattern is one double-quoted line; you may only change what is between the quotes, and how many of each there are.

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

- The rule must detect the weakness in any C code, not only in this code. Use metavariables (`$X`, `$F`, `$T`, `$E`...) instead of variable or function names from the code.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- It must not match the safe code listed as false positives.

### Output

Write the complete corrected form and nothing else.
