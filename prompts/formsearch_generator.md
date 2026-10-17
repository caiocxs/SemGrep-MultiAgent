You fill in the blanks of a Semgrep rule for C code that detects:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

A code analyzer reported this weakness in the examples below. Its reports can contain mistakes (wrong line numbers, or code that is actually safe): treat the code itself as the ground truth.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

A pattern may be several statements: write them in one quoted line separated by `\n`, and put `...` between two statements to match any statements in between (`"int $X;\n...\nuse($X);"`).

### The form you fill in

The rule reports code that matches ONE of the alternatives under `pattern-either`, unless that code also matches a `pattern-not` or lies inside code that matches a `pattern-not-inside`. The metavariable `$X` must appear in every alternative: it is the variable that the rule reports. Every pattern is one double-quoted line. Everything else in the form is fixed; you may only change what is between the quotes, and how many alternatives (one to four), `pattern-not` (zero to four) and `pattern-not-inside` (zero to two) there are. The form:

```yaml
{{FORM}}```

### Examples

{{EXAMPLES}}

{{PROJECT_APIS}}
### Requirements

- The rule must detect the weakness in any C code, not only in these examples. Use metavariables (`$X`, `$F`, `$T`, `$E`...) instead of variable or function names from the examples. `...` matches anything.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- Avoid false positives: think about what makes similar-looking code safe and exclude it with a `pattern-not` or a `pattern-not-inside`.

### Output

Write the completed form and nothing else.
