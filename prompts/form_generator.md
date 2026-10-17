You fill in the blanks of a Semgrep rule for C code that detects:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

A code analyzer reported this weakness in the examples below. Its reports can contain mistakes (wrong line numbers, or code that is actually safe): treat the code itself as the ground truth.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

### The form you fill in

The rule is a Semgrep taint rule that follows ONE variable, named by the metavariable `$X`, through the code of a function (taint by side effect):

1. The **source** is the statement that puts `$X` in a new state. From that point `$X` is "marked".
2. A **sink** is a use of `$X` that is a problem when `$X` is marked. The rule reports it. Give one sink per kind of use (one to four). A sink may list up to two `pattern-not-inside` entries: code in which that use does not count.
3. A **sanitizer** is a statement that puts `$X` back in a clean state; after it `$X` is no longer marked. Sanitizers are optional (zero to four).

Every pattern is one double-quoted line and must mention `$X`. Everything else in the form is fixed; you may only change what is between the quotes, and how many sinks and sanitizers there are. The form:

```yaml
{{FORM}}```

### Examples

{{EXAMPLES}}

{{PROJECT_APIS}}
### Requirements

- The rule must detect the weakness in any C code, not only in these examples. Use metavariables (`$X`, `$F`, `$T`, `$E`...) instead of variable or function names from the examples. `...` matches anything.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- Avoid false positives: think about what makes similar-looking code safe and exclude it with a sanitizer or a `pattern-not-inside`.

### Output

Write the completed form and nothing else.
