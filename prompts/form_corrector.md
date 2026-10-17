You fix a Semgrep rule for C code. The rule is a form with blanks that you fill in; it should detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

It was tested against vulnerable and safe C code and failed. Fix it.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

### The form you fill in

The rule is a Semgrep taint rule that follows ONE variable, named by the metavariable `$X`, through the code of a function (taint by side effect): the **source** puts `$X` in a new state, a **sink** is a use of `$X` that is a problem when `$X` is marked (one to four, each with up to two `pattern-not-inside` entries), and a **sanitizer** puts `$X` back in a clean state (zero to four). Every pattern is one double-quoted line and must mention `$X`. You may only change what is between the quotes, and how many sinks and sanitizers there are.

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
