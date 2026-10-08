You fix the matching logic of a Semgrep rule for C code. The rule (a JSON spec of patterns) should detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

It was tested against vulnerable and safe C code and failed. Fix it. You do NOT write YAML: a program turns the JSON spec into the rule file.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

### How Semgrep matches

- A pattern is C code with metavariables and `...`. In a multi-line pattern every statement must end with `;`. A single-line pattern such as `free($P)` is an expression pattern and needs no `;`.
- **Search rule** (`search`): reports code that matches `pattern` (or any of the patterns in `either`), keeping only matches that are inside every pattern of `inside`, that are not equal to any pattern of `not`, and that are not inside any pattern of `not_inside`.
- **Taint rule** (`taint`): follows data along the control flow of one function. Semgrep reports code that matches a `sinks` pattern when a value produced by a `sources` pattern reaches it, unless it passed through a `sanitizers` pattern first. If a source is an expression that matches a variable (e.g. the argument of a call), set `focus` to the metavariable of that variable and `by_side_effect` to `true`: from that point on the variable itself is regarded as tainted, not just that one occurrence. Sinks may also use `focus` to report a sub-expression. Any entry can list patterns in `not` to exclude matches equal to them. A sanitizer by side effect (`focus` + `by_side_effect`) makes the variable safe again from that point on.

Spec keys: `message`, and exactly one of `search` (`pattern` or `either`; optional `inside`, `not`, `not_inside`) or `taint` (`sources`, `sinks`, optional `sanitizers`; each entry is `{"pattern": "...", "focus": "$X", "by_side_effect": true}` where `focus`, `by_side_effect` and `not` (a list of patterns) are optional and `by_side_effect` only applies to sources and sanitizers). Use `\n` for line breaks inside a pattern string.

### Current spec

```json
{{RULE}}
```

### Test result

{{FEEDBACK}}

{{HISTORY}}
### Vulnerable code the rule does not detect

{{MISSED_CODE}}

### Requirements

- The rule must detect the weakness in any C code, not only in this code. Use metavariables (`$P`, `$X`, `$F`...) instead of variable or function names from the code.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- It must not match the safe code listed as false positives.

### Output

First explain in at most 5 short lines what was wrong and what you change. Then write the complete corrected spec in a single json block.
