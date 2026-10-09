You design the matching logic of ONE generic Semgrep rule for C code that detects:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

A code analyzer reported this weakness in the examples below. Its reports can contain mistakes (wrong line numbers, or code that is actually safe): treat the code itself as the ground truth.

You do NOT write YAML. You write a JSON spec containing only the Semgrep patterns; a program turns it into the rule file.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

### How Semgrep matches

- A pattern is C code with metavariables and `...`. In a multi-line pattern every statement must end with `;`. A single-line pattern such as `free($P)` is an expression pattern and needs no `;`.
- **Search rule** (`search`): reports code that matches `pattern` (or any of the patterns in `either`), keeping only matches that are inside every pattern of `inside`, that are not equal to any pattern of `not`, and that are not inside any pattern of `not_inside`.
- **Taint rule** (`taint`): follows data along the control flow of one function. Semgrep reports code that matches a `sinks` pattern when a value produced by a `sources` pattern reaches it, unless it passed through a `sanitizers` pattern first. If a source is an expression that matches a variable (e.g. the argument of a call), set `focus` to the metavariable of that variable and `by_side_effect` to `true`: from that point on the variable itself is regarded as tainted, not just that one occurrence. Sinks may also use `focus` to report a sub-expression. Any entry can list patterns in `not` to exclude matches equal to them. A sanitizer by side effect (`focus` + `by_side_effect`) makes the variable safe again from that point on.

### JSON spec format

Search rule:

```json
{
  "message": "one-line description shown to the user",
  "search": {
    "pattern": "foo($X);\n...\nbar($X);",
    "inside": ["..."],
    "not": ["..."],
    "not_inside": ["..."]
  }
}
```

Taint rule:

```json
{
  "message": "one-line description shown to the user",
  "taint": {
    "sources": [{"pattern": "make_tainted($X)", "focus": "$X", "by_side_effect": true}],
    "sinks": [{"pattern": "sink($X)"}],
    "sanitizers": [{"pattern": "clean($X)"}]
  }
}
```

Only `search` OR `taint` (never both). `inside`, `not`, `not_inside`, `sanitizers`, `focus` and `by_side_effect` are optional; `either` can replace `pattern` in a search rule. Use `\n` for line breaks inside a pattern string. These are example names only: use the calls that matter for this weakness.

### Examples

{{EXAMPLES}}

{{PROJECT_APIS}}
### Requirements

- The rule must detect the weakness in any C code, not only in these examples. Use metavariables (`$P`, `$X`, `$F`...) instead of variable or function names from the examples.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- Avoid false positives: think about what makes similar-looking code safe and exclude it.

### Output

First explain your strategy in at most 5 short lines. Then write the spec in a single json block.
