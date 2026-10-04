You fill in a predefined strategy to make ONE generic Semgrep rule for C code that detects:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

A code analyzer reported this weakness in the examples below. Its reports can contain mistakes (wrong line numbers, or code that is actually safe): treat the code itself as the ground truth.

You do NOT write YAML. You write a JSON containing only the Semgrep patterns for the strategy below; a program turns it into the rule file.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

### The strategy you fill in

This rule follows one variable through the code of a function (Semgrep taint mode, by side effect):

1. An **event** is a statement that puts a variable into a new state (its pattern binds the variable with a metavariable, e.g. `$X`). From that point on, that variable is "marked".
2. A **use** is code that is a problem when it happens to a marked variable. The rule reports the use. A use is a pattern that mentions the variable through its own metavariable. Give one entry per kind of use; an entry can be a plain pattern string or an object `{"pattern": "...", "focus": "$Y", "not": ["..."]}` where `focus` picks the sub-expression to report and `not` lists patterns that must not count as a use.
3. A **reset** is a statement that puts the variable back into a clean state (an assignment, a check...). After it the variable is no longer marked. Resets are optional.

You write only the patterns. The program builds the Semgrep rule from them.

### JSON format

```json
{
  "message": "one-line description shown to the user",
  "event": {"pattern": "change_state($X)", "variable": "$X"},
  "uses": ["use_it($Y)", {"pattern": "other_use($Y, ...)", "focus": "$Y", "not": ["safe_call(...)"]}],
  "resets": [{"pattern": "$X = $E", "variable": "$X"}]
}
```

`variable` must be a metavariable that appears in that pattern. Only `message`, `event`, `uses` and `resets` are allowed. Use `
` for line breaks inside a pattern string. These are example names only: use the code that matters for this weakness.

### Examples

{{EXAMPLES}}

### Requirements

- The rule must detect the weakness in any C code, not only in these examples. Use metavariables (`$P`, `$X`, `$F`...) instead of variable or function names from the examples.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- Avoid false positives: think about what makes similar-looking code safe and exclude it.

### Output

First explain your strategy in at most 5 short lines. Then write the JSON in a single json block.
