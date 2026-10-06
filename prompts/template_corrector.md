You fix a Semgrep rule for C code. The rule is a JSON that fills in a predefined strategy; it should detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

It was tested against vulnerable and safe C code and failed. Fix it. You do NOT write YAML: a program builds the rule file from the JSON.

### Semgrep pattern syntax

{{PATTERN_DOCS}}

### The strategy you fill in

This rule follows one variable through the code of a function (Semgrep taint mode, by side effect):

1. An **event** is a statement that puts a variable into a new state (its pattern binds the variable with a metavariable, e.g. `$X`). From that point on, that variable is "marked".
2. A **use** is code that is a problem when it happens to a marked variable. The rule reports the use. A use is a pattern that mentions the variable through its own metavariable. Give one entry per kind of use; an entry can be a plain pattern string or an object `{"pattern": "...", "focus": "$Y", "not": ["..."], "not_inside": ["..."]}` where `focus` picks the sub-expression to report, `not` lists patterns that must not count as a use (a match is excluded only when it is exactly one of those patterns) and `not_inside` lists patterns such that a use located anywhere inside code matching one of them does not count.
3. A **reset** is a statement that puts the variable back into a clean state (an assignment, a check...). After it the variable is no longer marked. Resets are optional.

You write only the patterns. The program builds the Semgrep rule from them.

### JSON format

```json
{
  "message": "one-line description shown to the user",
  "event": {"pattern": "change_state($X)", "variable": "$X"},
  "uses": ["use_it($Y)", {"pattern": "other_use($Y, ...)", "focus": "$Y", "not": ["safe_call(...)"], "not_inside": ["wrapper(...)"]}],
  "resets": [{"pattern": "$X = $E", "variable": "$X"}]
}
```

`variable` must be a metavariable that appears in that pattern. Only `message`, `event`, `uses` and `resets` are allowed. Use `
` for line breaks inside a pattern string. These are example names only: use the code that matters for this weakness.

### Current JSON

```json
{{RULE}}
```

### Test result

{{FEEDBACK}}

### Vulnerable code the rule does not detect

{{MISSED_CODE}}

### Requirements

- The rule must detect the weakness in any C code, not only in this code. Use metavariables (`$P`, `$X`, `$F`...) instead of variable or function names from the code.
- Standard C library functions that are part of the weakness can be matched by name.
- The match must point at the line where the weakness happens.
- It must not match the safe code listed as false positives.

### Output

First explain in at most 5 short lines what was wrong and what you change. Then write the complete corrected JSON in a single json block.
