<!--
Excerpts from the official Semgrep documentation, injected into the rule
generator and corrector prompts as {{SEMGREP_DOCS}}. Only generic tool
documentation - no CWE- or benchmark-specific hints. Examples are kept as in
the original docs (mostly Python).

Sources (semgrep/semgrep-docs, LGPL-2.1, fetched 2026-09-27):
- https://semgrep.dev/docs/writing-rules/rule-syntax
- https://semgrep.dev/docs/writing-rules/pattern-syntax
- https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced
-->
## Rule schema

All required fields must be present at the top level of a rule immediately under the `rules` key.

| Field | Type | Description |
| :-- | :-- | :-- |
| `id` | string | Unique, descriptive identifier, for example: `no-unused-variable` |
| `message` | string | Message that includes why Semgrep matched this pattern and how to remediate it. |
| `severity` | string | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` (older levels `ERROR`, `WARNING`, `INFO` still work). |
| `languages` | array | Languages the rule applies to, e.g. `[c]`. |
| `pattern`* | string | Find code matching this expression |
| `patterns`* | array | Logical `AND` of multiple patterns |
| `pattern-either`* | array | Logical `OR` of multiple patterns |
| `pattern-regex`* | string | Find code matching this PCRE2-compatible pattern in multiline mode |

Only one of the keys marked * is required (or `mode: taint` with its own keys, see below).

## Operators

`pattern` looks for code matching its expression, e.g. `$X == $X` or `hashlib.md5(...)`.

`patterns` performs a logical AND of its child patterns:

```yaml
rules:
  - id: unverified-db-query
    patterns:
      - pattern: db_query(...)
      - pattern-not: db_query(..., verify=True, ...)
    message: Found unverified db query
    severity: HIGH
    languages:
      - python
```

`pattern-either` performs a logical OR of its child patterns:

```yaml
    pattern-either:
      - pattern: hashlib.sha1(...)
      - pattern: hashlib.md5(...)
```

`pattern-not` finds code that does not match its expression; useful for eliminating common false positives. It also accepts a `patterns` or `pattern-either` property and negates everything inside it.

`pattern-inside` keeps matched findings that reside within its expression, such as functions or if blocks.

`pattern-not-inside` keeps matched findings that do not reside within its expression. Useful for code missing a corresponding cleanup action like close, or problematic code that isn't inside code that mitigates the issue:

```yaml
rules:
  - id: open-never-closed
    patterns:
      - pattern: $F = open(...)
      - pattern-not-inside: |
          $F = open(...)
          ...
          $F.close()
    message: file object opened without a corresponding close
    languages:
      - python
    severity: HIGH
```

`focus-metavariable: $ARG` zooms in on the code region matched by that metavariable, instead of the whole match.

`metavariable-pattern` filters a match by running patterns against what a metavariable matched:

```yaml
      - metavariable-pattern:
          metavariable: $ARG
          patterns:
            - pattern-not: "..."
```

Evaluation of `patterns`: first all positive patterns (`pattern`, `pattern-inside`, `pattern-either`, `pattern-regex`) are intersected; then negative patterns (`pattern-not`, `pattern-not-inside`, `pattern-not-regex`) filter those ranges; then conditionals (`metavariable-pattern`, `metavariable-regex`, `metavariable-comparison`) run on metavariables bound by positive patterns; finally `focus-metavariable` is applied. Metavariables bound only by negative patterns are not available afterwards.

## Pattern syntax

The `...` ellipsis operator abstracts away a sequence of zero or more items such as arguments, statements, parameters or fields. `insecure_function(...)` finds calls regardless of arguments; `func(1, ...)` matches calls whose first argument is 1; `$FUNC(..., $ARG, ...)` matches an argument in any position.

Metavariables match code when you don't know its value ahead of time, similar to capture groups in regular expressions. They look like `$X`, `$WIDGET`, or `$USERS_2`: they begin with `$` and contain only uppercase characters, `_`, or digits (`$x` is invalid). The same metavariable used twice in a pattern must match the same code (e.g. `$X == $X`).

The deep expression operator `<... $X ...>` matches an expression that could be deeply nested within another expression, e.g. `if <... $USER.is_admin() ...>:` or `sql.query(<... $X ...>)`.

### Ellipses and statement blocks (limitation)

The ellipsis operator does *not* jump from inner to outer statement blocks. The pattern

```text
foo()
...
bar()
```

matches `foo(); baz(); bar()` and also `foo(); baz(); if cond: bar()`, but it does *not* match

```python
if cond:
    foo()
baz()
bar()
```

because `...` cannot jump from the inner block where `foo()` is, to the outer block where `bar()` is.

## Taint mode

To create a taint tracking rule, include `mode: taint` in the rule. Taint mode tracks data along the control flow of a function. It enables these operators, which act as `pattern-either` lists:

| Operator | Required? |
| - | - |
| `pattern-sources` | Yes |
| `pattern-propagators` | No |
| `pattern-sanitizers` | No |
| `pattern-sinks` | No |

Each entry can use any pattern operator (`pattern`, `patterns`, `pattern-either`, `pattern-regex`), with the same expressive power as a search-mode rule. Example:

```yaml
rules:
  - id: taint-example
    mode: taint
    pattern-sources:
      - pattern: get_user_input(...)
    pattern-sanitizers:
      - pattern: sanitize_input(...)
    pattern-sinks:
      - pattern: html_output(...)
      - pattern: eval(...)
    message: Tainted data reaches a sink
    languages: [python]
    severity: HIGH
```

Any subexpression matched by a source pattern is regarded as a source of tainted data. Any subexpression matched by a sanitizer is regarded as sanitized. For sinks, by default the matched expression itself (not its subexpressions) is the sink; set `exact: false` on a sink to make its subexpressions sinks too.

Metavariables used in `pattern-sources` are considered *different* from those used in `pattern-sinks`, even if they have the same name.

### Taint sources by side effect

Consider code where `make_tainted` makes its argument tainted by side effect:

```python
make_tainted(my_set)
sink(my_set)
```

This kind of source is specified by setting `by-side-effect: true`:

```yaml
pattern-sources:
   - patterns:
      - pattern: make_tainted($X)
      - focus-metavariable: $X
     by-side-effect: true
```

When `by-side-effect: true` is enabled and the source matches a variable (an l-value) exactly, Semgrep assumes that the variable becomes tainted by side effect at the places where the source produces a match. You must use `focus-metavariable: $X` to focus the match on the l-value to taint; otherwise `by-side-effect` does not work. Without `by-side-effect`, only the very occurrence of `x` in `make_tainted(x)` is tainted, not the one in `sink(x)`, so the rule produces no finding.

### Taint sanitizers by side effect

Consider code where, after `check_if_safe(x)`, the value of `x` must be safe:

```python
x = source()
check_if_safe(x)
sink(x)
```

This kind of sanitizer is specified by setting `by-side-effect: true`:

```yaml
pattern-sanitizers:
  - patterns:
      - pattern: check_if_safe($X)
      - focus-metavariable: $X
    by-side-effect: true
```

If the sanitizer matches a variable (an l-value) exactly, Semgrep assumes that the variable is sanitized by side effect at the places where the sanitizer matches. Use `focus-metavariable: $X` to focus the match on the l-value to sanitize.
