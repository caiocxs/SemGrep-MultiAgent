"""
The "form" output formats: the model fills the blanks of a Semgrep rule written as YAML, and the decoder is held to that skeleton
(a llama.cpp grammar), so that every answer is a rule file with the fixed keys, the fixed `focus-metavariable: $X` lines and quoted
single-line patterns in the slots, and nothing else. What the model decides is the message, the patterns and how many there are.

`form` (taint mode, one variable named `$X` followed through a function):
  source     one pattern that binds `$X` (the statement that puts the variable in a state)
  sinks      one to four patterns that mention `$X` (the uses that are the problem), each with up to two `pattern-not-inside`
  sanitizers zero to four patterns that mention `$X` (what puts it back in a clean state)

`formsearch` (search mode, for weaknesses a taint source cannot start, such as a declaration without a value):
  one to four alternatives that are the weakness (a pattern may be several statements joined with `\\n` and `...`),
  up to four `pattern-not` (the same shape when it is safe) and up to two `pattern-not-inside`

The grammar is the strategy, which is our knowledge, as in the template format; docs/graph_progress.md reports it apart from the
free-form YAML.
"""

QUOTED = r'"\"" ( [^"\\\n] | "\\" ["\\nt] )* "\""'  # a one-line string; the escapes \", \\, \n and \t are allowed inside


def grammar(cwe):
    """GBNF text of the taint form for `cwe` (the id of the rule is fixed)."""
    rule_id = "gen-" + cwe.lower()
    return f"""root ::= "rules:\\n  - id: {rule_id}\\n    languages:\\n      - c\\n    severity: ERROR\\n    message: " str "\\n    mode: taint\\n    pattern-sources:\\n" source "    pattern-sinks:\\n" sink sink? sink? sink? sanitizers?
sanitizers ::= "    pattern-sanitizers:\\n" sanitizer sanitizer? sanitizer? sanitizer?
source ::= "      - patterns:\\n          - pattern: " str "\\n          - focus-metavariable: $X\\n        by-side-effect: true\\n"
sanitizer ::= "      - patterns:\\n          - pattern: " str "\\n          - focus-metavariable: $X\\n        by-side-effect: true\\n"
sink ::= "      - patterns:\\n          - pattern: " str "\\n" inside? inside? "          - focus-metavariable: $X\\n"
inside ::= "          - pattern-not-inside: " str "\\n"
str ::= {QUOTED}
"""


def search_grammar(cwe):
    """GBNF text of the search-mode form: one to four alternatives, up to four `pattern-not` and two `pattern-not-inside`, the focus fixed."""
    rule_id = "gen-" + cwe.lower()
    return f"""root ::= "rules:\\n  - id: {rule_id}\\n    languages:\\n      - c\\n    severity: ERROR\\n    message: " str "\\n    patterns:\\n      - pattern-either:\\n" alt alt? alt? alt? negation? negation? negation? negation? inside? inside? "      - focus-metavariable: $X\\n"
alt ::= "          - pattern: " str "\\n"
negation ::= "      - pattern-not: " str "\\n"
inside ::= "      - pattern-not-inside: " str "\\n"
str ::= {QUOTED}
"""


SKELETON = """rules:
  - id: gen-<cwe>
    languages:
      - c
    severity: ERROR
    message: "<one line shown to the user>"
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: "<the statement that puts $X in a state>"
          - focus-metavariable: $X
        by-side-effect: true
    pattern-sinks:
      - patterns:
          - pattern: "<a use of $X that is a problem>"
          - pattern-not-inside: "<optional: code in which that use does not count>"
          - focus-metavariable: $X
    pattern-sanitizers:
      - patterns:
          - pattern: "<a statement that puts $X back in a clean state>"
          - focus-metavariable: $X
        by-side-effect: true
"""

SEARCH_SKELETON = """rules:
  - id: gen-<cwe>
    languages:
      - c
    severity: ERROR
    message: "<one line shown to the user>"
    patterns:
      - pattern-either:
          - pattern: "<code that is the weakness>"
          - pattern: "<another shape of the same weakness (optional, up to four)>"
      - pattern-not: "<code of the same shape that is safe (optional, up to four)>"
      - pattern-not-inside: "<code in which a match does not count (optional, up to two)>"
      - focus-metavariable: $X
"""
