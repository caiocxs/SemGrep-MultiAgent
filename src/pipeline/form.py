"""
The "form" output format: the model fills the blanks of a Semgrep taint rule written as YAML, and the decoder is held to that skeleton
(a llama.cpp grammar), so that every answer is a rule file with the fixed keys, the fixed `focus-metavariable: $X` lines and quoted
single-line patterns in the slots, and nothing else. What the model decides is the message, the patterns and how many there are:

  source     one pattern that binds `$X` (the statement that puts the variable in a state)
  sinks      one to four patterns that mention `$X` (the uses that are the problem), each with up to two `pattern-not-inside`
  sanitizers zero to four patterns that mention `$X` (what puts it back in a clean state)

The grammar is the strategy (taint by side effect on one variable), which is our knowledge, as in the template format; the docs of
the loop (docs/graph_progress.md) report it apart from the free-form YAML.
"""

QUOTED = r'"\"" ( [^"\\\n] | "\\" ["\\] )* "\""'


def grammar(cwe):
    """GBNF text of the form for `cwe` (the id of the rule is fixed)."""
    rule_id = "gen-" + cwe.lower()
    return f"""root ::= "rules:\\n  - id: {rule_id}\\n    languages:\\n      - c\\n    severity: ERROR\\n    message: " str "\\n    mode: taint\\n    pattern-sources:\\n" source "    pattern-sinks:\\n" sink sink? sink? sink? sanitizers?
sanitizers ::= "    pattern-sanitizers:\\n" sanitizer sanitizer? sanitizer? sanitizer?
source ::= "      - patterns:\\n          - pattern: " str "\\n          - focus-metavariable: $X\\n        by-side-effect: true\\n"
sanitizer ::= "      - patterns:\\n          - pattern: " str "\\n          - focus-metavariable: $X\\n        by-side-effect: true\\n"
sink ::= "      - patterns:\\n          - pattern: " str "\\n" inside? inside? "          - focus-metavariable: $X\\n"
inside ::= "          - pattern-not-inside: " str "\\n"
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
