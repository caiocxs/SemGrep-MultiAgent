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

`apply_field`/`fields` support the corrector's `field_correct` mode (see synthesize.py): instead of rewriting the whole rule, the
corrector answers with the new value of one field (one alternative, one `pattern-not`, one sink...), found generically by walking
the already-parsed rule for `pattern`/`pattern-not`/`pattern-not-inside` leaves - the same walk works for both the taint and the
search skeleton, since it does not know about "sources" or "alternatives", only about those three keys.
"""

import copy
import json

from src.pipeline.rules import check_c_statements, check_structure, lint

QUOTED = r'"\"" ( [^"\\\n] | "\\" ["\\nt] )* "\""'  # a one-line string; the escapes \", \\, \n and \t are allowed inside
FIELD_GRAMMAR = f"root ::= {QUOTED}\n"  # one field's answer: the same one-line string, nothing else around it


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

FIELD_KEYS = ("pattern", "pattern-not", "pattern-not-inside")


def _walk_fields(node, path):
    """(path, value) of every `pattern`/`pattern-not`/`pattern-not-inside` string leaf, in document order."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in FIELD_KEYS and isinstance(value, str):
                yield path + [key], value
            else:
                yield from _walk_fields(value, path + [key])
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_fields(item, path + [i])


def fields(rule_doc):
    """(path, key, value) of every field of the rule's single rule, path being the keys/indices to the dict that holds `key`."""
    return [(path[:-1], path[-1], value) for path, value in _walk_fields(rule_doc["rules"][0], [])]


def get_field(rule_doc, path, key):
    node = rule_doc["rules"][0]
    for step in path:
        node = node[step]
    return node[key]


def set_field(rule_doc, path, key, value):
    """A deep copy of `rule_doc` with the field at `path`/`key` replaced by `value`."""
    new_doc = copy.deepcopy(rule_doc)
    node = new_doc["rules"][0]
    for step in path:
        node = node[step]
    node[key] = value
    return new_doc


def describe_field(path, key):
    """
    What a field is, in words for the corrector prompt - generic across the taint and search skeletons, and
    across a hand-written yaml rule once field_correct is used with that format too (synthesize.py).
    """
    where = None
    if "pattern-sources" in path:
        where = "the taint source"
    elif "pattern-sanitizers" in path:
        idx = path[path.index("pattern-sanitizers") + 1]
        where = f"sanitizer {idx + 1}"
    elif "pattern-sinks" in path:
        idx = path[path.index("pattern-sinks") + 1]
        where = f"sink {idx + 1}"
    elif "pattern-either" in path:
        idx = path[path.index("pattern-either") + 1]
        where = f"alternative {idx + 1} of the weakness (pattern-either)"

    if key == "pattern":
        if where == "the taint source":
            return "the taint source: the statement that puts $X in a tainted state"
        if where and where.startswith("sanitizer"):
            return f"{where}: a statement that puts $X back in a clean state"
        if where and where.startswith("sink"):
            return f"{where}: a use of $X that is a problem"
        return where or "the pattern"
    if key == "pattern-not-inside":
        return f"{where}'s pattern-not-inside: code in which that use does not count" if where \
            else "a pattern-not-inside: code in which a match does not count"
    if key == "pattern-not":
        return f"{where}'s pattern-not: code of the same shape that does not count" if where \
            else "a pattern-not: code of the same shape that is safe"
    return key


def parse_field_value(text):
    """The model's one-field answer (held to FIELD_GRAMMAR): a JSON string, since its escapes are a subset of JSON's."""
    stripped = text.strip()
    try:
        value = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None, [f"Could not parse the field's value as a quoted string: {stripped[:200]!r}"]
    if not isinstance(value, str) or not value.strip():
        return None, ["The field's value must be a non-empty quoted string."]
    return value, []


def apply_field(text, rule_doc, path, key, forbidden):
    """
    Splices the model's single-field answer into a copy of `rule_doc`. Mirrors
    rules.parse_response's return shape (yaml_text, rule_doc, problems); yaml_text
    is unused here since form/formsearch always re-dump rule_doc (see synthesize.step).
    """
    value, problems = parse_field_value(text)
    if problems:
        return None, None, problems
    new_doc = set_field(rule_doc, path, key, value)
    problems = check_structure(new_doc) + check_c_statements(new_doc)
    if not problems:
        problems = lint(new_doc, forbidden)
    return None, new_doc, problems
