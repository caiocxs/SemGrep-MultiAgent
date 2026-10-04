"""
Deterministic handling of a model's rule output, before the gate runs:
extract the YAML block, normalize the fields the model has no reason to get
creative with (id, languages, severity, metadata), and lint for rules that
would only work on the examples they were written from.

Everything here is plain code (no LLM); problems it finds are sent to the
corrector exactly like gate feedback.
"""

import re
from pathlib import Path

import yaml

PATTERN_KEYS = {
    "pattern", "pattern-inside", "pattern-not", "pattern-not-inside",
    "pattern-regex", "pattern-not-regex",
}
TOP_LEVEL_MATCHERS = {"pattern", "patterns", "pattern-either", "pattern-regex"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO", "WARNING", "ERROR"}

# Output helpers from Juliet's std_testcase.h. A rule that names them only
# works on the benchmark, so they are treated like example-specific names.
BENCHMARK_HELPERS = {
    "printLine", "printWLine", "printIntLine", "printShortLine", "printFloatLine",
    "printLongLine", "printLongLongLine", "printSizeTLine", "printHexCharLine",
    "printWcharLine", "printUnsignedLine", "printHexUnsignedCharLine",
    "printDoubleLine", "printStructLine", "printBytesLine",
}
_BENCHMARK_NAME_RE = re.compile(r"\bCWE\d+_\w*")
_YAML_BLOCK_RE = re.compile(r"```(?:ya?ml)?[ \t]*\n(.*?)```", re.S)
_OPEN_YAML_BLOCK_RE = re.compile(r"```(?:ya?ml)?[ \t]*\n(.*)", re.S)
_IDENT_RE = re.compile(r"(?<![$\w])[A-Za-z_]\w*")


def extract_yaml(text):
    """The ```yaml block of a response (the one with `rules:` if several), or None."""
    if not isinstance(text, str):
        return None
    blocks = _YAML_BLOCK_RE.findall(text)
    for block in blocks:
        if "rules:" in block:
            return block.strip()
    if blocks:
        return blocks[0].strip()
    # Response cut off by max_tokens before the closing fence.
    m = _OPEN_YAML_BLOCK_RE.search(text)
    if m:
        return m.group(1).strip()
    idx = text.find("rules:")
    return text[idx:].strip() if idx != -1 else None


def normalize(yaml_text, rule_id, cwe):
    """
    Returns (rule_doc, problems). Fixes up id/languages/severity/message/metadata
    without touching the matching logic; returns problems for anything it
    can't fix (YAML errors, no rule, no matching operator).
    """
    if not yaml_text:
        return None, ["No YAML rule found in the response. Answer with the rule in a ```yaml block."]
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        msg = f"YAML syntax error: {' '.join(str(e).split())}"
        if "alias" in msg or "mapping values are not allowed" in msg:
            msg += (" Hint: a YAML value that starts with `*`, `&`, `!`, `%`, `@` or contains `: ` must be "
                    "quoted or written as a `|` block, e.g. `pattern: \"*$P\"`, and `message:` text with "
                    "a colon must be quoted too.")
        return None, [msg]

    if isinstance(data, dict) and "rules" in data:
        rules = data["rules"]
    elif isinstance(data, dict):
        rules = [data]
    else:
        rules = data
    if not isinstance(rules, list) or not rules or not all(isinstance(r, dict) for r in rules):
        return None, ["The YAML must have a top-level `rules:` list with at least one rule."]

    problems = []
    for i, rule in enumerate(rules):
        rule["id"] = rule_id if len(rules) == 1 else f"{rule_id}-{i + 1}"
        rule["languages"] = ["c"]
        if str(rule.get("severity", "")).upper() not in SEVERITIES:
            rule["severity"] = "ERROR"
        if not isinstance(rule.get("message"), str) or not rule["message"].strip():
            rule["message"] = f"Possible {cwe}"
        metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        metadata["cwe"] = cwe
        rule["metadata"] = metadata
        if rule.get("mode") == "taint":
            if "pattern-sources" not in rule:
                problems.append(f"Rule {rule['id']} uses `mode: taint` but has no `pattern-sources`.")
        elif not TOP_LEVEL_MATCHERS & rule.keys():
            problems.append(
                f"Rule {rule['id']} has none of `pattern`, `patterns`, `pattern-either`, "
                "`pattern-regex` (or `mode: taint` with `pattern-sources`)."
            )
    return {"rules": rules}, problems


# Operators that only make sense inside `patterns:` (or a taint entry), never
# directly at the top level of a rule.
NESTED_ONLY = {
    "pattern-not", "pattern-inside", "pattern-not-inside", "pattern-not-regex",
    "focus-metavariable", "metavariable-pattern", "metavariable-regex", "metavariable-comparison",
}
TAINT_KEYS = ("pattern-sources", "pattern-propagators", "pattern-sanitizers", "pattern-sinks")
# `pattern-not`/`-inside` may also take a `patterns`/`pattern-either` mapping (see the docs).
MAPPING_ALLOWED = {"pattern-not", "pattern-inside", "pattern-not-inside"}


# Operator names Semgrep OSS accepts. Semgrep silently ignores unknown keys in some
# places (e.g. `metavariable-patterns`), so operator-like keys are checked against this.
KNOWN_OPERATORS = PATTERN_KEYS | {
    "patterns", "pattern-either", "pattern-sources", "pattern-sinks", "pattern-sanitizers",
    "pattern-propagators", "metavariable", "metavariable-pattern", "metavariable-regex",
    "metavariable-comparison", "metavariable-analysis", "focus-metavariable",
}
_OPERATOR_PREFIXES = ("pattern", "metavariable", "focus")


def _names(keys):
    return ", ".join(f"`{k}`" for k in keys)


def _check_node(node):
    problems = []
    if isinstance(node, list):
        for item in node:
            problems += _check_node(item)
    elif isinstance(node, dict):
        for key, value in node.items():
            if key == "metadata":
                continue
            if isinstance(key, str) and key.startswith(_OPERATOR_PREFIXES) and key not in KNOWN_OPERATORS:
                problems.append(
                    f"`{key}` is not a Semgrep operator (Semgrep may ignore it silently). "
                    f"Valid operators: {_names(sorted(KNOWN_OPERATORS - {'metavariable'}))}."
                )
            if key in PATTERN_KEYS:
                if isinstance(value, list):
                    problems.append(
                        f"`{key}` must be a single pattern string, not a list. To combine several patterns "
                        "use `patterns:` (all must match) or `pattern-either:` (any can match)."
                    )
                elif isinstance(value, dict) and key not in MAPPING_ALLOWED:
                    problems.append(f"`{key}` must be a single pattern string.")
            elif key in ("patterns", "pattern-either"):
                if not isinstance(value, list):
                    problems.append(f"`{key}` must be a list of operators, e.g. `- pattern: ...`.")
                elif any(not isinstance(item, dict) for item in value):
                    problems.append(
                        f"Each item of `{key}:` must be an operator such as `- pattern: ...` or "
                        "`- pattern-not: ...`, not a bare string."
                    )
            problems += _check_node(value)
    return problems


def check_structure(rule_doc):
    """
    Common schema mistakes, explained in terms a model can act on - Semgrep's
    own message for them is often just "[...] is not of type 'string'".
    Generic Semgrep syntax only, nothing CWE-specific.
    """
    problems = []
    for rule in rule_doc["rules"]:
        if rule.get("mode") == "taint":
            for key in TAINT_KEYS:
                entries = rule.get(key)
                if key in rule and not (isinstance(entries, list) and all(isinstance(e, dict) for e in entries)):
                    problems.append(
                        f"`{key}` must be a list of entries, each starting with `- pattern: ...`, "
                        "`- patterns: [...]` or `- pattern-either: [...]`."
                    )
            misplaced = sorted((TOP_LEVEL_MATCHERS | NESTED_ONLY) & rule.keys())
            if misplaced:
                problems.append(
                    f"In a `mode: taint` rule, {_names(misplaced)} must go inside the entries of "
                    "`pattern-sources`/`pattern-sanitizers`/`pattern-sinks`, not at the top level."
                )
        else:
            matchers = sorted(TOP_LEVEL_MATCHERS & rule.keys())
            if len(matchers) > 1:
                problems.append(
                    f"A rule takes exactly one of `pattern`, `patterns`, `pattern-either`, `pattern-regex` "
                    f"at the top level, but this one has {_names(matchers)}. Combine them inside a single "
                    "`patterns:` (AND) or `pattern-either:` (OR) list."
                )
            nested = sorted(NESTED_ONLY & rule.keys())
            if nested:
                problems.append(
                    f"{_names(nested)} can't be used at the top level of a rule. Put "
                    f"{'it' if len(nested) == 1 else 'them'} inside a `patterns:` list together with "
                    "the positive `pattern`."
                )
        problems += _check_node(rule)
    return list(dict.fromkeys(problems))  # dedupe, keep order


_C_HEADER_RE = re.compile(r"^(if|else|while|for|switch|case|default|do)\b|^[A-Za-z_$]\w*:$")


def check_c_statements(rule_doc):
    """
    Multi-line patterns are C statement sequences, and Semgrep rejects a
    statement without its `;` with a bare "Parse_error". Single-line patterns
    are left alone: `free($P)` is a valid expression pattern.
    """
    missing = []
    for text in _pattern_strings(rule_doc):
        if "\n" not in text.strip():
            continue
        for line in text.splitlines():
            s = line.strip()
            if (not s or s == "..." or s.endswith((";", "{", "}", ",", "(", "...", "\\"))
                    or s.startswith(("{", "}", "//", "/*", "#", "<...")) or _C_HEADER_RE.match(s)):
                continue
            missing.append(s)
    if not missing:
        return []
    shown = ", ".join(f"`{s}`" for s in list(dict.fromkeys(missing))[:3])
    return [f"In a multi-line C pattern every statement must end with `;` (write `f($X);`, not `f($X)`). "
            f"Missing in: {shown}."]


def _pattern_strings(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in PATTERN_KEYS and isinstance(value, str):
                yield value
            else:
                yield from _pattern_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _pattern_strings(item)


def forbidden_identifiers(findings):
    """Variable names the detector reported in the examples (e.g. `data`)."""
    names = set()
    for f in findings:
        names.update(_IDENT_RE.findall(f.pointer or ""))
    return names


def lint(rule_doc, forbidden):
    """Problems that make a rule specific to the examples instead of general."""
    problems = []
    used = set()
    benchmark = set()
    for text in _pattern_strings(rule_doc):
        idents = set(_IDENT_RE.findall(text))
        used |= idents & (set(forbidden) | BENCHMARK_HELPERS)
        benchmark |= set(_BENCHMARK_NAME_RE.findall(text))
    for name in sorted(used):
        problems.append(
            f"The rule uses `{name}`, a name taken from the example code. Replace it with a "
            "metavariable (e.g. $P, $X, $F) so the rule works on any code."
        )
    for name in sorted(benchmark):
        problems.append(f"The rule uses `{name}`, a test-case-specific name. Use a metavariable instead.")
    return problems


def parse_response(text, rule_id, cwe, forbidden):
    """extract -> normalize -> structure check -> lint. Returns (yaml_text, rule_doc, problems)."""
    yaml_text = extract_yaml(text)
    rule_doc, problems = normalize(yaml_text, rule_id, cwe)
    if rule_doc is not None:
        problems = problems + check_structure(rule_doc) + check_c_statements(rule_doc)
    if rule_doc is not None and not problems:
        problems = lint(rule_doc, forbidden)
    return yaml_text, rule_doc, problems


class _LiteralDumper(yaml.SafeDumper):
    pass


def _str_representer(dumper, value):
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_LiteralDumper.add_representer(str, _str_representer)


def dump_rule(rule_doc):
    """YAML text with multi-line patterns as `|` blocks, as people write them."""
    return yaml.dump(rule_doc, Dumper=_LiteralDumper, sort_keys=False, allow_unicode=True, width=1000)


def write_rule(rule_doc, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_rule(rule_doc), encoding="utf-8")
    return path
