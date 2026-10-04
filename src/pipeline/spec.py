"""
Structured output mode for the generator/corrector: instead of writing the
rule's YAML, the model writes a small JSON spec with only the patterns, and
this module builds the rule from it. The model never touches YAML quoting,
operator nesting or schema keys, which is where small models kept failing.

The matching logic is entirely the model's: every pattern comes from the spec
and nothing is added, removed or rewritten here. The rest of the pipeline
(normalize, structure/`;`/name checks, gate) runs unchanged on the built rule.

Spec format:

    {"message": "...",
     "taint": {"sources":    [{"pattern": "...", "focus": "$X", "by_side_effect": true}],
               "sinks":      [{"pattern": "...", "focus": "$X", "not": ["..."]}],
               "sanitizers": [{"pattern": "...", "focus": "$X", "by_side_effect": true}]}}

or, without data flow:

    {"message": "...",
     "search": {"pattern": "..."  (or "either": ["...", "..."]),
                "inside": ["..."], "not": ["..."], "not_inside": ["..."]}}
"""

import json
import re

from src.pipeline.rules import check_c_statements, check_structure, dump_rule, lint, normalize

_JSON_BLOCK_RE = re.compile(r"```(?:json)?[ \t]*\n(.*?)```", re.S)
_TAINT_ROLES = {"sources": "pattern-sources", "sinks": "pattern-sinks", "sanitizers": "pattern-sanitizers"}
_ENTRY_KEYS = {"pattern", "focus", "by_side_effect", "not"}
_SEARCH_KEYS = {"pattern", "either", "inside", "not", "not_inside"}


def extract_json(text):
    """The JSON object of a response: a fenced block, else the outermost {...}."""
    if not isinstance(text, str):
        return None
    for block in _JSON_BLOCK_RE.findall(text):
        if "{" in block:
            return block.strip()
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if start != -1 and end > start else None


def _pattern(value, where, problems):
    if isinstance(value, str) and value.strip():
        return value
    problems.append(f"{where} must be a non-empty pattern string.")
    return None


def _pattern_list(value, where, problems):
    if not isinstance(value, list) or not value:
        problems.append(f"{where} must be a non-empty list of pattern strings.")
        return []
    return [p for i, item in enumerate(value) if (p := _pattern(item, f"{where}[{i}]", problems))]


def _taint_entry(entry, where, problems, allow_side_effect):
    """One source/sink/sanitizer. `not` excludes matches equal to those patterns."""
    if not isinstance(entry, dict):
        problems.append(f'{where} must be an object like {{"pattern": "..."}}.')
        return None
    unknown = sorted(set(entry) - _ENTRY_KEYS)
    if unknown:
        problems.append(f"{where} has unknown keys {', '.join(f'`{k}`' for k in unknown)}; "
                        "allowed: `pattern`, `focus`, `by_side_effect`, `not`.")
    pattern = _pattern(entry.get("pattern"), f"{where}.pattern", problems)
    if pattern is None:
        return None
    focus = entry.get("focus")
    if focus is not None and not (isinstance(focus, str) and focus.startswith("$")):
        problems.append(f"{where}.focus must be a metavariable such as \"$X\".")
        focus = None
    side_effect = bool(entry.get("by_side_effect"))
    if side_effect and not allow_side_effect:
        problems.append(f"{where}: `by_side_effect` only applies to sources and sanitizers.")
    if side_effect and not focus:
        problems.append(f"{where}: `by_side_effect` needs `focus` (the metavariable that becomes tainted).")
    excluded = _pattern_list(entry["not"], f"{where}.not", problems) if "not" in entry else []
    if not focus and not excluded:
        return {"pattern": pattern}
    built = {"patterns": [{"pattern": pattern}] + [{"pattern-not": n} for n in excluded]
             + ([{"focus-metavariable": focus}] if focus else [])}
    if side_effect and allow_side_effect and focus:
        built["by-side-effect"] = True
    return built


def _build_taint(taint, problems):
    rule = {"mode": "taint"}
    if not isinstance(taint, dict):
        problems.append('`taint` must be an object with `sources` and `sinks` (and optionally `sanitizers`).')
        return rule
    unknown = sorted(set(taint) - set(_TAINT_ROLES))
    if unknown:
        problems.append(f"`taint` has unknown keys {', '.join(f'`{k}`' for k in unknown)}; "
                        "allowed: `sources`, `sinks`, `sanitizers`.")
    for role, key in _TAINT_ROLES.items():
        if role not in taint:
            if role != "sanitizers":
                problems.append(f"`taint.{role}` is required.")
            continue
        entries = taint[role]
        if not isinstance(entries, list) or not entries:
            problems.append(f"`taint.{role}` must be a non-empty list of objects.")
            continue
        built = [_taint_entry(e, f"taint.{role}[{i}]", problems, role != "sinks") for i, e in enumerate(entries)]
        rule[key] = [b for b in built if b]
    return rule


def _build_search(search, problems):
    if not isinstance(search, dict):
        problems.append("`search` must be an object with `pattern` (or `either`) and optional "
                        "`inside`, `not`, `not_inside`.")
        return {}
    unknown = sorted(set(search) - _SEARCH_KEYS)
    if unknown:
        problems.append(f"`search` has unknown keys {', '.join(f'`{k}`' for k in unknown)}; "
                        "allowed: `pattern`, `either`, `inside`, `not`, `not_inside`.")
    if ("pattern" in search) == ("either" in search):
        problems.append("`search` needs exactly one of `pattern` or `either`.")
        return {}
    if "pattern" in search:
        main = {"pattern": _pattern(search["pattern"], "search.pattern", problems)}
    else:
        main = {"pattern-either": [{"pattern": p} for p in _pattern_list(search["either"], "search.either", problems)]}
    extras = []
    for key, operator in (("inside", "pattern-inside"), ("not", "pattern-not"), ("not_inside", "pattern-not-inside")):
        if key in search:
            extras += [{operator: p} for p in _pattern_list(search[key], f"search.{key}", problems)]
    return {"patterns": [main] + extras} if extras else main


def build_rule(spec):
    """Returns (rule_dict, problems) for a parsed spec."""
    problems = []
    if not isinstance(spec, dict):
        return None, ["The JSON must be an object with `message` and either `taint` or `search`."]
    unknown = sorted(set(spec) - {"message", "taint", "search"})
    if unknown:
        problems.append(f"Unknown top-level keys {', '.join(f'`{k}`' for k in unknown)}; "
                        "allowed: `message`, `taint`, `search`.")
    if ("taint" in spec) == ("search" in spec):
        problems.append("Give exactly one of `taint` or `search`.")
        return None, problems
    rule = {"message": spec.get("message") if isinstance(spec.get("message"), str) else ""}
    rule.update(_build_taint(spec["taint"], problems) if "taint" in spec else _build_search(spec["search"], problems))
    return rule, problems


def _finish(spec_text, rule, problems, rule_id, cwe, forbidden):
    """Shared by the JSON formats: built rule -> normalize -> structure/`;`/name checks."""
    if rule is None or problems:
        return spec_text, None, problems
    rule_doc, problems = normalize(dump_rule({"rules": [rule]}), rule_id, cwe)
    if rule_doc is not None:
        problems = problems + check_structure(rule_doc) + check_c_statements(rule_doc)
    if rule_doc is not None and not problems:
        problems = lint(rule_doc, forbidden)
    return spec_text, rule_doc, problems


def _no_duplicates(pairs):
    """json.loads keeps only the last of two equal keys; report them instead."""
    seen, duplicated = {}, []
    for key, value in pairs:
        if key in seen and key not in duplicated:
            duplicated.append(key)
        seen[key] = value
    if duplicated:
        raise ValueError("duplicate keys: " + ", ".join(f"`{k}`" for k in duplicated))
    return seen


def _load_json(text):
    """Returns (spec, spec_text, problems); spec_text is the pretty JSON the corrector shows."""
    raw = extract_json(text)
    if raw is None:
        return None, None, ["No JSON spec found in the response. Answer with the spec in a ```json block."]
    try:
        spec = json.loads(raw, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as e:
        return None, raw, [f"JSON syntax error: {e}. Check quotes, commas and that a backslash followed by n "
                           "is used for line breaks inside a pattern."]
    except ValueError as e:
        return None, raw, [f"The JSON has {e}. Each key may appear only once: merge the values into one list."]
    return spec, json.dumps(spec, indent=2, ensure_ascii=False), []


def parse_response(text, rule_id, cwe, forbidden):
    """
    Same contract as `rules.parse_response`, for spec-format answers:
    returns (spec_text, rule_doc, problems). `spec_text` is the spec as
    pretty JSON (what the corrector shows the model as the current rule).
    """
    spec, spec_text, problems = _load_json(text)
    if spec is None:
        return spec_text, None, problems
    rule, problems = build_rule(spec)
    return _finish(spec_text, rule, problems, rule_id, cwe, forbidden)


# --- Template format -------------------------------------------------------
# A predefined strategy (written by us, not by the model): an event puts a
# variable into a new state, some uses of the variable afterwards are the
# problem, and some statements put it back into a clean state. The code turns
# it into a taint rule by side effect; the model only fills in the patterns.
#
#   {"message": "...",
#    "event":  {"pattern": "...", "variable": "$X"},
#    "uses":   ["...", {"pattern": "...", "focus": "$Y", "not": ["..."]}],
#    "resets": [{"pattern": "...", "variable": "$X"}]}

_EVENT_KEYS = {"pattern", "variable"}


def _state_change(entry, where, problems):
    """`{"pattern", "variable"}`; the variable must be a metavariable that the pattern binds."""
    if not isinstance(entry, dict):
        problems.append(f'{where} must be an object like {{"pattern": "...", "variable": "$X"}}.')
        return None
    unknown = sorted(set(entry) - _EVENT_KEYS)
    if unknown:
        problems.append(f"{where} has unknown keys {', '.join(f'`{k}`' for k in unknown)}; "
                        "allowed: `pattern`, `variable`.")
    pattern = _pattern(entry.get("pattern"), f"{where}.pattern", problems)
    variable = entry.get("variable")
    if not (isinstance(variable, str) and variable.startswith("$")):
        problems.append(f'{where}.variable must be a metavariable such as "$X".')
        return None
    if pattern is not None and variable not in pattern:
        problems.append(f"{where}.variable `{variable}` does not appear in the pattern `{pattern}`.")
        return None
    return {"pattern": pattern, "focus": variable, "by_side_effect": True} if pattern else None


def build_template_spec(spec):
    """Turns a template answer into a spec (taint) dict. Returns (spec, problems)."""
    problems = []
    if not isinstance(spec, dict):
        return None, ["The JSON must be an object with `message`, `event`, `uses` and optionally `resets`."]
    unknown = sorted(set(spec) - {"message", "event", "uses", "resets"})
    if unknown:
        problems.append(f"Unknown top-level keys {', '.join(f'`{k}`' for k in unknown)}; "
                        "allowed: `message`, `event`, `uses`, `resets`.")
    event = _state_change(spec.get("event"), "event", problems) if "event" in spec else None
    if "event" not in spec:
        problems.append("`event` is required.")
    uses = spec.get("uses")
    if not isinstance(uses, list) or not uses:
        problems.append("`uses` must be a non-empty list of patterns or objects.")
        uses = []
    sinks = [{"pattern": u} if isinstance(u, str) else u for u in uses]
    sanitizers = []
    resets = spec.get("resets", [])
    if not isinstance(resets, list):
        problems.append("`resets` must be a list of objects like "
                        '{"pattern": "...", "variable": "$X"}.')
        resets = []
    for i, entry in enumerate(resets):
        built = _state_change(entry, f"resets[{i}]", problems)
        if built:
            sanitizers.append(built)
    taint = {"sources": [event] if event else [], "sinks": sinks}
    if sanitizers:
        taint["sanitizers"] = sanitizers
    return {"message": spec.get("message", ""), "taint": taint}, problems


def parse_template_response(text, rule_id, cwe, forbidden):
    """Same contract as `parse_response`, for template-format answers."""
    spec, spec_text, problems = _load_json(text)
    if spec is None:
        return spec_text, None, problems
    taint_spec, problems = build_template_spec(spec)
    if taint_spec is None or problems:
        return spec_text, None, problems
    rule, problems = build_rule(taint_spec)
    return _finish(spec_text, rule, problems, rule_id, cwe, forbidden)
