from src.pipeline.findings import Finding
from src.pipeline.rules import dump_rule, extract_yaml, forbidden_identifiers, lint, normalize, parse_response
from src.pipeline.split import flow_variant, split_files

RULE = """rules:
  - id: whatever
    languages: [python]
    message: m
    pattern: free($P)
"""


def test_extract_yaml_prefers_block_with_rules():
    text = f"Strategy: ...\n```yaml\nfoo: 1\n```\nand\n```yaml\n{RULE}```\n"
    assert extract_yaml(text).startswith("rules:")


def test_extract_yaml_handles_truncated_block():
    assert extract_yaml(f"Strategy\n```yaml\n{RULE}").startswith("rules:")


def test_extract_yaml_without_block():
    assert extract_yaml("no rule here") is None


def test_normalize_fixes_metadata_fields():
    doc, problems = normalize(RULE, "gen-cwe-416", "CWE-416")
    rule = doc["rules"][0]
    assert problems == []
    assert rule["id"] == "gen-cwe-416"
    assert rule["languages"] == ["c"]
    assert rule["severity"] == "ERROR"
    assert rule["metadata"]["cwe"] == "CWE-416"


def test_normalize_accepts_bare_rule_and_reports_errors():
    doc, problems = normalize("id: x\npattern: free($P)\n", "gen", "CWE-416")
    assert problems == [] and doc["rules"][0]["pattern"] == "free($P)"

    assert normalize("rules: [\n", "gen", "CWE-416")[1][0].startswith("YAML syntax error")
    assert "none of `pattern`" in normalize("rules:\n  - id: x\n    message: m\n", "gen", "CWE-416")[1][0]
    assert "pattern-sources" in normalize("rules:\n  - id: x\n    mode: taint\n", "gen", "CWE-416")[1][0]


def test_lint_rejects_example_names_but_allows_metavariables():
    forbidden = forbidden_identifiers([Finding(file=None, cwe="CWE-416", pointer="*data")])
    assert forbidden == {"data"}

    specific, _ = normalize("rules:\n  - id: x\n    pattern: |\n      free(data);\n      printLine(data);\n", "g", "CWE-416")
    problems = lint(specific, forbidden)
    assert any("`data`" in p for p in problems)
    assert any("`printLine`" in p for p in problems)

    generic, _ = normalize("rules:\n  - id: x\n    pattern: |\n      free($DATA);\n      $F($DATA);\n", "g", "CWE-416")
    assert lint(generic, forbidden) == []


def test_parse_response_and_dump_roundtrip():
    text = "Plan.\n```yaml\nrules:\n  - id: x\n    pattern: |\n      free($P);\n      ...\n      $F($P);\n```"
    _, doc, problems = parse_response(text, "gen", "CWE-416", set())
    assert problems == []
    assert "pattern: |" in dump_rule(doc)


def test_split_keeps_variants_together():
    files = [f"CWE416_Use_After_Free__malloc_free_{t}_{v}_bad.c" for t in ("char", "int") for v in ("01", "02", "63a", "63b")]
    assert flow_variant(files[2]) == "63"
    train, test, variants = split_files(files, test_ratio=0.3, seed=1)
    assert len(variants) == 1 and sorted(train + test) == sorted(files)
    assert all(flow_variant(f) in variants for f in test)
    assert all(flow_variant(f) not in variants for f in train)
    assert split_files(files, 0.3, 1) == (train, test, variants)  # deterministic


def _structure_problems(yaml_text):
    from src.pipeline.rules import check_structure
    doc, problems = normalize(yaml_text, "gen", "CWE-416")
    assert problems == []
    return check_structure(doc)


def test_structure_explains_pattern_list_and_top_level_negation():
    # The rule Qwen2.5-Coder-3B produced in its first real run.
    problems = _structure_problems("""
rules:
  - id: x
    message: m
    severity: HIGH
    languages: [c]
    pattern:
      - pattern: |
          $P = malloc($SIZE)
          ...
          free($P)
    pattern-not:
      - pattern: free($P)
    focus-metavariable: $P
""")
    assert any("`pattern` must be a single pattern string, not a list" in p for p in problems)
    assert any("`focus-metavariable`, `pattern-not` can't be used at the top level" in p for p in problems)


def test_structure_flags_several_top_level_matchers_and_bare_strings():
    problems = _structure_problems("rules:\n  - id: x\n    pattern: a($X)\n    patterns:\n      - b($X)\n")
    assert any("exactly one of" in p for p in problems)
    assert any("not a bare string" in p for p in problems)


def test_structure_flags_misplaced_taint_operators():
    problems = _structure_problems(
        "rules:\n  - id: x\n    mode: taint\n    pattern-sources: free($P)\n    pattern: use($P)\n")
    assert any("`pattern-sources` must be a list" in p for p in problems)
    assert any("In a `mode: taint` rule, `pattern` must go inside" in p for p in problems)


def test_structure_accepts_valid_search_and_taint_rules():
    from pathlib import Path
    assert _structure_problems(
        "rules:\n  - id: x\n    patterns:\n      - pattern: a($X)\n      - pattern-not: a(1)\n") == []
    fixture = Path(__file__).parent / "fixtures" / "rules" / "cwe416_uaf.yaml"
    assert _structure_problems(fixture.read_text()) == []


def test_c_statements_need_semicolons_in_multiline_patterns():
    from src.pipeline.rules import check_c_statements
    # Attempt 2 of Qwen2.5-Coder-3B's second real run.
    doc, _ = normalize("rules:\n  - id: x\n    pattern: |\n      $P = malloc($SIZE)\n      ...\n      free($P)\n", "g", "CWE-416")
    problems = check_c_statements(doc)
    assert len(problems) == 1 and "`$P = malloc($SIZE)`, `free($P)`" in problems[0]

    ok, _ = normalize(
        "rules:\n  - id: x\n    patterns:\n      - pattern: free($P)\n      - pattern-inside: |\n"
        "          if ($C) {\n            ...\n          }\n          free($P);\n", "g", "CWE-416")
    assert check_c_statements(ok) == []


def test_structure_rejects_operator_names_outside_the_schema():
    # Invented by Qwen2.5-Coder-3B in a real run; Semgrep accepted it silently.
    problems = _structure_problems(
        "rules:\n  - id: x\n    patterns:\n      - pattern: a($X)\n      - metavariable-patterns:\n"
        "          metavariable: $X\n")
    assert any("`metavariable-patterns` is not a Semgrep operator" in p for p in problems)
    # `metadata` is free-form and must not be checked.
    assert _structure_problems(
        "rules:\n  - id: x\n    pattern: a($X)\n    metadata:\n      pattern-note: ok\n") == []


def test_yaml_alias_error_gets_a_quoting_hint():
    # Qwen3-4B wrote `- pattern: *$P` in most attempts of its real runs.
    _, problems = normalize("rules:\n  - id: x\n    patterns:\n      - pattern: *$P\n", "g", "CWE-416")
    assert len(problems) == 1 and "must be quoted" in problems[0]
