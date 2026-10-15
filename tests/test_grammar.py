import json
import shutil

import pytest

from src.pipeline.gate import collect_files
from src.pipeline.spec import TEMPLATE_SCHEMA, build_template_spec
from src.pipeline.synthesize import synthesize
from tests.test_synthesize import FIXTURES, ROOT, write_logs


def test_the_template_schema_allows_exactly_what_the_template_builder_accepts():
    answer = {"message": "m", "event": {"pattern": "free($P)", "variable": "$P"},
              "uses": ["$P->$F", {"pattern": "$F2($P)", "focus": "$P", "not": ["free(...)"], "not_inside": ["free($X)"]}],
              "resets": [{"pattern": "$P = ...", "variable": "$P"}]}
    spec, problems = build_template_spec(answer)
    assert problems == [] and spec["taint"]["sinks"]
    props = TEMPLATE_SCHEMA["properties"]
    assert set(answer) <= set(props) and set(TEMPLATE_SCHEMA["required"]) == {"message", "event", "uses"}
    assert TEMPLATE_SCHEMA["additionalProperties"] is False
    assert set(props["uses"]["items"]["anyOf"][1]["properties"]) == {"pattern", "focus", "not", "not_inside"}


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_grammar_passes_the_schema_to_every_model_call(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    seen = []

    def fake_complete(role, prompt, json_schema=None):
        seen.append(json_schema)
        return json.dumps({"message": "m", "event": {"pattern": "free($P)", "variable": "$P"}, "uses": ["$P[...]"]}), 0.0

    synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0, rules_dir=tmp_path / "rules",
               logs_dir=tmp_path / "synthesis", max_fix_attempts=1, output_format="template", grammar=True)
    assert seen and all(s is TEMPLATE_SCHEMA for s in seen)
    with pytest.raises(ValueError, match="template format only"):
        synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, rules_dir=tmp_path / "rules",
                   logs_dir=tmp_path / "synthesis", output_format="yaml", grammar=True)
