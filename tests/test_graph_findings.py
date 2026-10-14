import json
import shutil
from pathlib import Path

import pytest

from src.graph import export_findings, extract, paths
from src.pipeline.gate import collect_files
from src.pipeline.synthesize import synthesize
from tests.test_synthesize import FIXTURES, KNOWN_GOOD_RULE, ROOT


def test_the_graph_alerts_are_written_in_the_layout_the_generator_reads(tmp_path):
    src = tmp_path / "CWE416_x_01_bad.c"
    src.write_text("void f(void) {\n char *p = malloc(4);\n free(p);\n p[0] = 1;\n}\n", encoding="utf-8")
    clean = tmp_path / "CWE416_x_01_good.c"
    clean.write_text("void f(void) {\n char *p = malloc(4);\n p[0] = 1;\n free(p);\n}\n", encoding="utf-8")
    conn, _ = extract.build([src, clean])
    total = export_findings.write_logs(paths.use_after_free(conn), "use_after_free", [src, clean], tmp_path / "logs")
    assert total == 1
    bad = json.loads((tmp_path / "logs" / "log_CWE416_x_01_bad.json").read_text())
    assert bad["vulnerable"] and bad["findings"][0]["cwe"] == "CWE-416"
    finding = bad["findings"][0]
    assert (finding["pointer"], finding["source_line"], finding["violation_line"]) == ("p", 3, 4)
    assert finding["source_code"] == "free(p);" and finding["violation_code"] == "p[0] = 1;"
    assert "released at line 3 and used at line 4" in finding["description"]
    good = json.loads((tmp_path / "logs" / "log_CWE416_x_01_good.json").read_text())
    assert good["findings"] == [] and not good["vulnerable"]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_example_mode_graph_shows_the_graph_alerts_to_the_generator(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr("src.pipeline.synthesize.GRAPH_LOGS", tmp_path / "graph")
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    conn, _ = extract.build(bad + good)
    export_findings.write_logs(paths.use_after_free(conn), "use_after_free", bad + good, tmp_path / "graph" / "cwe_416")
    prompts = []

    def fake_complete(role, prompt):
        prompts.append((role, prompt))
        return f"```yaml\n{KNOWN_GOOD_RULE.read_text()}```", 0.0

    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "does-not-exist"], complete=fake_complete, min_recall=0.0,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=0, example_mode="graph")
    assert "event-graph" not in prompts[0][1]  # the generator is shown the alert, not the name of the analyzer
    assert "released at line" in prompts[0][1] and "Analyzer report" in prompts[0][1]
    assert run["roles"]["example_mode"] == "graph"


def test_example_mode_graph_without_exported_findings_says_what_to_run(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr("src.pipeline.synthesize.GRAPH_LOGS", tmp_path / "graph")
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    with pytest.raises(RuntimeError, match="export_findings"):
        synthesize("CWE-416", "A", bad, good, [tmp_path], complete=lambda r, p: ("", 0.0), rules_dir=tmp_path / "rules",
                   logs_dir=tmp_path / "synthesis", example_mode="graph")
