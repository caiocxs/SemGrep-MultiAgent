import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("export_results", ROOT / "scripts" / "export_results.py")
export_results = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_results)


def summary(path, **extra):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"seed": 1, "folds": [], **extra}), encoding="utf-8")
    return path


def test_summaries_are_copied_with_their_combo_and_cwe_folders(tmp_path):
    source, dest = tmp_path / "logs", tmp_path / "results"
    summary(source / "D" / "CWE-416" / "a.json")
    summary(source / "C" / "CWE-415" / "b.json", docs=False)

    written = export_results.export(source, dest)

    assert sorted(p.relative_to(dest).as_posix() for p in written) == ["C/CWE-415/b.json", "D/CWE-416/a.json"]
    assert json.loads((dest / "C" / "CWE-415" / "b.json").read_text(encoding="utf-8"))["docs"] is False


def test_a_second_export_copies_nothing_until_a_summary_changes(tmp_path):
    source, dest = tmp_path / "logs", tmp_path / "results"
    first = summary(source / "D" / "CWE-416" / "a.json")
    assert len(export_results.export(source, dest)) == 1
    assert export_results.export(source, dest) == []

    summary(first, seed=2)  # same file, new content
    assert len(export_results.export(source, dest)) == 1


def test_files_that_are_not_summaries_are_left_out(tmp_path):
    source, dest = tmp_path / "logs", tmp_path / "results"
    (source / "D").mkdir(parents=True)
    (source / "D" / "other.json").write_text(json.dumps({"hello": 1}), encoding="utf-8")
    (source / "D" / "broken.json").write_text("{", encoding="utf-8")
    (source / "D" / "notes.txt").write_text("x", encoding="utf-8")

    assert export_results.export(source, dest) == []
    assert not dest.exists()
