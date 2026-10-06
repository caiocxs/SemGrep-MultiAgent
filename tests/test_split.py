import shutil

from src.pipeline.split import split_negatives


def make_tree(root, names):
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n", encoding="utf-8")
    return sorted(str(p) for p in root.rglob("*.c"))


NAMES = [f"dir{i % 3}/file{i}.c" for i in range(60)]


def test_split_negatives_is_disjoint_and_covers_everything(tmp_path):
    files = make_tree(tmp_path, NAMES)
    train, test = split_negatives(files, tmp_path, test_ratio=0.3, seed=0)

    assert set(train) | set(test) == set(files)
    assert not set(train) & set(test)
    assert 0.15 < len(test) / len(files) < 0.45  # about the requested ratio


def test_split_negatives_does_not_depend_on_where_the_repository_is(tmp_path):
    first = make_tree(tmp_path / "a" / "repo", NAMES)
    shutil.copytree(tmp_path / "a" / "repo", tmp_path / "elsewhere" / "clone")
    second = sorted(str(p) for p in (tmp_path / "elsewhere" / "clone").rglob("*.c"))

    _, test_a = split_negatives(first, tmp_path / "a" / "repo")
    _, test_b = split_negatives(second, tmp_path / "elsewhere" / "clone")

    relative = lambda files, root: sorted(str(f)[len(str(root)) + 1:].replace("\\", "/") for f in files)
    assert relative(test_a, tmp_path / "a" / "repo") == relative(test_b, tmp_path / "elsewhere" / "clone")


def test_split_negatives_changes_with_the_seed(tmp_path):
    files = make_tree(tmp_path, NAMES)

    assert split_negatives(files, tmp_path, seed=0)[1] != split_negatives(files, tmp_path, seed=1)[1]


def test_split_negatives_is_stable_when_other_files_appear(tmp_path):
    files = make_tree(tmp_path, NAMES)
    _, test_before = split_negatives(files, tmp_path)

    more = make_tree(tmp_path, [f"extra/new{i}.c" for i in range(20)])
    _, test_after = split_negatives(more, tmp_path)

    assert set(test_before) <= set(test_after)  # a file never moves between sides


def test_split_negatives_max_train_keeps_a_deterministic_subset(tmp_path):
    files = make_tree(tmp_path, NAMES)
    train_all, test_all = split_negatives(files, tmp_path)
    train_few, test_few = split_negatives(files, tmp_path, max_train=10)

    assert train_few == train_all[:10]
    assert test_few == test_all  # the limit only bounds the train side
