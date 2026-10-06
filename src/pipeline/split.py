"""
Train/test split of Juliet files by flow variant.

Juliet names a test case `<CWE>__<family>_<variant>[a-z]_(bad|good).c`, e.g.
`CWE416_Use_After_Free__malloc_free_int_07_bad.c`. Files of the same flow
variant are near-identical across families (`malloc_free_char_07` and
`malloc_free_int_07` differ only in the data type), so every file of a
variant goes to the same side - otherwise the test set would leak into
training. With only a handful of families per CWE, splitting by variant also
keeps enough cases on both sides.
"""

import hashlib
import random
import re
from pathlib import Path

_VARIANT_RE = re.compile(r"_(\d+)[a-z]?_(?:bad|good)$")


def flow_variant(path) -> str:
    stem = Path(path).stem
    m = _VARIANT_RE.search(stem)
    return m.group(1) if m else stem


def split_files(files, test_ratio=0.3, seed=0):
    """Returns (train, test, test_variants), deterministic for a given seed."""
    variants = sorted({flow_variant(f) for f in files})
    shuffled = variants[:]
    random.Random(seed).shuffle(shuffled)
    n_test = max(1, round(len(variants) * test_ratio)) if len(variants) > 1 else 0
    test_variants = sorted(shuffled[:n_test])
    train = [f for f in files if flow_variant(f) not in test_variants]
    test = [f for f in files if flow_variant(f) in test_variants]
    return train, test, test_variants


def _bucket(path, root, seed):
    """Deterministic number in [0, 1) for a file: its hash, from the path relative to `root` so it does not depend on the machine."""
    try:
        name = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        name = Path(path).name
    return int(hashlib.sha256(f"{seed}:{name}".encode()).hexdigest()[:8], 16) / 0x100000000


def split_negatives(files, root, test_ratio=0.3, seed=0, max_train=None):
    """
    Train/test split of real-world files (no flow variants here: they are not
    near-duplicates of each other, so the split is per file). A file goes to
    the test side when its hash falls below `test_ratio`, so the choice is the
    same on any machine and does not change when files are added elsewhere.
    `max_train` keeps only that many train files (the lowest hashes), to bound
    the time every gate run spends on them.
    """
    ranked = sorted(((_bucket(f, root, seed), str(f)) for f in files))
    test = [f for b, f in ranked if b < test_ratio]
    train = [f for b, f in ranked if b >= test_ratio]
    return (train[:max_train] if max_train else train), test


def fold_split(files, folds, fold, seed=0):
    """
    k-fold split by flow variant: the variants are shuffled (deterministically for a
    given seed) and dealt into `folds` groups, and `fold` is the test group. Over all
    folds every variant is tested exactly once, so the results can be averaged instead
    of depending on one random 30%. Returns (train, test, test_variants).
    """
    if folds < 2:
        raise ValueError("folds must be at least 2")
    if not 0 <= fold < folds:
        raise ValueError(f"fold must be between 0 and {folds - 1}")
    variants = sorted({flow_variant(f) for f in files})
    if len(variants) < folds:
        raise ValueError(f"{len(variants)} flow variants cannot make {folds} folds")
    shuffled = variants[:]
    random.Random(seed).shuffle(shuffled)
    test_variants = sorted(shuffled[fold::folds])
    train = [f for f in files if flow_variant(f) not in test_variants]
    test = [f for f in files if flow_variant(f) in test_variants]
    return train, test, test_variants
