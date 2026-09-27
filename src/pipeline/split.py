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
