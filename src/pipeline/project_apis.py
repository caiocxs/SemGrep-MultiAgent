"""
Inventory of the memory functions a C project defines on top of the standard ones, found with regular expressions
(no model involved) and written as a short text for the generator and corrector prompts.

Li et al. (arXiv 2601.19239) trace most misses and false alarms of rule-based and LLM-based detectors to sources and
sinks that do not match the project's own APIs. A project like git frees memory through `FREE_AND_NULL(p)` and
allocates through `xmalloc`, `ALLOC_ARRAY`..., so a rule that names only `free` and `malloc` both misses those calls
and reports a pointer as freed right after a wrapper that already cleared it.

Three kinds are listed:
- releasers    free a pointer parameter (a function or macro whose body frees it, directly or through another releaser);
- clearers     releasers that also set the argument to NULL, so the variable is clean afterwards;
- allocators   return fresh memory, or assign it to their first argument.

The scan reads the definitions in every .c and .h file under the root. That is project knowledge, not a rule and not
an example, but it makes the generated rule specific to that project: declare it when the option is used.
"""

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

STANDARD_RELEASERS = {"free"}
STANDARD_ALLOCATORS = {"malloc", "calloc", "realloc", "strdup", "strndup"}
NOT_FUNCTIONS = {"if", "for", "while", "switch", "return", "sizeof", "defined", "do", "else"}
DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_]\w*)\((?P<params>[^)]*)\)(?P<body>(?:[^\n\\]|\\\n|\\)*)", re.M)
CALL = re.compile(r"(?<![\w.>])([A-Za-z_]\w*)\s*\(")


@dataclass
class Definition:
    name: str
    params: list  # (name, is_pointer)
    body: str
    returns_pointer: bool


def _params(text):
    result = []
    for part in text.split(","):
        found = re.findall(r"[A-Za-z_]\w*", part)
        if not found or part.strip() in ("void", "..."):
            result.append(("", False))
        else:
            result.append((found[-1], "*" in part or len(found) == 1))  # a macro parameter has no type: assume it may be a pointer
    return result


def _match_block(text, start, open_char, close_char):
    """Index just after the block that opens at text[start], or len(text) when it is not closed."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == open_char:
            depth += 1
        elif text[i] == close_char:
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _split_args(text):
    args, depth, current = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return args


def _bare(arg):
    """`(p)`, `p`, `*p` and `(void *)p` all name the variable p; anything else comes back unchanged."""
    arg = re.sub(r"^\(\s*[\w \t]+\*+\s*\)\s*", "", arg.strip()).lstrip("*").strip()
    while arg.startswith("(") and arg.endswith(")"):
        arg = arg[1:-1].strip()
    return arg


def definitions(text):
    """Every function and function-like macro defined in `text`."""
    found = []
    for m in DEFINE.finditer(text):
        found.append(Definition(m["name"], _params(m["params"]), m["body"].replace("\\\n", " "), False))
    lines = text.split("\n")
    offsets, total = [], 0
    for line in lines:
        offsets.append(total)
        total += len(line) + 1
    for i, line in enumerate(lines):
        # A function definition starts at column 0 and its `{` is on its own line or ends the header line.
        if line.rstrip() == "{" and i > 0:
            header_lines = []
            for previous in reversed(lines[max(0, i - 3):i]):
                if not previous.strip() or previous.rstrip().endswith((";", "}")):
                    break
                header_lines.insert(0, previous)
            header, brace = " ".join(header_lines), offsets[i]
        elif re.match(r"^[A-Za-z_][^;]*\)\s*\{\s*$", line):
            header, brace = line, offsets[i] + line.rindex("{")
        else:
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*\{?\s*$", header)
        if not m or m[1] in NOT_FUNCTIONS or header.lstrip().startswith(("#", "}")):
            continue
        end = _match_block(text, brace, "{", "}")
        found.append(Definition(m[1], _params(m[2]), text[brace:end], "*" in header[:m.start(1)]))
    return found


def _assigns_allocation(body, variable, allocators):
    """True when the body has `variable = allocator(...)`, with or without parentheses and a cast."""
    for part in re.split(r"[;{]", body):
        m = re.match(r"\(*\s*" + re.escape(variable) + r"\s*\)*\s*=\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", part.strip())
        if m and m[1] in allocators:
            return True
    return False


def _is_small_wrapper(body, param):
    """
    A release wrapper is short and does not give the parameter a new value from a call (that is realloc, which frees
    only on one path). Long functions that free an argument somewhere along the way are not wrappers.
    """
    squeezed = re.sub(r"\s+", " ", body)
    reassigned = re.search(r"(?<![\w.>])\(?\s*" + re.escape(param) + r"\s*\)?\s*=\s*(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(", squeezed)
    return len(squeezed) <= 400 and not reassigned


def analyse(defs):
    """
    Classifies the definitions. Returns (releasers, clearers, allocators): releasers and clearers map a name to the
    index of the argument that is freed; allocators are a set of names. Wrappers of wrappers are found by iterating.
    """
    releasers = {name: 0 for name in STANDARD_RELEASERS}
    allocators = set(STANDARD_ALLOCATORS)
    clearers = {}
    for _ in range(4):
        changed = False
        for d in defs:
            if d.name in STANDARD_RELEASERS or d.name in STANDARD_ALLOCATORS:
                continue
            calls = [(m[1], _split_args(d.body[m.end():_match_block(d.body, m.end() - 1, "(", ")") - 1]))
                     for m in CALL.finditer(d.body) if m[1] in releasers or m[1] in allocators]
            if d.name not in releasers:
                freed = {_bare(args[releasers[name]]) for name, args in calls
                         if name in releasers and len(args) > releasers[name]}
                for index, (param, is_pointer) in enumerate(d.params):
                    if param and is_pointer and param in freed and _is_small_wrapper(d.body, param):
                        releasers[d.name] = index
                        if re.search(r"(?<![\w.>])\(?\s*\*?\s*" + re.escape(param) + r"\s*\)?\s*=\s*NULL\b", d.body):
                            clearers[d.name] = index
                        changed = True
                        break
            if d.name not in allocators:
                returns_fresh = d.returns_pointer and any(
                    (end == "(" and what in allocators) or (end == ";" and _assigns_allocation(d.body, what, allocators))
                    for what, end in re.findall(r"\breturn\s+(?:\([^)]*\)\s*)?(\w+)\s*([(;])", d.body))
                first = d.params[0][0] if d.params else ""
                if returns_fresh or (first and _assigns_allocation(d.body, first, allocators)):
                    allocators.add(d.name)
                    changed = True
        if not changed:
            break
    for std in STANDARD_RELEASERS:
        releasers.pop(std, None)
    return releasers, clearers, allocators - STANDARD_ALLOCATORS


def scan(root):
    """Reads every .c and .h under `root`; returns the classification and how often each name is called."""
    texts = []
    for path in sorted(Path(root).rglob("*.[ch]")):
        try:
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    defs = [d for text in texts for d in definitions(text)]
    releasers, clearers, allocators = analyse(defs)
    wanted = set(releasers) | set(allocators)
    uses = Counter()
    for text in texts:
        uses.update(m[1] for m in CALL.finditer(text) if m[1] in wanted)
    return releasers, clearers, allocators, uses


def describe(root, limit=10):
    """The prompt text ("" when the project defines no such function)."""
    releasers, clearers, allocators, uses = scan(root)

    def top(names):
        ranked = sorted(names, key=lambda n: (-uses[n], n))
        return [n for n in ranked if uses[n] > 0][:limit]

    def with_argument(names):
        return ", ".join(f"`{n}` (argument {releasers[n] + 1})" for n in names)

    lines = []
    keep_clear, keep_release, keep_alloc = top(clearers), top(set(releasers) - set(clearers)), top(allocators)
    if keep_release:
        lines.append("- release the memory their argument points to, like `free`: " + with_argument(keep_release))
    if keep_clear:
        lines.append("- release it AND set the variable to NULL, so the variable is clean afterwards: "
                     + with_argument(keep_clear))
    if keep_alloc:
        lines.append("- return newly allocated memory, like `malloc`: " + ", ".join(f"`{n}`" for n in keep_alloc))
    if not lines:
        return ""
    return ("### Memory functions of the project the rule will run on\n\n"
            "Besides the standard functions, this C project defines the following (most used first). Code that calls "
            "them handles memory too, so a rule that names only the standard functions misjudges it.\n\n"
            + "\n".join(lines) + "\n")
