"""
Deterministic path queries over the event graph (schema.sql). A candidate is a pair (free, later event) of the same variable
joined by a control-flow path on which the variable is not given a new value. The queries are intraprocedural; the summaries
and call_args tables are the hook for following a pointer through a call (not used yet).
"""

import sqlite3
from pathlib import Path

SCHEMA = Path(__file__).with_name("schema.sql")

# Events reachable from a free of the same variable without crossing a reset/alloc of it (the walk stops there).
# UNION (not UNION ALL) removes repeated rows, so loops terminate.
_REACHABLE = """
WITH RECURSIVE reach(free_id, event_id) AS (
    SELECT f.id, fl.dst
    FROM events f JOIN flow fl ON fl.src = f.id
    WHERE f.kind = 'free'
    UNION
    SELECT r.free_id, fl.dst
    FROM reach r
    JOIN events cur ON cur.id = r.event_id
    JOIN events origin ON origin.id = r.free_id
    JOIN flow fl ON fl.src = cur.id
    WHERE NOT (cur.kind IN ('reset', 'alloc') AND (
        cur.var = origin.var
        OR substr(origin.var, 1, length(cur.var) + 1) IN (cur.var || '.', cur.var || '[')
        OR substr(origin.var, 1, length(cur.var) + 2) = cur.var || '->'
        OR instr(origin.var, '[' || cur.var || ']') > 0))  -- a[i] after i changes is another element
)
"""

_CANDIDATES = _REACHABLE + """
SELECT origin.id AS free_event, origin.line AS free_line, hit.id AS event, hit.line AS line, hit.kind AS kind,
       hit.var AS var, fn.name AS function, fi.path AS path, hit.detail AS detail
FROM reach r
JOIN events origin ON origin.id = r.free_id
JOIN events hit ON hit.id = r.event_id
JOIN functions fn ON fn.id = origin.func_id
JOIN files fi ON fi.id = fn.file_id
WHERE (hit.var = origin.var OR substr(hit.var, 1, length(origin.var) + 1) IN (origin.var || '.', origin.var || '[')
       OR substr(hit.var, 1, length(origin.var) + 2) = origin.var || '->') AND hit.kind IN ({kinds})
ORDER BY fi.path, origin.line, hit.line
"""


def connect(path=":memory:"):
    conn = sqlite3.connect(path, check_same_thread=False)  # the extractor walks the files on a thread with a big stack
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    return conn


def use_after_free(conn):
    """Uses of a variable reachable from a free of it with no reassignment in between."""
    return [dict(row) for row in conn.execute(_CANDIDATES.format(kinds="'use'"))]


def double_free(conn):
    """Frees of a variable reachable from an earlier free of it with no reassignment in between."""
    return [dict(row) for row in conn.execute(_CANDIDATES.format(kinds="'free'"))]


# Null dereference. Source: an assignment of NULL, or a branch known NULL. Hit: a `use` of the same path (or a part of it) reached with no new value, no
# allocation and no non-NULL test of it in between. Second pattern: a `use` followed by a NULL test of the same variable (dereferenced, then checked).
_NULL_SOURCE = "(f.kind = 'null' OR (f.kind = 'reset' AND f.detail = '<null-assign>'))"
_NULL_REACHABLE = """
WITH RECURSIVE reach(origin_id, event_id) AS (
    SELECT f.id, fl.dst FROM events f JOIN flow fl ON fl.src = f.id WHERE {source}
    UNION
    SELECT r.origin_id, fl.dst
    FROM reach r
    JOIN events cur ON cur.id = r.event_id
    JOIN events origin ON origin.id = r.origin_id
    JOIN flow fl ON fl.src = cur.id
    WHERE NOT (cur.kind IN ('reset', 'alloc', 'nonnull', 'free') AND (
        cur.var = origin.var
        OR substr(origin.var, 1, length(cur.var) + 1) IN (cur.var || '.', cur.var || '[')
        OR substr(origin.var, 1, length(cur.var) + 2) = cur.var || '->'
        OR instr(origin.var, '[' || cur.var || ']') > 0))
)
SELECT origin.id AS free_event, origin.line AS free_line, hit.id AS event, hit.line AS line, hit.kind AS kind,
       hit.var AS var, fn.name AS function, fi.path AS path, hit.detail AS detail
FROM reach r
JOIN events origin ON origin.id = r.origin_id
JOIN events hit ON hit.id = r.event_id
JOIN functions fn ON fn.id = origin.func_id
JOIN files fi ON fi.id = fn.file_id
WHERE {hit}
ORDER BY fi.path, origin.line, hit.line
"""


def _straight(succ, start, kinds_stop, var_of, kind, limit=2000):
    """The events that follow `start` along the only path there is: the walk goes on while an event has a single successor, so no decision lies between
    `start` and any of them. It stops at the first branch, at a new value of the variable and at a loop (an event seen twice)."""
    chain, node = [], start
    while len(chain) < limit:
        nxt = succ.get(node, ())
        if len(nxt) != 1:
            break
        node = nxt[0]
        if node in chain:
            break
        chain.append(node)
        if kind[node] in kinds_stop:
            break
    return chain


def _certain_paths(conn):
    """Null-dereference candidates with no decision between the cause and the effect. A pointer set or known NULL that is dereferenced on the one path
    that follows, and a dereference followed on the one path that follows by a test of the same pointer. Real code is full of correlated conditions
    (`goto error` with a NULL, then `if (other) { p->x }` at the label) that a walk without path conditions cannot tell from a bug; this keeps only the
    cases that need none."""
    succ = {}
    for src, dst in conn.execute("SELECT src, dst FROM flow"):
        succ.setdefault(src, []).append(dst)
    kind, var_of, line_of, func_of, detail_of = {}, {}, {}, {}, {}
    for event_id, k, var, line, detail, func_id in conn.execute("SELECT id, kind, var, line, detail, func_id FROM events"):
        kind[event_id], var_of[event_id], line_of[event_id], detail_of[event_id], func_of[event_id] = k, var, line, detail, func_id
    calls = {r[0] for r in conn.execute("SELECT call_event FROM call_args")}
    deref_calls = {r[0] for r in conn.execute("SELECT call_event FROM deref_calls")}
    names = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT f.id, f.name, fi.path FROM functions f JOIN files fi ON fi.id = f.file_id")}

    broken = {r[0] for r in conn.execute("SELECT id FROM functions WHERE broken = 1")}

    def dereference(event_id):
        return (kind[event_id] == "use" and detail_of[event_id] not in ("<arg>", "<addr>") and func_of[event_id] not in broken
                and (event_id not in calls or event_id in deref_calls))

    def related(hit_var, origin_var):
        return hit_var == origin_var or (hit_var or "").startswith((origin_var + ".", origin_var + "[", origin_var + "->"))

    rows = []

    def row(origin, hit, pattern):
        name, path = names[func_of[origin]]
        rows.append({"free_event": origin, "free_line": line_of[origin], "event": hit, "line": line_of[hit], "kind": kind[hit], "var": var_of[hit],
                     "function": name, "path": path, "detail": detail_of[hit], "pattern": pattern})

    for event_id, k in kind.items():
        var = var_of[event_id]
        if not var:
            continue
        null_source = (k == "null" or (k == "reset" and detail_of[event_id] == "<null-assign>")) and func_of[event_id] not in broken
        if null_source:  # source to dereference
            for hit in _straight(succ, event_id, (), var_of, kind):
                if var_of[hit] == var and kind[hit] in ("reset", "alloc", "free", "nonnull"):
                    break  # a new value, a release or a non-NULL test ends it
                if related(var_of[hit], var) and dereference(hit):
                    if line_of[hit] != line_of[event_id]:  # a source and a dereference on one line is a macro's own temporary (`tl` in `local_trylock`)
                        row(event_id, hit, "null-to-use")
                    break
        if dereference(event_id):  # dereference to test
            for hit in _straight(succ, event_id, (), var_of, kind):
                if var_of[hit] == var and kind[hit] in ("reset", "alloc", "free"):
                    break
                if var_of[hit] == var and kind[hit] in ("null", "nonnull") and line_of[hit] != line_of[event_id]:
                    row(event_id, hit, "use-to-test")
                    break
            else:
                pass
            # the test events are the successors of the branch that ends the chain
            chain = []
            for node in _straight(succ, event_id, (), var_of, kind):
                if var_of[node] == var and kind[node] in ("reset", "alloc", "free"):
                    break  # the pointer has another value after this: a test after it is of the new value (`while (n) { n = n->next; }`)
                chain.append(node)
            last = chain[-1] if chain else event_id
            for hit in succ.get(last, ()):
                if len(succ.get(last, ())) > 1 and var_of[hit] == var and kind[hit] in ("null", "nonnull") and line_of[hit] != line_of[event_id]:
                    row(event_id, hit, "use-to-test")
                    break
    seen, unique = set(), []
    for r in sorted(rows, key=lambda r: (r["path"], r["free_line"], r["line"], r["pattern"])):
        key = (r["free_event"], r["event"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def null_dereference(conn):
    """A pointer known or set to be NULL that is dereferenced with no decision in between (needs no path condition, so it can be certain)."""
    return [r for r in _certain_paths(conn) if r["pattern"] == "null-to-use"]


def check_after_deref(conn):
    """A pointer dereferenced and then tested for NULL with no decision in between. Kept apart: in real code the test is mostly a defensive one on a
    pointer the contract says is not NULL, so the count on code assumed correct is far above the limit."""
    return [r for r in _certain_paths(conn) if r["pattern"] == "use-to-test"]


# The allocation sites the leak query follows: a local variable given what an allocator returned. `p = f(p, ..)` counts only for the standard library
# and for functions the code proves to return their own allocation, not for learned ones (`bms_add_member(set, i)` returns the set it was given).
ALLOC_SITES_SQL = ("SELECT a.event_id, a.callee FROM allocs a JOIN leak_allocators la ON la.name = a.callee "
                   "WHERE a.local = 1 AND (a.selfarg = 0 OR la.proven = 1)")

RETURN, END, REALLOC_SELF, SCOPE_END = "<return>", "<end>", "<realloc-self>", "<scope-end>"  # details the extractor gives to the markers it needs here


def memory_leak(conn):
    """
    Allocations of a local variable that can reach a return, or the end of the function, on some path along which the variable is not
    freed, not handed on (stored, returned, passed to something that keeps it) and not overwritten (needs `extract.prepare_leaks`).
    `p = realloc(p, n)` keeps the old block alive on the path where p becomes NULL, the classic leak when realloc fails.
    One row per allocation, with the first return it reaches.
    """
    out, kind, var_of, line_of, detail_of, func_of = {}, {}, {}, {}, {}, {}
    for src, dst in conn.execute("SELECT src, dst FROM flow"):
        out.setdefault(src, []).append(dst)
    for event_id, k, var, line, detail, func_id in conn.execute("SELECT id, kind, var, line, detail, func_id FROM events"):
        kind[event_id], var_of[event_id], line_of[event_id], detail_of[event_id], func_of[event_id] = k, var, line, detail, func_id
    handoff = {r[0] for r in conn.execute("SELECT call_event FROM handoff")}
    calls = {r[0] for r in conn.execute("SELECT call_event FROM call_args")}
    sites = conn.execute(
        "SELECT a.event_id, e.var, f.name, fi.path FROM allocs a JOIN events e ON e.id = a.event_id JOIN functions f ON f.id = e.func_id "
        "JOIN files fi ON fi.id = f.file_id JOIN leak_allocators la ON la.name = a.callee "
        "WHERE a.local = 1 AND (a.selfarg = 0 OR la.proven = 1) ORDER BY fi.path, e.line").fetchall()
    found = []
    for alloc, var, function, path in sites:
        seen, stack, hit = set(), [(alloc, 0)], None  # mode 0: held; 1: p = realloc(p, n) happened; 2: the old block is lost (p is NULL)
        first = True
        while stack and hit is None:
            node, mode = stack.pop()
            if (node, mode) in seen:
                continue
            seen.add((node, mode))
            if not first:
                d = detail_of[node]
                if d in (RETURN, END):
                    if mode in (0, 2):
                        hit = node
                    continue
                other = var_of[node]
                # a call that receives `&p->f` or `p->f` and keeps it holds a pointer into the block: the block goes with it
                derived = other is not None and node in handoff and other.startswith((var + "->", var + ".", var + "["))
                if derived and mode != 2:
                    continue
                if other == var:
                    k = kind[node]
                    if k == "null":
                        if mode == 0:
                            continue          # the NULL branch: nothing was allocated
                        mode = 2              # after a realloc: p is NULL, the old block is lost
                    elif k in ("free", "escape") or (k != "null" and node in calls and node in handoff):
                        if mode != 2:
                            continue          # freed or held elsewhere
                    elif k in ("reset", "alloc"):
                        if d == SCOPE_END:
                            if mode in (0, 2):
                                hit = node        # the variable dies still holding the allocation
                            continue
                        if d == REALLOC_SELF and mode == 0:
                            mode = 1
                        elif mode != 2:
                            continue          # overwritten with something else: not followed
            first = False
            for nxt in out.get(node, ()):
                stack.append((nxt, mode))
        if hit is not None:
            found.append({"free_event": alloc, "free_line": line_of[alloc], "event": hit, "line": line_of[hit], "kind": "leak", "var": var,
                          "function": function, "path": path, "detail": detail_of[alloc]})
    return found
