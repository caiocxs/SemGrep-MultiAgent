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
        "JOIN files fi ON fi.id = f.file_id WHERE a.local = 1 AND a.callee IN (SELECT name FROM leak_allocators) ORDER BY fi.path, e.line").fetchall()
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
                if var_of[node] == var:
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
