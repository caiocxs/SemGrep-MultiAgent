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
    WHERE NOT (cur.var = origin.var AND cur.kind IN ('reset', 'alloc'))
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
WHERE hit.var = origin.var AND hit.kind IN ({kinds})
ORDER BY fi.path, origin.line, hit.line
"""


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    return conn


def use_after_free(conn):
    """Uses of a variable reachable from a free of it with no reassignment in between."""
    return [dict(row) for row in conn.execute(_CANDIDATES.format(kinds="'use'"))]


def double_free(conn):
    """Frees of a variable reachable from an earlier free of it with no reassignment in between."""
    return [dict(row) for row in conn.execute(_CANDIDATES.format(kinds="'free'"))]
