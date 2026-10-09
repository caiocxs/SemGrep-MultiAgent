-- Event graph of a C code base for memory-lifetime queries (use after free, double free).
-- One row per pointer-relevant event, linked by control-flow edges inside a function. Interprocedural facts are kept as
-- per-function summaries and call bindings, so a query can follow a pointer through a call without re-reading the callee.

CREATE TABLE IF NOT EXISTS files (
    id   INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS functions (
    id         INTEGER PRIMARY KEY,
    file_id    INTEGER NOT NULL REFERENCES files(id),
    name       TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line   INTEGER NOT NULL
);

-- kind: alloc  the variable receives a new object (malloc/calloc/realloc/project allocator)
--       free   the object the variable points to is released (free/kfree/project deallocator)
--       use    the variable is dereferenced, passed on or compared
--       reset  the variable gets a new value that is not an allocation (NULL, another pointer, loop step)
--       call   a call to a function defined in the project (see call_args)
-- var is the access path as text ("p", "ctx->buf"); it is scoped by function.
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    func_id INTEGER NOT NULL REFERENCES functions(id),
    line    INTEGER NOT NULL,
    kind    TEXT NOT NULL CHECK (kind IN ('alloc', 'free', 'use', 'reset', 'call')),
    var     TEXT,
    detail  TEXT                      -- the source text of the statement, shown to the judge
);
CREATE INDEX IF NOT EXISTS events_by_var ON events(func_id, var, kind);

-- Control-flow successor of an event (branches give several rows, loops give back edges).
CREATE TABLE IF NOT EXISTS flow (
    src INTEGER NOT NULL REFERENCES events(id),
    dst INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (src, dst)
);
CREATE INDEX IF NOT EXISTS flow_by_src ON flow(src);

-- Aliases the extractor could prove in one function (q = p): a free of p also frees q until either is reset.
CREATE TABLE IF NOT EXISTS aliases (
    func_id INTEGER NOT NULL REFERENCES functions(id),
    a       TEXT NOT NULL,
    b       TEXT NOT NULL,
    PRIMARY KEY (func_id, a, b)
);

-- A call event and the variable bound to each argument position, and what each function does to its parameters.
CREATE TABLE IF NOT EXISTS call_args (
    call_event INTEGER NOT NULL REFERENCES events(id),
    callee_id  INTEGER REFERENCES functions(id),   -- NULL when the callee is not in the project
    arg_index  INTEGER NOT NULL,
    var        TEXT NOT NULL,
    PRIMARY KEY (call_event, arg_index)
);

CREATE TABLE IF NOT EXISTS summaries (
    func_id   INTEGER NOT NULL REFERENCES functions(id),
    param     INTEGER NOT NULL,
    effect    TEXT NOT NULL CHECK (effect IN ('frees', 'uses', 'resets')),
    PRIMARY KEY (func_id, param, effect)
);
