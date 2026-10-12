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
--       call   an argument of a call, until the callee is resolved (see call_args); afterwards free, use or join
--       join   no effect: a merge point of the flow (loop heads, labels, cases) or a call that touches nothing
-- var is the access path as text ("p", "ctx->buf"); it is scoped by function.
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    func_id INTEGER NOT NULL REFERENCES functions(id),
    line    INTEGER NOT NULL,
    kind    TEXT NOT NULL CHECK (kind IN ('alloc', 'free', 'use', 'reset', 'call', 'join')),
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
    call_event  INTEGER NOT NULL REFERENCES events(id),
    callee_name TEXT NOT NULL,
    callee_id   INTEGER REFERENCES functions(id),  -- NULL when the callee is not in the project
    arg_index   INTEGER NOT NULL,
    var         TEXT NOT NULL,
    addr        INTEGER NOT NULL DEFAULT 0,        -- 1 when the argument is `&var`: the callee gets a pointer to the variable
    PRIMARY KEY (call_event, arg_index)
);

-- deref = 0: the function frees/uses the parameter itself; deref = 1: it frees/uses the pointer stored at *parameter
-- (what a caller passing `&p` needs to know about p).
CREATE TABLE IF NOT EXISTS summaries (
    func_id   INTEGER NOT NULL REFERENCES functions(id),
    param     INTEGER NOT NULL,
    deref     INTEGER NOT NULL DEFAULT 0,
    effect    TEXT NOT NULL CHECK (effect IN ('frees', 'uses', 'resets')),
    PRIMARY KEY (func_id, param, deref, effect)
);

-- Frees, uses and reassignments (`*param = ..`), inside a function, of a local that holds `*param` (q = *param, possibly through a copy of param).
CREATE TABLE IF NOT EXISTS deref_effects (
    func_id INTEGER NOT NULL REFERENCES functions(id),
    param   TEXT NOT NULL,
    effect  TEXT NOT NULL CHECK (effect IN ('free', 'use', 'reset'))
);

-- Parameter names by position, to bind call arguments to what a function does to its parameters.
CREATE TABLE IF NOT EXISTS params (
    func_id INTEGER NOT NULL REFERENCES functions(id),
    idx     INTEGER NOT NULL,
    name    TEXT NOT NULL,
    PRIMARY KEY (func_id, idx)
);

-- Release functions learned from how the code uses them (no list, no body): the name, the argument position, the number of call sites
-- with a plain pointer argument and the share of them followed by a use of that argument.
CREATE TABLE IF NOT EXISTS inferred_release (
    name      TEXT NOT NULL,
    arg_index INTEGER NOT NULL,
    sites     INTEGER NOT NULL,
    rate      REAL NOT NULL,      -- share of the sites followed by a use of the argument
    acquired  REAL NOT NULL,      -- share of the sites where the argument was assigned from a call before
    score     REAL NOT NULL,      -- log-odds of the words of the name, learned from the functions proven to free their parameter
    PRIMARY KEY (name, arg_index)
);
