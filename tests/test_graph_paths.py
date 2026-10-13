from src.graph import paths


def build(events, edges):
    """events: [(id, kind, var, line)]; edges: [(src, dst)]. One file, one function."""
    conn = paths.connect()
    conn.execute("INSERT INTO files VALUES (1, 'a.c')")
    conn.execute("INSERT INTO functions (id, file_id, name, start_line, end_line) VALUES (1, 1, 'f', 1, 100)")
    conn.executemany("INSERT INTO events (id, func_id, line, kind, var) VALUES (?, 1, ?, ?, ?)",
                     [(i, line, kind, var) for i, kind, var, line in events])
    conn.executemany("INSERT INTO flow VALUES (?, ?)", edges)
    return conn


def test_use_after_free_is_found():
    conn = build([(1, "alloc", "p", 1), (2, "free", "p", 2), (3, "use", "p", 3)], [(1, 2), (2, 3)])
    found = paths.use_after_free(conn)
    assert [(r["free_line"], r["line"], r["var"]) for r in found] == [(2, 3, "p")]


def test_reassignment_between_free_and_use_kills_the_path():
    conn = build([(1, "free", "p", 1), (2, "reset", "p", 2), (3, "use", "p", 3)], [(1, 2), (2, 3)])
    assert paths.use_after_free(conn) == []


def test_other_variable_is_not_a_hit():
    conn = build([(1, "free", "p", 1), (2, "use", "q", 2)], [(1, 2)])
    assert paths.use_after_free(conn) == []


def test_one_branch_without_reset_is_enough():
    # free -> (reset | nothing) -> use: the path that skips the reset is a real path
    conn = build([(1, "free", "p", 1), (2, "reset", "p", 2), (3, "use", "p", 3)], [(1, 2), (1, 3), (2, 3)])
    assert len(paths.use_after_free(conn)) == 1


def test_free_repeated_by_a_loop_is_a_double_free():
    conn = build([(1, "free", "p", 1), (2, "use", "q", 2)], [(1, 2), (2, 1)])
    assert [(r["free_line"], r["line"]) for r in paths.double_free(conn)] == [(1, 1)]


def test_loop_with_reset_is_not_a_double_free():
    conn = build([(1, "free", "p", 1), (2, "reset", "p", 2)], [(1, 2), (2, 1)])
    assert paths.double_free(conn) == []


def test_double_free_in_sequence():
    conn = build([(1, "free", "p", 1), (2, "free", "p", 2)], [(1, 2)])
    assert [(r["free_line"], r["line"]) for r in paths.double_free(conn)] == [(1, 2)]
