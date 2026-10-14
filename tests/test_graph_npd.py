from src.graph import extract, paths


def alerts(tmp_path, source):
    f = tmp_path / "f.c"
    f.write_text(source, encoding="utf-8")
    conn, failed = extract.build([f])
    assert failed == []
    return [(r["pattern"], r["line"]) for r in paths.null_dereference(conn) + paths.check_after_deref(conn)]


def test_dereference_of_a_pointer_set_to_null_is_found(tmp_path):
    assert alerts(tmp_path, "int f(void) {\n int *p = NULL;\n return *p;\n}\n") == [("null-to-use", 3)]


def test_a_new_value_or_an_allocation_ends_the_null_path(tmp_path):
    assert alerts(tmp_path, "int f(int *q) {\n int *p = NULL;\n p = q;\n return *p;\n}\n") == []
    assert alerts(tmp_path, "int f(void) {\n int *p = NULL;\n p = malloc(4);\n *p = 1;\n return *p;\n}\n") == []


def test_a_non_null_test_guards_the_dereference(tmp_path):
    assert alerts(tmp_path, "int f(void) {\n int *p = NULL;\n if (p != NULL) {\n  return *p;\n }\n return 0;\n}\n") == []
    assert alerts(tmp_path, "int f(void) {\n int *p = NULL;\n if (!p) {\n  return 0;\n }\n return *p;\n}\n") == []
    assert alerts(tmp_path, "int f(void) {\n int *p = NULL;\n return p ? *p : 0;\n}\n") == []


def test_short_circuit_guards_the_right_side_only_with_and(tmp_path):
    assert alerts(tmp_path, "int f(struct s *p) {\n p = NULL;\n if (p != NULL && p->x == 5) {\n  return 1;\n }\n return 0;\n}\n") == []
    assert alerts(tmp_path, "int f(struct s *p) {\n p = NULL;\n if (p != NULL & p->x == 5) {\n  return 1;\n }\n return 0;\n}\n") == [("null-to-use", 3)]


def test_branch_known_null_that_falls_through_reaches_the_dereference(tmp_path):
    src = "int f(int *p) {\n if (p == NULL) {\n  log(1);\n }\n return *p;\n}\n"
    assert ("null-to-use", 5) in alerts(tmp_path, src)
    assert alerts(tmp_path, "int f(int *p) {\n if (p == NULL) {\n  return 0;\n }\n return *p;\n}\n") == []


def test_a_wrapped_condition_is_the_condition(tmp_path):
    assert alerts(tmp_path, "int f(int *p) {\n p = NULL;\n if (unlikely(p == NULL)) {\n  return 0;\n }\n return *p;\n}\n") == []


def test_dereference_before_the_test_is_found(tmp_path):
    src = "int f(int *p) {\n *p = 1;\n if (p != NULL) {\n  return 2;\n }\n return 0;\n}\n"
    assert ("use-to-test", 3) in alerts(tmp_path, src)
    assert alerts(tmp_path, "int f(int *p) {\n if (p != NULL && *p == 1) {\n  return 2;\n }\n return 0;\n}\n") == []


def test_a_callee_that_dereferences_unguarded_counts_but_a_guarded_one_does_not(tmp_path):
    bad = "static int g(int *q) {\n return *q;\n}\nint f(void) {\n int *p = NULL;\n return g(p);\n}\n"
    assert alerts(tmp_path, bad) == [("null-to-use", 6)]
    good = "static int g(int *q) {\n if (q == NULL) {\n  return 0;\n }\n return *q;\n}\nint f(void) {\n int *p = NULL;\n return g(p);\n}\n"
    assert alerts(tmp_path, good) == []


def test_passing_null_to_a_function_the_code_does_not_define_is_not_a_dereference(tmp_path):
    assert alerts(tmp_path, "void f(void) {\n char *p = NULL;\n unknown(p);\n}\n") == []
    assert alerts(tmp_path, "void f(void) {\n char *p = NULL;\n p = realloc(p, 10);\n free(p);\n}\n") == []
