from src.graph import extract, paths


def graph(tmp_path, *sources):
    files = []
    for i, source in enumerate(sources):
        f = tmp_path / f"f{i}.c"
        f.write_text(source, encoding="utf-8")
        files.append(f)
    conn, failed = extract.build(files)
    assert failed == []
    return conn


def uaf(conn):
    return [(r["free_line"], r["line"], r["var"]) for r in paths.use_after_free(conn)]


def dfree(conn):
    return [(r["free_line"], r["line"]) for r in paths.double_free(conn)]


def test_basic_use_after_free(tmp_path):
    conn = graph(tmp_path, "void f(char *p) {\n free(p);\n p[0] = 1;\n}\n")
    assert uaf(conn) == [(2, 3, "p")]


def test_cast_malloc_free_printline(tmp_path):
    conn = graph(tmp_path, "void f() {\n char *d = (char *)malloc(10);\n free(d);\n printLine(d);\n}\n")
    assert uaf(conn) == [(3, 4, "d")]


def test_null_assignment_after_free_is_safe(tmp_path):
    conn = graph(tmp_path, "void f(char *p) {\n free(p);\n p = NULL;\n p[0] = 1;\n}\n")
    assert uaf(conn) == []


def test_comparison_after_free_is_not_a_use(tmp_path):
    conn = graph(tmp_path, "void f(char *p) {\n free(p);\n if (p == NULL) { return; }\n}\n")
    assert uaf(conn) == []


def test_use_in_one_branch(tmp_path):
    conn = graph(tmp_path, "void f(char *p, int c) {\n free(p);\n if (c) {\n  p = NULL;\n } else {\n  p[1] = 0;\n }\n}\n")
    assert uaf(conn) == [(2, 6, "p")]


def test_free_in_branch_and_use_after_the_join(tmp_path):
    conn = graph(tmp_path, "void f(char *p, int c) {\n if (c) {\n  free(p);\n }\n printLine(p);\n}\n")
    assert uaf(conn) == [(3, 5, "p")]


def test_loop_back_edge_gives_use_before_free_each_iteration(tmp_path):
    conn = graph(tmp_path, "void f(char *p) {\n while (1) {\n  p[0] = 1;\n  free(p);\n }\n}\n")
    assert uaf(conn) == [(4, 3, "p")]


def test_loop_that_moves_the_pointer_is_safe(tmp_path):
    conn = graph(tmp_path, "void f(char *p) {\n while (p) {\n  char *n = p->next;\n  free(p);\n  p = n;\n }\n}\n")
    assert uaf(conn) == []


def test_double_free_and_goto_cleanup(tmp_path):
    conn = graph(tmp_path, "void f(char *p, int e) {\n if (e) { free(p); goto out; }\n free(p);\nout:\n return;\n}\n")
    assert dfree(conn) == []  # the goto skips the second free
    conn = graph(tmp_path, "void f(char *p, int e) {\n if (e) { free(p); }\n free(p);\n}\n")
    assert dfree(conn) == [(2, 3)]


def test_switch_break_and_fallthrough(tmp_path):
    src = "void f(char *p, int c) {\n switch (c) {\n case 1:\n  free(p);\n  break;\n case 2:\n  p[0] = 1;\n  break;\n }\n}\n"
    assert uaf(graph(tmp_path, src)) == []  # case 2 does not follow the free
    src = "void f(char *p, int c) {\n switch (c) {\n case 1:\n  free(p);\n case 2:\n  p[0] = 1;\n }\n}\n"
    assert uaf(graph(tmp_path, src)) == [(4, 6, "p")]  # fallthrough


def test_return_of_freed_pointer_is_a_use(tmp_path):
    conn = graph(tmp_path, "char *f() {\n char *r = malloc(4);\n free(r);\n return r;\n}\n")
    assert uaf(conn) == [(3, 4, "r")]


def test_field_path_and_prefix_reset(tmp_path):
    conn = graph(tmp_path, "void f(struct s *c) {\n free(c->buf);\n c->buf[0] = 1;\n}\n")
    assert uaf(conn) == [(2, 3, "c->buf")]
    conn = graph(tmp_path, "void f(struct s *c, struct s *d) {\n free(c->buf);\n c = d;\n c->buf[0] = 1;\n}\n")
    assert uaf(conn) == []  # c was reassigned: c->buf is another object


def test_callee_that_frees_its_parameter(tmp_path):
    src = ("static void release(char *x) {\n free(x);\n}\n"
           "void f(char *p) {\n release(p);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(5, 6, "p")]


def test_wrapper_two_calls_deep(tmp_path):
    src = ("static void inner(char *x) { free(x); }\n"
           "static void outer(char *y) { inner(y); }\n"
           "void f(char *p) {\n outer(p);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(4, 5, "p")]


def test_callee_that_touches_nothing_is_not_a_use(tmp_path):
    src = "static void nop(char *x) { }\nvoid f(char *p) {\n free(p);\n nop(p);\n}\n"
    assert uaf(graph(tmp_path, src)) == []


def test_external_call_reads_its_arguments(tmp_path):
    assert uaf(graph(tmp_path, "void f(char *p) {\n free(p);\n memset(p, 0, 1);\n}\n")) == [(2, 3, "p")]


def test_for_loop_and_continue(tmp_path):
    src = "void f(char **a, int n) {\n for (int i = 0; i < n; i++) {\n  if (!a[i]) continue;\n  free(a[i]);\n }\n}\n"
    assert dfree(graph(tmp_path, src)) == []  # i++ makes the next a[i] another element


def test_declaration_initializer_is_a_reset(tmp_path):
    src = "void f(char *p) {\n free(p);\n char *p2 = p;\n p2[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []  # the copy is not followed (documented limit)


def test_index_not_changed_is_the_same_element(tmp_path):
    src = "void f(char **a, int n) {\n while (n) {\n  free(a[0]);\n }\n}\n"
    assert dfree(graph(tmp_path, src)) == [(3, 3)]


def test_noreturn_call_ends_the_flow(tmp_path):
    src = "void f(char *p, int c) {\n if (c) {\n  free(p);\n  exit(0);\n }\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []


def test_address_of_argument_is_a_reset(tmp_path):
    src = "void f(char *v) {\n free(v);\n get_string(&v);\n puts(v);\n}\n"
    assert uaf(graph(tmp_path, src)) == []


def test_shadowed_name_in_an_inner_block_is_another_variable(tmp_path):
    src = ("void f(char *prefix, int c) {\n if (c) {\n  char *prefix = xstrfmt(\"a\");\n  free(prefix);\n }\n"
           " puts(prefix);\n}\n")
    assert uaf(graph(tmp_path, src)) == []


def test_variable_declared_in_a_loop_body_is_new_each_iteration(tmp_path):
    src = "void f(int n) {\n while (n--) {\n  char *p = xmalloc(4);\n  p[0] = 1;\n  free(p);\n }\n}\n"
    assert uaf(graph(tmp_path, src)) == []


def test_alloc_macro_assigns_its_first_argument(tmp_path):
    src = "void f(struct s *c) {\n free(c->items);\n CALLOC_ARRAY(c->items, 4);\n c->items[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []


def test_iteration_macro_assigns_its_variable_each_iteration(tmp_path):
    src = "void f(struct h *m) {\n kh_foreach_value(m, oid, { free(oid); });\n}\n"
    assert dfree(graph(tmp_path, src)) == []


def test_free_and_null_macro(tmp_path):
    src = "void f(char *p) {\n FREE_AND_NULL(p);\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []


