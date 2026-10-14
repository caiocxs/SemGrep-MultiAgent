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


def test_macro_that_assigns_its_first_argument_is_found_from_its_definition(tmp_path):
    macro = "#define MAKE_ARRAY(x, n) (x) = xcalloc((n), sizeof(*(x)))\n"
    src = macro + "void f(struct s *c) {\n free(c->items);\n MAKE_ARRAY(c->items, 4);\n c->items[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []
    # the same call with no definition of the macro anywhere: nothing says it assigns, the pointer is read after the free
    src = "void f(struct s *c) {\n free(c->items);\n MAKE_ARRAY(c->items, 4);\n c->items[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == [(2, 3, "c->items"), (2, 4, "c->items")]


def test_iteration_macro_assigns_its_variable_each_iteration(tmp_path):
    src = "void f(struct h *m) {\n kh_foreach_value(m, oid, { free(oid); });\n}\n"
    assert dfree(graph(tmp_path, src)) == []


def test_free_and_null_macro_is_found_from_its_definition(tmp_path):
    macro = "#define CLEAR(p) do { free(p); (p) = NULL; } while (0)\n"
    assert uaf(graph(tmp_path, macro + "void f(char *p) {\n CLEAR(p);\n p[0] = 1;\n}\n")) == []


def test_noreturn_function_is_found_from_its_body(tmp_path):
    fatal = "static void fatal(const char *m) {\n log_it(m);\n exit(1);\n}\n"
    src = fatal + "void f(char *p, int c) {\n if (c) {\n  free(p);\n  fatal(\"x\");\n }\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []  # fatal never returns, so the free does not reach the use
    src = "void f(char *p, int c) {\n if (c) {\n  free(p);\n  fatal(\"x\");\n }\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == [(3, 6, "p")]  # with no body for fatal, nothing says it ends the path


def test_noreturn_through_another_noreturn_function(tmp_path):
    src = ("static void fatal(const char *m) {\n exit(1);\n}\n"
           "static void bug(const char *m) {\n fatal(m);\n}\n"
           "void f(char *p) {\n free(p);\n bug(\"x\");\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == []


def test_function_that_loops_forever_does_not_return(tmp_path):
    src = ("static void serve(void) {\n for (;;) {\n  handle();\n }\n}\n"
           "void f(char *p) {\n free(p);\n serve();\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == []


def test_thin_wrapper_macro_around_a_function_that_frees(tmp_path):
    src = ("static void impl_free(char *x, int line) {\n free(x);\n}\n#define my_free(x) impl_free(x, 7)\n"
           "void f(char *p) {\n my_free(p);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(6, 7, "p")]


def test_loop_macro_is_found_from_its_body(tmp_path):
    macro = "#define EACH(i, n) for ((i) = 0; (i) < (n); (i)++)\n"
    src = macro + "void f(char **a, int n) {\n int i;\n EACH(i, n) {\n  free(a[i]);\n }\n}\n"
    assert dfree(graph(tmp_path, src)) == []  # i is assigned at every iteration


SITES = 60  # the one use after the call that the tests plant must stay under the 2% floor of the after-use rate
# What the code itself proves: pool_release and buf_release free their parameter (so the word `release` names a deallocator, seen in two of
# them), and eight other functions free nothing (so the word is not one every name has); they only read it: passing a parameter on to a call would prove nothing.
PROVEN = ("static void pool_release(char *x) {\n free(x);\n}\nstatic void buf_release(char *x) {\n free(x);\n}\n"
          + "".join(f"static int other{i}(char *x) {{\n return x[0];\n}}\n" for i in range(8)))  # they only read it: handing it on proves nothing
PROVEN_LINES = 30


def _sites(call, acquired=True):
    """SITES functions that each get a buffer from a call (or take it as a parameter), use it and end with `call(p)`."""
    if acquired:
        return "".join(f"void g{i}(void) {{\n char *p = make_buf();\n p[0] = 1;\n {call}(p);\n}}\n" for i in range(SITES))
    return "".join(f"void g{i}(char *p) {{\n p[0] = 1;\n {call}(p);\n}}\n" for i in range(SITES))


def test_release_function_with_no_body_is_learned_from_its_uses(tmp_path):
    tail = "void f(void) {\n char *p = make_buf();\n lib_release(p);\n p[0] = 2;\n}\n"
    conn = graph(tmp_path, PROVEN + _sites("lib_release") + tail)
    base = PROVEN_LINES + 5 * SITES
    assert uaf(conn) == [(base + 3, base + 4, "p")]
    assert [tuple(r)[:2] for r in conn.execute("SELECT name, arg_index FROM inferred_release")] == [("lib_release", 0)]


def test_a_name_the_code_never_showed_is_not_learned_as_a_release_function(tmp_path):
    tail = "void f(void) {\n char *p = make_buf();\n lib_dump(p);\n p[0] = 2;\n}\n"
    conn = graph(tmp_path, PROVEN + _sites("lib_dump") + tail)  # same usage as a release, but nothing says it is one
    assert uaf(conn) == [] and list(conn.execute("SELECT * FROM inferred_release")) == []


def test_a_last_use_of_a_parameter_is_not_a_release(tmp_path):
    tail = "void f(char *p) {\n lib_release(p);\n p[0] = 2;\n}\n"
    conn = graph(tmp_path, PROVEN + _sites("lib_release", acquired=False) + tail)
    assert uaf(conn) == [] and list(conn.execute("SELECT * FROM inferred_release")) == []


def test_function_whose_argument_is_used_afterwards_is_not_a_release_function(tmp_path):
    body = "".join(f"void g{i}(void) {{\n char *p = make_buf();\n lib_release(p);\n p[0] = 1;\n}}\n" for i in range(SITES))
    conn = graph(tmp_path, PROVEN + body)
    assert list(conn.execute("SELECT * FROM inferred_release")) == []


def test_a_concatenated_name_takes_the_word_it_ends_with(tmp_path):
    tail = "void f(void) {\n char *p = make_buf();\n xrelease(p);\n p[0] = 2;\n}\n"
    conn = graph(tmp_path, PROVEN + _sites("xrelease") + tail)  # `xrelease` is one word; the code showed `release`
    base = PROVEN_LINES + 5 * SITES
    assert uaf(conn) == [(base + 3, base + 4, "p")]
    assert [tuple(r)[:2] for r in conn.execute("SELECT name, arg_index FROM inferred_release")] == [("xrelease", 0)]


def test_a_function_that_hands_its_parameter_on_is_not_evidence_against_its_own_name(tmp_path):
    # `xrelease` has a body and passes its parameter to a hook, like pfree does: it has proven nothing, so its name is not a negative example
    own = "static void xrelease(char *x) {\n hook(x);\n}\n"
    tail = "void f(void) {\n char *p = make_buf();\n xrelease(p);\n p[0] = 2;\n}\n"
    conn = graph(tmp_path, PROVEN + own + _sites("xrelease") + tail)
    base = PROVEN_LINES + 3 + 5 * SITES
    assert uaf(conn) == [(base + 3, base + 4, "p")]


def test_a_function_that_only_reads_is_a_negative_example(tmp_path):
    # the same shape, but the word is shown by functions that do nothing but read their parameter: the name is evidence against
    readers = "".join(f"static int xshow{i}(char *x) {{\n return x[0];\n}}\n" for i in range(12))
    tail = "void f(void) {\n char *p = make_buf();\n xshow(p);\n p[0] = 2;\n}\n"
    conn = graph(tmp_path, PROVEN + readers + _sites("xshow") + tail)
    assert uaf(conn) == [] and list(conn.execute("SELECT * FROM inferred_release")) == []


def test_few_sites_say_nothing(tmp_path):
    body = "".join(f"void g{i}(void) {{\n char *p = make_buf();\n lib_release(p);\n}}\n" for i in range(3))
    conn = graph(tmp_path, PROVEN + body + "void f(void) {\n char *p = make_buf();\n lib_release(p);\n p[0] = 2;\n}\n")
    assert uaf(conn) == []


def test_loop_that_runs_once_has_no_back_edge(tmp_path):
    once = "void f(char *d) {\n int j;\n for (j = 0; j < 1; j++) {\n  free(d);\n }\n}\n"
    assert dfree(graph(tmp_path, once)) == []
    twice = "void f(char *d) {\n int j;\n for (j = 0; j < 2; j++) {\n  free(d);\n }\n}\n"
    assert dfree(graph(tmp_path, twice)) == [(4, 4)]
    declared = "void f(char *d) {\n for (int j = 0; j <= 0; ++j) {\n  free(d);\n }\n}\n"
    assert dfree(graph(tmp_path, declared)) == []


def test_address_of_passed_to_a_function_that_uses_the_pointee(tmp_path):
    src = ("static void sink(char **pp) {\n char *d = *pp;\n d[0] = 1;\n}\n"
           "void f(char *p) {\n free(p);\n sink(&p);\n}\n")
    assert uaf(graph(tmp_path, src)) == [(6, 7, "p")]


def test_address_of_through_a_cast_of_the_parameter(tmp_path):
    src = ("static void sink(void *v) {\n char **pp = (char **)v;\n char *d = *pp;\n d[0] = 1;\n}\n"
           "void f(char *p) {\n free(p);\n sink(&p);\n}\n")
    assert uaf(graph(tmp_path, src)) == [(7, 8, "p")]


def test_callee_that_frees_the_pointee_frees_the_variable(tmp_path):
    src = ("static void drop(char **pp) {\n char *d = *pp;\n free(d);\n}\n"
           "void f(char *p) {\n drop(&p);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(6, 7, "p")]


def test_callee_that_assigns_the_pointee_resets_the_variable(tmp_path):
    src = ("static void pop(struct node **head) {\n struct node *top = *head;\n *head = top->next;\n free(top);\n}\n"
           "void f(struct node *s) {\n pop(&s);\n s->x = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == []


def test_address_of_to_an_unknown_function_is_a_reset(tmp_path):
    src = "void f(char *p) {\n free(p);\n fill(&p);\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == []


def test_release_macro_that_is_an_alias_of_free(tmp_path):
    src = "#define my_free free\nvoid f(char *p) {\n my_free(p);\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == [(3, 4, "p")]


def test_release_macro_with_a_reset_does_not_leave_a_dangling_pointer(tmp_path):
    src = ("#define SAFE_FREE(x) do { free(x); (x) = NULL; } while (0)\n"
           "void f(char *p) {\n SAFE_FREE(p);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == []


def test_release_macro_without_a_reset_frees_and_a_do_while_zero_runs_once(tmp_path):
    src = ("#define RELEASE(x) do { free(x); } while (0)\n"
           "void f(char *p) {\n RELEASE(p);\n p[0] = 1;\n}\n")
    conn = graph(tmp_path, src)
    assert uaf(conn) == [(3, 4, "p")]
    assert dfree(conn) == []  # the do { } while (0) has no back edge: it is not a repeated free


def test_release_macro_defined_through_another_macro(tmp_path):
    src = ("#define xfree free\n#define xsafefree(p) do { xfree(p); (p) = NULL; } while (0)\n"
           "void f(char *a, char *b) {\n xsafefree(a);\n a[0] = 1;\n xfree(b);\n b[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(6, 7, "b")]


def test_release_macro_on_a_field_path(tmp_path):
    src = ("#define RELEASE(x) do { free(x); } while (0)\n"
           "void f(struct s *c) {\n RELEASE(c->buf);\n c->buf[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(3, 4, "c->buf")]


def test_release_macro_from_a_header(tmp_path):
    header = tmp_path / "defs.h"
    header.write_text("#define my_free(x) free(x)\n", encoding="utf-8")
    source = tmp_path / "a.c"
    source.write_text("void f(char *p) {\n my_free(p);\n p[0] = 1;\n}\n", encoding="utf-8")
    conn, failed = extract.build([source], headers=[header])
    assert failed == [] and uaf(conn) == [(2, 3, "p")]
    conn, _ = extract.build([source])  # without the header the macro is an unknown call: p is only read
    assert uaf(conn) == []


def test_callee_that_frees_on_one_path_only_is_not_a_deallocator(tmp_path):
    src = ("static int g(char *x, int e) {\n if (e) {\n  free(x);\n  return 1;\n }\n return 0;\n}\n"
           "void f(char *p, int e) {\n g(p, e);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == []


def test_callee_that_frees_on_every_returning_path_is_a_deallocator(tmp_path):
    src = ("static void h(char *x, int e) {\n if (e) {\n  die(\"no\");\n }\n free(x);\n}\n"
           "void f(char *p) {\n h(p, 0);\n p[0] = 1;\n}\n")
    assert uaf(graph(tmp_path, src)) == [(8, 9, "p")]  # the path that dies never returns to the caller


def test_if_else_directives_are_alternatives(tmp_path):
    src = "void f(char *p) {\n#ifdef A\n free(p);\n#else\n p[0] = 1;\n#endif\n}\n"
    assert uaf(graph(tmp_path, src)) == []
    src = "void f(char *p) {\n#ifdef A\n free(p);\n#endif\n p[0] = 1;\n}\n"
    assert uaf(graph(tmp_path, src)) == [(3, 5, "p")]


def test_macro_that_does_not_release_is_not_expanded(tmp_path):
    src = "#define SHOW(x) printf(\"%s\", x)\nvoid f(char *p) {\n SHOW(p);\n p[0] = 1;\n free(p);\n}\n"
    assert uaf(graph(tmp_path, src)) == [] and dfree(graph(tmp_path, src)) == []


USE_AFTER_DEAD_END = "void f(char *p, int c) {\n if (c) {\n  free(p);\n  stop(\"x\");\n }\n p[0] = 1;\n}\n"


def test_function_declared_noreturn_by_the_language_ends_the_path(tmp_path):
    src = "_Noreturn void stop(const char *m);\n" + USE_AFTER_DEAD_END
    assert uaf(graph(tmp_path, src)) == []
    src = "void stop(const char *m) __attribute__((noreturn));\n" + USE_AFTER_DEAD_END
    assert uaf(graph(tmp_path, src)) == []
    # the same function with no declaration saying it never returns: nothing ends the path
    assert uaf(graph(tmp_path, USE_AFTER_DEAD_END)) == [(3, 6, "p")]


def test_noreturn_declared_through_a_macro_whose_body_is_the_attribute(tmp_path):
    src = "#define NORETURN __attribute__((__noreturn__))\nNORETURN void stop(const char *m);\n" + USE_AFTER_DEAD_END
    assert uaf(graph(tmp_path, src)) == []


def test_macro_that_calls_a_noreturn_function_never_returns(tmp_path):
    src = ("_Noreturn void bug_at(const char *file, int line, const char *m);\n"
           "#define STOP(m) bug_at(\"f.c\", 1, m)\n" + USE_AFTER_DEAD_END.replace("stop(", "STOP("))
    assert uaf(graph(tmp_path, src)) == []




def test_noreturn_with_other_attributes_around_it(tmp_path):
    header = tmp_path / "log.h"
    header.write_text("void sshfatal(const char *, int, ...) __attribute__((noreturn))\n    __attribute__((format(printf, 2, 3)));\n"
                      "#define fatal_f(...) sshfatal(__func__, 1, __VA_ARGS__)\n", encoding="utf-8")
    src = tmp_path / "f.c"
    src.write_text("int f(char *p) {\n if (p == NULL)\n  fatal_f(\"missing\");\n return *p;\n}\n", encoding="utf-8")
    conn, failed = extract.build([src], headers=[header])
    assert failed == []
    assert [r["line"] for r in paths.null_dereference(conn)] == []
