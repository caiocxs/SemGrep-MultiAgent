from src.graph import extract, paths


def graph(tmp_path, source):
    f = tmp_path / "f.c"
    f.write_text(source, encoding="utf-8")
    conn, failed = extract.build([f])
    assert failed == []
    extract.prepare_leaks(conn)
    return conn


def leaks(tmp_path, source):
    return [(r["free_line"], r["var"]) for r in paths.memory_leak(graph(tmp_path, source))]


def test_a_local_allocation_that_is_never_freed_leaks(tmp_path):
    assert leaks(tmp_path, "void f(void) {\n char *p = malloc(10);\n p[0] = 1;\n}\n") == [(2, "p")]


def test_freed_allocation_does_not_leak(tmp_path):
    assert leaks(tmp_path, "void f(void) {\n char *p = malloc(10);\n p[0] = 1;\n free(p);\n}\n") == []


def test_returned_pointer_is_held_by_the_caller(tmp_path):
    assert leaks(tmp_path, "char *f(void) {\n char *p = malloc(10);\n return p;\n}\n") == []


def test_stored_pointer_is_held_elsewhere(tmp_path):
    assert leaks(tmp_path, "void f(struct s *c) {\n char *p = malloc(10);\n c->buf = p;\n}\n") == []
    assert leaks(tmp_path, "void f(char **out) {\n char *p = malloc(10);\n *out = p;\n}\n") == []


def test_pointer_given_to_an_unknown_function_is_assumed_to_be_taken(tmp_path):
    assert leaks(tmp_path, "void f(void) {\n char *p = malloc(10);\n adopt(p);\n}\n") == []


def test_null_branch_has_nothing_to_free(tmp_path):
    ok = "int f(void) {\n char *p = malloc(10);\n if (!p) {\n  return -1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, ok) == []
    ok = "int f(void) {\n char *p = malloc(10);\n if (p == NULL) {\n  return -1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, ok) == []
    ok = "int f(void) {\n char *p;\n if ((p = malloc(10)) == NULL) {\n  return -1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, ok) == []
    ok = "int f(void) {\n char *p = malloc(10);\n if (p) {\n  free(p);\n }\n return 0;\n}\n"
    assert leaks(tmp_path, ok) == []


def test_one_path_without_a_free_is_enough(tmp_path):
    src = "int f(int c) {\n char *p = malloc(10);\n if (!p) {\n  return -1;\n }\n if (c) {\n  return 1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, src) == [(2, "p")]


def test_function_that_returns_what_it_allocates_is_an_allocator(tmp_path):
    src = "static char *xnew(void) {\n return malloc(4);\n}\nvoid f(void) {\n char *p = xnew();\n p[0] = 1;\n}\n"
    assert leaks(tmp_path, src) == [(5, "p")]
    src = "static char *xnew(void) {\n char *r = malloc(4);\n return r;\n}\nvoid f(void) {\n char *p = xnew();\n p[0] = 1;\n}\n"
    assert leaks(tmp_path, src) == [(6, "p")]
    src = "static char *lookup(void) {\n return table;\n}\nvoid f(void) {\n char *p = lookup();\n p[0] = 1;\n}\n"
    assert leaks(tmp_path, src) == []  # what a function returns that it did not allocate is not an allocation


def test_realloc_over_the_same_pointer_leaks_the_old_block_if_it_fails(tmp_path):
    src = "void f(void) {\n char *p = malloc(10);\n p = realloc(p, 20);\n if (p != NULL) {\n  free(p);\n }\n}\n"
    assert leaks(tmp_path, src) == [(2, "p")]
    src = "void f(void) {\n char *p = malloc(10);\n char *t = realloc(p, 20);\n if (t != NULL) {\n  p = t;\n }\n free(p);\n}\n"
    assert leaks(tmp_path, src) == []


def test_callee_that_does_not_keep_the_pointer_leaves_the_leak(tmp_path):
    assert leaks(tmp_path, "static void show(char *x) {\n x[0] = 1;\n}\nvoid f(void) {\n char *p = malloc(4);\n show(p);\n}\n") == [(5, "p")]


def test_callee_that_keeps_or_frees_the_pointer_takes_it(tmp_path):
    kept = "static char *kept;\nstatic void keep(char *x) {\n kept = x;\n}\nvoid f(void) {\n char *p = malloc(4);\n keep(p);\n}\n"
    assert leaks(tmp_path, kept) == []
    dropped = "static void drop(char *x) {\n free(x);\n}\nvoid f(void) {\n char *p = malloc(4);\n drop(p);\n}\n"
    assert leaks(tmp_path, dropped) == []
    passed_on = ("static void drop(char *x) {\n free(x);\n}\nstatic void wrap(char *y) {\n drop(y);\n}\n"
                 "void f(void) {\n char *p = malloc(4);\n wrap(p);\n}\n")
    assert leaks(tmp_path, passed_on) == []


def test_reader_without_a_body_is_learned_from_the_frees_that_follow_it(tmp_path):
    many = "".join(f"void g{i}(void) {{\n char *p = malloc(4);\n lib_print(p);\n free(p);\n}}\n" for i in range(10))
    src = many + "void f(void) {\n char *p = malloc(4);\n lib_print(p);\n}\n"
    assert leaks(tmp_path, src) == [(52, "p")]
    few = "".join(f"void g{i}(void) {{\n char *p = malloc(4);\n lib_print(p);\n free(p);\n}}\n" for i in range(2))
    assert leaks(tmp_path, few + "void f(void) {\n char *p = malloc(4);\n lib_print(p);\n}\n") == []  # too few sites to say


def test_constant_conditions_keep_only_the_branch_that_runs(tmp_path):
    assert leaks(tmp_path, "void f(void) {\n char *p = malloc(4);\n if (1) {\n  free(p);\n }\n}\n") == []
    assert leaks(tmp_path, "void f(void) {\n char *p = malloc(4);\n if (0) {\n  free(p);\n }\n}\n") == [(2, "p")]
    assert leaks(tmp_path, "void f(void) {\n char *p = malloc(4);\n if (5 == 5) {\n  free(p);\n }\n}\n") == []
    assert leaks(tmp_path, "static const int ON = 1;\nvoid f(void) {\n char *p = malloc(4);\n if (ON) {\n  free(p);\n }\n}\n") == []
    assert leaks(tmp_path, "static int yes(void) {\n return 1;\n}\nvoid f(void) {\n char *p = malloc(4);\n if (yes()) {\n  free(p);\n }\n}\n") == []
    src = "static int flag = 1;\nvoid set(void) {\n flag = 0;\n}\nvoid f(void) {\n char *p = malloc(4);\n if (flag) {\n  free(p);\n }\n}\n"
    assert leaks(tmp_path, src) == [(6, "p")]  # assigned somewhere else: not a constant


def test_switch_on_a_constant_runs_one_case(tmp_path):
    src = "void f(void) {\n char *p = malloc(4);\n switch (6) {\n case 6:\n  free(p);\n  break;\n default:\n  break;\n }\n}\n"
    assert leaks(tmp_path, src) == []
    src = "void f(void) {\n char *p = malloc(4);\n switch (7) {\n case 6:\n  free(p);\n  break;\n default:\n  break;\n }\n}\n"
    assert leaks(tmp_path, src) == [(2, "p")]


def test_goto_cleanup_frees_on_every_path(tmp_path):
    src = "int f(int c) {\n char *p = malloc(4);\n if (c) {\n  goto out;\n }\n p[0] = 1;\nout:\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, src) == []


def test_global_is_not_followed_and_a_parameter_overwritten_is(tmp_path):
    assert leaks(tmp_path, "static char *g;\nvoid f(void) {\n g = malloc(4);\n}\n") == []
    assert leaks(tmp_path, "void f(char *p) {\n p = malloc(4);\n}\n") == [(2, "p")]


def test_allocation_freed_in_each_iteration_does_not_leak(tmp_path):
    assert leaks(tmp_path, "void f(int n) {\n int i;\n for (i = 0; i < n; i++) {\n  char *p = malloc(4);\n  free(p);\n }\n}\n") == []
    assert leaks(tmp_path, "void f(int n) {\n int i;\n for (i = 0; i < n; i++) {\n  char *p = malloc(4);\n }\n}\n") == [(4, "p")]


def test_exit_path_is_not_a_leak(tmp_path):
    assert leaks(tmp_path, "void f(int c) {\n char *p = malloc(4);\n if (c) {\n  exit(1);\n }\n free(p);\n}\n") == []


def test_a_function_that_returns_an_int_is_not_an_allocator(tmp_path):
    src = "static int bogus(void) {\n return malloc(4);\n}\nvoid f(void) {\n char *p = bogus();\n p[0] = 1;\n}\n"
    assert leaks(tmp_path, src) == []


def test_a_variable_that_cannot_hold_a_pointer_is_not_followed(tmp_path):
    src = "static char *xnew(void) {\n return malloc(4);\n}\nvoid f(void) {\n int n = xnew();\n n = 1;\n}\n"
    assert leaks(tmp_path, src) == []


def test_returning_the_address_of_a_field_gives_the_block_away(tmp_path):
    assert leaks(tmp_path, "struct s *f(void) {\n struct s *p = malloc(8);\n return &p->base;\n}\n") == []


def test_chained_assignment_gives_the_value_to_the_first_name(tmp_path):
    assert leaks(tmp_path, "void f(void) {\n char *copy;\n char *s;\n copy = s = malloc(4);\n free(copy);\n}\n") == []


def test_macro_that_stores_its_parameter_keeps_the_block(tmp_path):
    src = "#define PUSH(head, elm) do { *(head) = (elm); } while (0)\nvoid f(char **list) {\n char *p = malloc(4);\n PUSH(list, p);\n}\n"
    assert leaks(tmp_path, src) == []


def test_macro_with_token_pasting_is_an_opaque_call_that_takes_the_pointer(tmp_path):
    src = "#define INSERT(name, x) name##_insert(x)\nvoid f(void) {\n char *p = malloc(4);\n INSERT(tree, p);\n}\n"
    assert leaks(tmp_path, src) == []


def test_realloc_of_a_null_pointer_is_an_allocation(tmp_path):
    assert leaks(tmp_path, "void f(void) {\n char *p = NULL;\n p = realloc(p, 10);\n}\n") == [(3, "p")]


def test_a_function_that_sometimes_returns_memory_it_does_not_own_is_not_an_allocator(tmp_path):
    src = "static char *pick(int c) {\n static char buf[4];\n if (c) {\n  return malloc(4);\n }\n return buf;\n}\nvoid f(void) {\n char *p = pick(1);\n p[0] = 1;\n}\n"
    assert leaks(tmp_path, src) == []
    src = "static char *mk(int c) {\n if (c) {\n  return malloc(4);\n }\n return NULL;\n}\nvoid f(void) {\n char *p = mk(1);\n p[0] = 1;\n}\n"
    assert leaks(tmp_path, src) == [(8, "p")]


def test_an_allocator_whose_own_sites_are_flagged_far_more_than_mallocs_is_an_arena(tmp_path):
    many = "".join(f"void g{i}(void) {{\n char *p = arena();\n p[0] = 1;\n}}\n" for i in range(10))
    arena = "static char *arena(void) {\n return malloc(4);\n}\n"
    assert leaks(tmp_path, arena + many) == []  # every one of ten sites would be a leak: the memory is not the caller's to free
    few = "".join(f"void g{i}(void) {{\n char *p = arena();\n p[0] = 1;\n}}\n" for i in range(2))
    assert len(leaks(tmp_path, arena + few)) == 2  # two sites say nothing


def test_null_test_inside_a_compound_condition_is_a_null_branch(tmp_path):
    either = "int f(int n) {\n char *p;\n if (n < 0 || (p = malloc(n)) == NULL) {\n  return -1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, either) == []
    both = "int f(int n) {\n char *p = malloc(n);\n if (n > 0 && p != NULL) {\n  free(p);\n }\n return 0;\n}\n"
    assert [line for line, _ in leaks(tmp_path, both)] == [2]  # n <= 0 still leaks p: only the NULL side is cleared
    lone = "int f(int n) {\n char *p = malloc(n);\n if (n < 0 || n > 9) {\n  return -1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, lone) == [(2, "p")]  # a condition that does not test p says nothing about it


def test_null_test_written_with_a_cast_is_a_null_test(tmp_path):
    src = "int f(int n) {\n char *p = malloc(n);\n if (p == (char *) NULL) {\n  return -1;\n }\n free(p);\n return 0;\n}\n"
    assert leaks(tmp_path, src) == []
    src = "int f(int n) {\n char *p = malloc(n);\n if (p != (char *) NULL) {\n  free(p);\n }\n return 0;\n}\n"
    assert leaks(tmp_path, src) == []
