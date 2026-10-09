import pytest

from src.pipeline import project_apis
from src.pipeline.project_apis import analyse, definitions, describe
from src.pipeline.synthesize import synthesize
from tests.test_roles import RULES, run_loop
from tests.test_synthesize import graded

HEADER = """\
#define FREE_AND_NULL(p) do { free(p); (p) = NULL; } while (0)
#define ALLOC_ARRAY(x, n) ((x) = xmalloc((n) * sizeof(*(x))))

void *xmalloc(size_t size)
{
	void *ret;

	ret = malloc(size);
	if (!ret)
		die("out of memory");
	return ret;
}

void release_node(struct node *node)
{
	free(node->name);
	free(node);
}

void drop_tree(struct node *tree)
{
	release_node(tree);
}

void *grow(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (!ptr)
		free(ptr);
	return ptr;
}

int count_nodes(struct node *list)
{
	int n = 0;
	for (; list; list = list->next)
		n++;
	return n;
}
"""

CLIENT = """\
void work(struct node *a, char *s)
{
	ALLOC_ARRAY(s, 4);
	drop_tree(a);
	FREE_AND_NULL(s);
	xmalloc(3);
	grow(s, 8);
}
"""


def project(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    (repo / "wrapper.h").write_text(HEADER, encoding="utf-8")
    for i in range(12):
        (repo / f"client{i}.c").write_text(CLIENT, encoding="utf-8")
    return repo


def classified():
    return analyse(definitions(HEADER))


def test_a_macro_that_frees_and_clears_its_argument_is_a_clearer():
    releasers, clearers, _ = classified()
    assert releasers["FREE_AND_NULL"] == 0 and "FREE_AND_NULL" in clearers


def test_a_wrapper_of_a_wrapper_is_a_releaser_but_not_a_clearer():
    releasers, clearers, _ = classified()
    assert "release_node" in releasers and "drop_tree" in releasers      # drop_tree calls release_node, which frees
    assert "drop_tree" not in clearers and "release_node" not in clearers


def test_a_function_that_frees_on_one_path_of_a_realloc_is_not_a_wrapper():
    releasers, _, _ = classified()
    assert "grow" not in releasers and "count_nodes" not in releasers


def test_allocators_are_found_by_the_value_they_return_and_by_assigning_to_their_first_argument():
    _, _, allocators = classified()
    assert "xmalloc" in allocators and "ALLOC_ARRAY" in allocators       # ALLOC_ARRAY assigns xmalloc(...), a wrapper found first
    assert "count_nodes" not in allocators and "release_node" not in allocators


def test_the_standard_functions_are_not_listed():
    releasers, clearers, allocators = classified()
    assert not ({"free"} & set(releasers)) and not ({"malloc", "calloc"} & allocators)


def test_the_description_lists_the_functions_most_used_first(tmp_path):
    text = describe(project(tmp_path))
    assert text.startswith("### Memory functions of the project the rule will run on")
    assert "`release_node` (argument 1)" in text and "`drop_tree` (argument 1)" in text
    assert "AND set the variable to NULL" in text and "`FREE_AND_NULL` (argument 1)" in text
    assert "`xmalloc`" in text and "`ALLOC_ARRAY`" in text


def test_a_project_without_such_functions_gives_an_empty_description(tmp_path):
    repo = tmp_path / "plain"
    repo.mkdir()
    (repo / "a.c").write_text("int add(int a, int b)\n{\n\treturn a + b;\n}\n", encoding="utf-8")
    assert describe(repo) == ""


def test_the_project_functions_reach_both_prompts_only_when_asked(tmp_path, monkeypatch):
    repo = project(tmp_path)
    reports = [graded(true_positives=2, detected=2, false_positives=5), graded(true_positives=3, detected=3)]
    answers = lambda: {"generator": [RULES["a"]], "corrector": [RULES["b"]]}
    _, with_apis, _ = run_loop(tmp_path, monkeypatch, reports, answers(), negatives=repo, project_apis=True,
                               min_recall=0.0, max_fix_attempts=2)
    _, without, _ = run_loop(tmp_path, monkeypatch, reports, answers(), negatives=repo, min_recall=0.0, max_fix_attempts=2)

    assert all("Memory functions of the project" in prompt and "`FREE_AND_NULL`" in prompt for _, prompt in with_apis)
    assert all("Memory functions of the project" not in prompt and "{{" not in prompt for _, prompt in without)


def test_the_option_is_recorded_in_the_log(tmp_path, monkeypatch):
    repo = project(tmp_path)
    run, _, _ = run_loop(tmp_path, monkeypatch, [graded(true_positives=3, detected=3)], {"generator": [RULES["a"]]},
                         negatives=repo, project_apis=True, min_recall=0.0)
    assert run["roles"]["project_apis"] is True and run["roles"]["guard"] is False


def test_the_project_functions_need_a_project_to_read(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="needs negatives"):
        run_loop(tmp_path, monkeypatch, [graded(true_positives=3, detected=3)], {"generator": [RULES["a"]]},
                 project_apis=True, min_recall=0.0)


def test_module_exports_are_the_ones_the_pipeline_uses():
    assert callable(project_apis.describe) and callable(synthesize)
