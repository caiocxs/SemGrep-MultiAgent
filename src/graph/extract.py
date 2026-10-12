"""
Extractor: C source -> event graph (schema.sql), with tree-sitter.

Per function it walks the statements and emits one event per pointer-relevant action in evaluation order, linking each to its
control-flow successors (if/else, loops, switch, break/continue, goto, return). Pass 1 (`extract_file`) is per file; pass 2
(`resolve_calls`) binds the arguments of calls to the callee's parameters and turns each call event into a free, a use or
nothing, from a summary of what the callee does to that parameter, iterated until it stops changing (so a wrapper of `free`
two calls deep still counts).

What counts as an event (everything else is ignored):
  alloc  `p = malloc(..)` (also through a cast, `calloc`, `realloc`, `strdup`...), or the same as an initializer
  free   `free(p)` and the other deallocators in FREE_FUNCTIONS
  use    a dereference of a path (`p->x`, `p[i]`, `*p`), the argument of a call that is not a deallocator, `return p`
  reset  any other assignment to a path (`p = NULL`, `p = q`, `p++`, `p->next = ..`), which ends what a free said about it
Comparisons and plain copies of a pointer are not uses. Paths are text (`p`, `ctx->buf`, `a[i]`).
Generic conventions (not tied to one project): `exit`/`die`/`abort`... end the flow; `&p` passed to a call may reassign `p`;
a name declared in a block is a new variable when the block ends or is entered again (shadowing, loop bodies); a macro whose
name contains ALLOC assigns its first argument; a call with a block as argument (`foreach(h, k, v, { .. })`) is a loop that
assigns its plain-identifier arguments.

Nothing is listed by hand but the C standard library (`free`; `malloc`, `calloc`, `realloc`, `strdup`, `strndup`; `exit`, `abort`...).
The rest is learned from the code:
  - macros (`#define`s of the sources and of the headers passed to `build`): an object-like alias of a known name is renamed; a
    function-like macro whose body calls something with a parameter, assigns a parameter or frees one is expanded at its calls with the
    arguments substituted; one with a `for`/`while` in its body, or called with a block as an argument, is a loop that assigns its
    plain-identifier arguments at every iteration;
  - a function that frees its parameter on every path is a deallocator for its callers (summaries, to a fixed point);
  - a function declared `noreturn` by the language (`_Noreturn`, `__attribute__((noreturn))`, or a macro whose body is that attribute), a
    macro that calls such a function, and a function whose every path ends in a noreturn call or in another such function never
    return, and the flow stops after their calls;
  - a function with no usable body is a release function if three things hold (`infer_releases`): its arguments are almost never used
    after the call, as `free`'s are not; they were acquired (assigned from a call) as often as `free`'s were; and its name looks like the
    names of the functions that the code itself proves to free their parameter, by a small model of the name's words learned from
    those proven examples against the functions proven not to free anything.

A summary says a function frees its parameter only if the free lies on every path from the entry to a return (a function that frees
on an error path and returns a code is not a deallocator for its caller); a path that ends in `exit`/`die` is not a return.
`#if`/`#else` branches are alternatives, not statements in sequence.

Known limits (the graph is path-insensitive and intraprocedural except for the call summaries): conditions are not evaluated
(both sides of a branch are feasible), `&p` passed to a function and aliases (`q = p`) are not followed, a summary says "frees
its parameter somewhere", not "on every path", and macros are seen as the calls they look like.
"""

import math
import re
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Parser

from src.graph import paths

# The C standard library is the only thing given. Every other release function, wrapper macro, allocator macro, noreturn function
# and loop macro is found from the code being analyzed (see the module docstring), not listed here.
FREE_FUNCTIONS = {"free"}
ALLOC_FUNCTIONS = {"malloc", "calloc", "realloc", "strdup", "strndup"}
NORETURN_FUNCTIONS = {"exit", "_exit", "_Exit", "abort", "quick_exit", "longjmp", "thrd_exit"}
ALWAYS_TRUE = {"1", "true", "TRUE"}
NEVER_TRUE = {"0", "false", "FALSE"}
MAX_SUMMARY_ROUNDS = 6
# Inference of release functions that have no usable body (a library, a function pointer, a hook): see `infer_releases`.
MIN_SITES = 8            # call sites with a plain pointer argument needed to say anything about a name
RATE_FACTOR = 2.0        # a release function may be followed by a use as often as `free` is, times this ...
RATE_FLOOR = 0.02        # ... but never less than this
ACQUIRED_FACTOR = 0.5    # the variable must have been acquired (assigned from a call) at least this often as free's argument is ...
ACQUIRED_FLOOR = 0.2     # ... but never less than this
COMMON_WORD = 0.25       # a word in more than this share of the names the model learns from is a project prefix (`curl`, `ngx`): it says nothing
MIN_SUPPORT = 2          # a word must be seen in this many proven release functions to count as evidence
MAX_SITES = 400          # sites sampled per name (evenly spaced)
MAX_STEPS = 4000         # events visited per site
CALL_MARK = "<call:"     # detail of the marker event after each call: where a call to a function that never returns cuts the flow

MAX_MACRO_DEPTH = 4
ENTRY, RETURN, END, NORETURN = "<entry>", "<return>", "<end>", "<noreturn>"  # details of the marker events of a function
_SUBST = []  # stack of {macro parameter: argument path or None} while a macro body is being walked

_PARSER = Parser(Language(tree_sitter_c.language()))
_WS = re.compile(r"\s+")
_BASE = re.compile(r"->|\.|\[")


def _text(node):
    return _WS.sub("", node.text.decode("utf-8", errors="replace"))


def _strip(node):
    """Removes parentheses and casts around an expression."""
    while node is not None and node.type in ("parenthesized_expression", "cast_expression"):
        node = node.child_by_field_name("value") if node.type == "cast_expression" else (
            node.named_children[0] if node.named_children else None)
    return node


def path_of(node):
    """The access path of an lvalue-like expression as text, or None (`p`, `p->x`, `s.a->b`, `a[i]`)."""
    node = _strip(node)
    if node is None:
        return None
    if node.type == "identifier":
        text = _text(node)
        return _SUBST[-1].get(text, text) if _SUBST else text
    if node.type == "field_expression":
        base = path_of(node.child_by_field_name("argument"))
        field = node.child_by_field_name("field")
        if base is None or field is None:
            return None
        arrow = "->" if any(c.type == "->" for c in node.children) else "."
        return f"{base}{arrow}{_text(field)}"
    if node.type == "subscript_expression":
        base = path_of(node.child_by_field_name("argument"))
        index = node.child_by_field_name("index")
        if base is None or index is None:
            return None
        return f"{base}[{_text(index)}]"
    return None


def _identifier_of(declarator):
    """The declared name inside `*p`, `**p`, `p[10]`, `(*p)`..."""
    while declarator is not None and declarator.type != "identifier":
        inner = declarator.child_by_field_name("declarator")
        if inner is None:
            named = declarator.named_children
            inner = named[0] if named else None
        declarator = inner
    return _text(declarator) if declarator is not None else None


def _called_name(call):
    function = call.child_by_field_name("function")
    return _text(function) if function is not None and function.type == "identifier" else None


class _Function:
    """Builds the events and flow edges of one function."""

    def __init__(self, extractor, func_id, source_lines, params=()):
        self.x = extractor
        self.params = set(params)
        self.macro_depth = 0
        self.call_row = None     # while a macro body is walked, the line of the call, for the events it makes
        self.copy_of = {}        # local -> parameter it is a copy of (q = (T *)param)
        self.deref_of = {}       # local -> parameter whose pointee it holds (q = *param, `data = *dataPtr`)
        self.func_id = func_id
        self.lines = source_lines
        self.frontier = set()
        self.loops = []          # {'breaks': set, 'continues': set} of the enclosing loops/switches
        self.labels = {}         # label -> join event
        self.switch_entry = []   # frontier at the top of each enclosing switch, for its case labels
        self.scopes = []         # names declared in each enclosing block

    # -- events -------------------------------------------------------------------------------------------------
    def event(self, kind, var, node, detail=None):
        eid = self.x.next_id()
        row = node.start_point[0] if self.call_row is None else self.call_row
        if detail is None:
            detail = self.lines[row].strip()[:200] if row < len(self.lines) else ""
        self.x.events.append((eid, self.func_id, row + 1, kind, var, detail))
        if kind in ("use", "free") and var:
            owner = self.deref_of.get(_BASE.split(var, 1)[0])
            if owner:  # the pointer loaded from *owner is freed or used here: what a caller of &p needs to know
                self.x.deref_effects.append((self.func_id, owner, kind))
        for src in self.frontier:
            self.x.flow.append((src, eid))
        self.frontier = {eid}
        return eid

    def join(self, node, extra=()):
        self.frontier = set(self.frontier) | set(extra)
        return self.event("join", None, node)

    # -- expressions --------------------------------------------------------------------------------------------
    def use(self, path, node):
        if path:
            self.event("use", path, node)

    def expr(self, n):
        if n is None:
            return
        t = n.type
        if t == "assignment_expression":
            self.assign(n)
        elif t == "call_expression":
            self.call(n)
        elif t == "update_expression":
            target = n.child_by_field_name("argument")
            self.lvalue(target)
            self.reset(path_of(target), n)
        elif t == "sizeof_expression":
            return
        elif t == "field_expression":
            base = n.child_by_field_name("argument")
            self.expr(base)
            if any(c.type == "->" for c in n.children):
                self.use(path_of(base), n)
        elif t == "subscript_expression":
            base = n.child_by_field_name("argument")
            self.expr(base)
            self.expr(n.child_by_field_name("index"))
            self.use(path_of(base), n)
        elif t == "pointer_expression":
            argument = n.child_by_field_name("argument")
            self.expr(argument)
            if n.children and n.children[0].type == "*":
                self.use(path_of(argument), n)
        else:
            for child in n.named_children:
                self.expr(child)

    def lvalue(self, left):
        """The dereferences hidden in the target of an assignment (`p->x = 1` reads `p`)."""
        left = _strip(left)
        if left is None:
            return
        if left.type == "field_expression":
            base = left.child_by_field_name("argument")
            self.expr(base)
            if any(c.type == "->" for c in left.children):
                self.use(path_of(base), left)
        elif left.type == "subscript_expression":
            base = left.child_by_field_name("argument")
            self.expr(base)
            self.expr(left.child_by_field_name("index"))
            self.use(path_of(base), left)
        elif left.type == "pointer_expression":
            argument = left.child_by_field_name("argument")
            self.expr(argument)
            self.use(path_of(argument), left)

    def reset(self, path, node):
        if path:
            self.event("reset", path, node)

    def _root(self, path):
        return path if path in self.params else self.copy_of.get(path)

    def track(self, name, value):
        """Remembers `q = param`, `q = (T *)param` and `q = *param` so that uses of q count for the parameter."""
        self.copy_of.pop(name, None)
        self.deref_of.pop(name, None)
        value = _strip(value)
        if value is None:
            return
        path = path_of(value)
        if path and self._root(path):
            self.copy_of[name] = self._root(path)
        elif value.type == "pointer_expression" and value.children and value.children[0].type == "*":
            owner = self._root(path_of(value.child_by_field_name("argument")) or "")
            if owner:
                self.deref_of[name] = owner

    @staticmethod
    def _allocates(value):
        """`p = f(..)`: p now holds what a call returned (an acquisition); for the queries it is a new value, like any assignment."""
        value = _strip(value)
        return value is not None and value.type == "call_expression"

    def assign(self, n):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        self.expr(right)
        self.lvalue(left)
        target = _strip(left)
        if target is not None and target.type == "pointer_expression" and target.children and target.children[0].type == "*":
            owner = self._root(path_of(target.child_by_field_name("argument")) or "")
            if owner:  # `*param = ..`: whoever passed &p gets a new value in p
                self.x.deref_effects.append((self.func_id, owner, "reset"))
        path = path_of(left)
        if path:
            self.event("alloc" if self._allocates(right) else "reset", path, n)
            if left.type == "identifier":
                self.track(path, right)

    def call(self, n):
        function = n.child_by_field_name("function")
        name = _called_name(n)
        if name is None:
            self.expr(function)  # `p->fn(x)` dereferences p
        arguments = n.child_by_field_name("arguments")
        args = arguments.named_children if arguments is not None else []
        for _ in range(MAX_MACRO_DEPTH):  # `#define my_free free`
            alias = self.x.aliases.get(name)
            if alias is None:
                break
            name = alias
        if args and (any(a.type == "compound_statement" for a in args) or name in self.x.loop_macros):
            self.iteration_macro(args)
            return
        macro = self.x.fn_macros.get(name) if name and name not in FREE_FUNCTIONS and name not in ALLOC_FUNCTIONS else None
        if macro is not None and self.macro_depth < MAX_MACRO_DEPTH:
            for arg in args:
                self.expr(arg)
            self.expand(macro, args, n)
            return
        for arg in args:
            self.expr(arg)
        if name in FREE_FUNCTIONS:
            if args and path_of(args[0]):
                self.event("free", path_of(args[0]), n)
            return
        if name in ALLOC_FUNCTIONS:
            if name == "realloc" and args:
                self.use(path_of(args[0]), n)
            return
        for index, arg in enumerate(args):
            path = path_of(arg)
            if not path:
                continue
            if name is None:
                self.event("use", path, n)
            else:
                eid = self.event("call", path, n)
                self.x.call_args.append((eid, name, index, path, 0))
        for index, arg in enumerate(args):  # `&p`, also `(void **)&p`: the callee may free, use or fill in p (decided when it is known)
            arg = _strip(arg)
            if arg is not None and arg.type == "pointer_expression" and arg.children and arg.children[0].type == "&":
                target = path_of(arg.child_by_field_name("argument"))
                if not target:
                    continue
                if name is None:
                    self.reset(target, arg)
                else:
                    eid = self.event("call", target, arg)
                    self.x.call_args.append((eid, name, index, target, 1))
        if name in self.x.noreturn:
            self.event("join", None, n, detail=NORETURN)  # marks the end of a path that never returns to the caller
            self.frontier = set()
        elif name:
            self.event("join", None, n, detail=f"{CALL_MARK}{name}>")  # where the flow stops if `name` turns out never to return

    def expand(self, macro, args, call):
        """Walks the body of a release macro with its parameters replaced by the paths of the arguments."""
        params, body = macro
        mapping = {param: path_of(arg) for param, arg in zip(params, args)}
        root = _macro_body(body)
        if root is None:
            return
        outer = self.call_row
        self.call_row = call.start_point[0] if outer is None else outer
        self.macro_depth += 1
        _SUBST.append(mapping)
        try:
            for child in root.named_children:
                self.stmt(child)
        finally:
            _SUBST.pop()
            self.macro_depth -= 1
            self.call_row = outer

    def iteration_macro(self, args):
        """`foreach(h, k, v, { body })`: a loop whose plain-identifier arguments are assigned at every iteration."""
        head = self.join(args[0])
        for arg in args:
            if arg.type == "identifier":
                self.reset(_text(arg), arg)
        exits = set(self.frontier)
        self.loops.append({"breaks": set(), "continues": set(), "depth": len(self.scopes)})
        for arg in args:
            self.stmt(arg) if arg.type == "compound_statement" else self.expr(arg)
        ctx = self.loops.pop()
        for src in set(self.frontier) | ctx["continues"]:
            self.x.flow.append((src, head))
        self.frontier = exits | ctx["breaks"]

    # -- statements ---------------------------------------------------------------------------------------------
    def stmt(self, n):
        if n is None:
            return
        handler = getattr(self, "s_" + n.type, None)
        if handler:
            handler(n)
        elif n.type.startswith("preproc_") or n.type in ("else_clause", "compound_statement"):
            for child in n.named_children:
                self.stmt(child)
        else:
            self.expr(n)

    def _alternatives(self, n):
        """`#if`/`#ifdef`/`#elif` with its `#else`: the branches are alternatives, not statements one after the other."""
        skip = {c.id for c in (n.child_by_field_name("condition"), n.child_by_field_name("name"),
                               n.child_by_field_name("alternative")) if c is not None}
        entry = set(self.frontier)
        for child in n.named_children:
            if child.id not in skip:
                self.stmt(child)
        after_then = set(self.frontier)
        self.frontier = entry
        alternative = n.child_by_field_name("alternative")
        if alternative is not None:
            self.stmt(alternative)
        self.frontier = after_then | self.frontier

    s_preproc_if = s_preproc_ifdef = s_preproc_elif = s_preproc_elifdef = _alternatives

    @staticmethod
    def _unterminated_call(node):
        """`NAME(args)` with no `;` (the parser marks it missing): what a macro that opens a block looks like, `NAME(args) { .. }`."""
        if node.type != "expression_statement" or not any(c.is_missing for c in node.children):
            return None
        call = next(iter(node.named_children), None)
        return call if call is not None and call.type == "call_expression" else None

    def s_compound_statement(self, n):
        self.scopes.append([])
        children = n.named_children
        i = 0
        while i < len(children):
            child, following = children[i], children[i + 1] if i + 1 < len(children) else None
            call = self._unterminated_call(child)
            if call is not None and following is not None and following.type == "compound_statement":
                arguments = call.child_by_field_name("arguments")
                self.iteration_macro((list(arguments.named_children) if arguments is not None else []) + [following])
                i += 2
                continue
            self.stmt(child)
            i += 1
        for name in self.scopes.pop():  # the block ends: those names are gone (a later same name is another variable)
            self.event("reset", name, n)

    def s_expression_statement(self, n):
        for child in n.named_children:
            self.expr(child)

    def s_declaration(self, n):
        for declarator in n.children_by_field_name("declarator"):
            if declarator.type == "init_declarator":
                value = declarator.child_by_field_name("value")
                self.expr(value)
                name = _identifier_of(declarator.child_by_field_name("declarator"))
                kind = "alloc" if self._allocates(value) else "reset"
            else:
                name, kind = _identifier_of(declarator), "reset"  # a new variable starts without a value
            if name:
                self.event(kind, name, declarator)
                self.track(name, value if declarator.type == "init_declarator" else None)
                if self.scopes:
                    self.scopes[-1].append(name)

    def s_if_statement(self, n):
        self.expr(n.child_by_field_name("condition"))
        entry = set(self.frontier)
        self.stmt(n.child_by_field_name("consequence"))
        after_then = set(self.frontier)
        self.frontier = entry
        alternative = n.child_by_field_name("alternative")
        if alternative is not None:
            self.stmt(alternative)
        self.frontier = after_then | self.frontier

    def _loop_body(self, body):
        self.loops.append({"breaks": set(), "continues": set(), "depth": len(self.scopes)})
        self.stmt(body)
        return self.loops.pop()

    def _exit_when(self, condition):
        """Can the loop be left through its condition? Not with no condition (`for (;;)`) or with a constant true one."""
        return condition is not None and _text(_strip(condition) or condition) not in ALWAYS_TRUE

    def s_while_statement(self, n):
        head = self.join(n)
        condition = n.child_by_field_name("condition")
        self.expr(condition)
        exits = set(self.frontier) if self._exit_when(condition) else set()
        ctx = self._loop_body(n.child_by_field_name("body"))
        for src in set(self.frontier) | ctx["continues"]:
            self.x.flow.append((src, head))
        self.frontier = exits | ctx["breaks"]

    @staticmethod
    def _runs_once(n):
        """`for (i = 0; i < 1; i++)` and the like: constant bounds, step 1, so the body runs exactly once."""
        init, cond, update = (n.child_by_field_name(f) for f in ("initializer", "condition", "update"))
        if init is None or cond is None or update is None:
            return False
        if init.type == "declaration":
            decls = init.children_by_field_name("declarator")
            if len(decls) != 1 or decls[0].type != "init_declarator":
                return False
            var, start = _identifier_of(decls[0].child_by_field_name("declarator")), decls[0].child_by_field_name("value")
        elif init.type == "assignment_expression":
            var, start = path_of(init.child_by_field_name("left")), init.child_by_field_name("right")
        else:
            return False
        if cond.type != "binary_expression" or update.type != "update_expression" or not var \
                or _text(update) not in (var + "++", "++" + var):
            return False
        operator = cond.child_by_field_name("operator")
        left, right = cond.child_by_field_name("left"), cond.child_by_field_name("right")
        try:
            low, high = int(_text(start), 0), int(_text(right), 0)
        except (TypeError, ValueError):
            return False
        if path_of(left) != var or operator is None or _text(operator) not in ("<", "<="):
            return False
        return high - low + (1 if _text(operator) == "<=" else 0) == 1

    def s_for_statement(self, n):
        initializer = n.child_by_field_name("initializer")
        if initializer is not None:
            self.stmt(initializer) if initializer.type == "declaration" else self.expr(initializer)
        once = self._runs_once(n)
        head = self.join(n)
        condition = n.child_by_field_name("condition")
        if condition is not None:
            self.expr(condition)
        exits = set(self.frontier) if self._exit_when(condition) and not once else set()
        ctx = self._loop_body(n.child_by_field_name("body"))
        self.frontier = set(self.frontier) | ctx["continues"]
        update = n.child_by_field_name("update")
        if update is not None:
            self.join(n)
            self.expr(update)
        if not once:  # a loop that runs once has no back edge
            for src in self.frontier:
                self.x.flow.append((src, head))
            self.frontier = set()
        self.frontier = set(self.frontier) | exits | ctx["breaks"]

    def s_do_statement(self, n):
        head = self.join(n)
        ctx = self._loop_body(n.child_by_field_name("body"))
        self.frontier = set(self.frontier) | ctx["continues"]
        condition = n.child_by_field_name("condition")
        self.expr(condition)
        if _text(_strip(condition) or condition) not in NEVER_TRUE:  # `do { .. } while (0)` runs once
            for src in self.frontier:
                self.x.flow.append((src, head))
        self.frontier = (set(self.frontier) if self._exit_when(condition) else set()) | ctx["breaks"]

    def s_switch_statement(self, n):
        self.expr(n.child_by_field_name("condition"))
        entry = set(self.frontier)
        body = n.child_by_field_name("body")
        has_default = any(c.type == "case_statement" and c.children and c.children[0].type == "default"
                          for c in (body.named_children if body is not None else []))
        self.switch_entry.append(entry)
        self.loops.append({"breaks": set(), "continues": set(), "depth": len(self.scopes)})
        self.frontier = set()  # nothing falls into the first case except through its label
        if body is not None:
            for child in body.named_children:
                self.stmt(child)
        ctx = self.loops.pop()
        self.switch_entry.pop()
        outer = self.loops[-1] if self.loops else None
        if outer is not None:  # `continue` inside a switch belongs to the enclosing loop
            outer["continues"] |= ctx["continues"]
        self.frontier = set(self.frontier) | ctx["breaks"] | (set() if has_default else entry)

    def s_case_statement(self, n):
        entry = self.switch_entry[-1] if self.switch_entry else set()
        self.join(n, entry)
        value = n.child_by_field_name("value")
        for child in n.named_children:
            if value is None or child.id != value.id:
                self.stmt(child)

    def _leave_scopes(self, node):
        """break/continue skip the end of the blocks they leave: the names declared there are gone as well."""
        for names in self.scopes[self.loops[-1]["depth"]:]:
            for name in names:
                self.event("reset", name, node)

    def s_break_statement(self, n):
        if self.loops:
            self._leave_scopes(n)
            self.loops[-1]["breaks"] |= self.frontier
        self.frontier = set()

    def s_continue_statement(self, n):
        if self.loops:  # inside a switch it is passed on to the enclosing loop when the switch ends
            self._leave_scopes(n)
            self.loops[-1]["continues"] |= self.frontier
        self.frontier = set()

    def s_return_statement(self, n):
        for child in n.named_children:
            self.expr(child)
            self.use(path_of(child), child)
        self.event("join", None, n, detail=RETURN)  # the path leaves the function here, even if it made no event before
        self.frontier = set()

    def _label(self, name, node):
        if name not in self.labels:
            self.labels[name] = self.x.new_event(self.func_id, node, "join")
        return self.labels[name]

    def s_goto_statement(self, n):
        label = n.child_by_field_name("label")
        if label is not None:
            target = self._label(_text(label), n)
            for src in self.frontier:
                self.x.flow.append((src, target))
        self.frontier = set()

    def s_labeled_statement(self, n):
        label = n.child_by_field_name("label")
        target = self._label(_text(label), n)
        for src in self.frontier:
            self.x.flow.append((src, target))
        self.frontier = {target}
        for child in n.named_children:
            if label is None or child.id != label.id:
                self.stmt(child)


class Extractor:
    def __init__(self, conn):
        self.conn = conn
        self.events, self.flow, self.call_args, self.deref_effects = [], [], [], []
        self.aliases = {}           # name -> name it stands for (`#define my_free free`)
        self.fn_macros = {}         # name -> (parameters, body) of a function-like macro that is expanded at its calls
        self.loop_macros = set()    # names of macros that are loops
        self.noreturn = set(NORETURN_FUNCTIONS)  # the standard library's, plus what the code declares noreturn
        self._next = (conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]) + 1

    def next_id(self):
        eid, self._next = self._next, self._next + 1
        return eid

    def new_event(self, func_id, node, kind):
        eid = self.next_id()
        self.events.append((eid, func_id, node.start_point[0] + 1, kind, None, ""))
        return eid

    def flush(self):
        c = self.conn
        c.executemany("INSERT INTO events (id, func_id, line, kind, var, detail) VALUES (?, ?, ?, ?, ?, ?)", self.events)
        c.executemany("INSERT OR IGNORE INTO flow VALUES (?, ?)", self.flow)
        c.executemany("INSERT OR IGNORE INTO call_args (call_event, callee_name, arg_index, var, addr) VALUES (?, ?, ?, ?, ?)",
                      self.call_args)
        c.executemany("INSERT INTO deref_effects VALUES (?, ?, ?)", self.deref_effects)
        self.events, self.flow, self.call_args, self.deref_effects = [], [], [], []


def _functions(root):
    """function_definition nodes, also inside `#if` blocks, not inside other functions."""
    stack = [root]
    while stack:
        node = stack.pop()
        for child in reversed(node.children):
            if child.type == "function_definition":
                yield child
            elif child.type.startswith("preproc_") or child.type == "linkage_specification" \
                    or child.type == "declaration_list":
                stack.append(child)


def _function_name_and_params(node):
    declarator = node.child_by_field_name("declarator")
    while declarator is not None and declarator.type != "function_declarator":
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None:
        return None, []
    name = _identifier_of(declarator.child_by_field_name("declarator"))
    params = []
    parameter_list = declarator.child_by_field_name("parameters")
    for parameter in (parameter_list.named_children if parameter_list is not None else []):
        if parameter.type == "parameter_declaration":
            params.append(_identifier_of(parameter.child_by_field_name("declarator")))
    return name, params


def extract_file(conn, path, extractor=None):
    """Adds the functions and events of one C file. Returns the number of functions."""
    source = Path(path).read_bytes()
    tree = _PARSER.parse(source)
    lines = source.decode("utf-8", errors="replace").splitlines()
    own = extractor is None
    extractor = extractor or Extractor(conn)
    conn.execute("INSERT OR IGNORE INTO files (path) VALUES (?)", (str(path),))
    file_id = conn.execute("SELECT id FROM files WHERE path = ?", (str(path),)).fetchone()[0]
    count = 0
    for node in _functions(tree.root_node):
        name, params = _function_name_and_params(node)
        body = node.child_by_field_name("body")
        if not name or body is None:
            continue
        cur = conn.execute("INSERT INTO functions (file_id, name, start_line, end_line) VALUES (?, ?, ?, ?)",
                           (file_id, name, node.start_point[0] + 1, node.end_point[0] + 1))
        func_id = cur.lastrowid
        conn.executemany("INSERT INTO params VALUES (?, ?, ?)",
                         [(func_id, i, p) for i, p in enumerate(params) if p])
        builder = _Function(extractor, func_id, lines, [p for p in params if p])
        builder.event("join", None, body, detail=ENTRY)  # a path with no event at all must still start somewhere
        builder.stmt(body)
        builder.event("join", None, body, detail=END)  # falling off the end of the function is a return as well
        count += 1
    if own:
        extractor.flush()
    return count


def _bind_callees(conn):
    """Finds the function each call event calls, by file first and then by a unique name."""
    by_file = {(f, n): i for i, f, n in conn.execute("SELECT id, file_id, name FROM functions")}
    by_name = {}
    for i, n in conn.execute("SELECT id, name FROM functions"):
        by_name.setdefault(n, []).append(i)
    file_of = dict(conn.execute("SELECT id, file_id FROM functions"))
    func_of_event = dict(conn.execute("SELECT id, func_id FROM events WHERE id IN (SELECT call_event FROM call_args)"))
    for event_id, name in conn.execute("SELECT call_event, callee_name FROM call_args").fetchall():
        func = func_of_event[event_id]
        callee = by_file.get((file_of[func], name))
        if callee is None and len(by_name.get(name, [])) == 1:
            callee = by_name[name][0]
        conn.execute("UPDATE call_args SET callee_id = ? WHERE call_event = ?", (callee, event_id))

def _params_of(conn):
    params = {}
    for func_id, idx, name in conn.execute("SELECT func_id, idx, name FROM params"):
        params.setdefault(func_id, {})[name] = idx
    return params


def _cut_noreturn(conn):
    """
    Finds the functions that never return (no return or end marker is reachable from the entry, to a fixed point: a function whose
    paths all end in a call to one of them never returns either) and cuts the flow after every call to them.
    """
    out, entry, exits, name_of, marks = {}, {}, {}, {}, {}
    for src, dst in conn.execute("SELECT src, dst FROM flow"):
        out.setdefault(src, []).append(dst)
    for func_id, name in conn.execute("SELECT id, name FROM functions"):
        name_of[func_id] = name
    for event_id, func_id, detail in conn.execute("SELECT id, func_id, detail FROM events ORDER BY id"):
        entry.setdefault(func_id, event_id)
        if detail in (RETURN, END):
            exits.setdefault(func_id, set()).add(event_id)
        elif detail.startswith(CALL_MARK):
            marks.setdefault(detail[len(CALL_MARK):-1], []).append(event_id)
    never, cut = set(), []
    for _ in range(MAX_SUMMARY_ROUNDS):
        candidates = {}
        for func_id, name in name_of.items():
            if name in never or name in NORETURN_FUNCTIONS or func_id not in entry:
                continue
            seen, stack, returns = {entry[func_id]}, [entry[func_id]], False
            while stack and not returns:
                node = stack.pop()
                if node in exits.get(func_id, ()):
                    returns = True
                    break
                for nxt in out.get(node, ()):
                    if nxt not in seen:
                        seen.add(nxt)
                        stack.append(nxt)
            candidates[name] = candidates.get(name, True) and not returns  # every definition of the name must be noreturn
        found = {name for name, ok in candidates.items() if ok}
        if not found:
            break
        never |= found
        for name in found:
            for mark in marks.get(name, ()):
                if out.pop(mark, None) is not None:
                    cut.append(mark)
    conn.executemany("DELETE FROM flow WHERE src = ?", [(m,) for m in cut])
    return never


def _reaches_use(out, kind, var_of, calls, start, var):
    """
    True if `var` is read, freed or passed on to any call on some path after `start` before it is given a new value (`calls` are the
    call events: a call that the summaries say does nothing with the parameter still received the variable); None if the walk is too long.
    """
    seen, stack, steps = set(), list(out.get(start, ())), 0
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        steps += 1
        if steps > MAX_STEPS:
            return None
        other = var_of[node]
        if other is not None:
            k = kind[node]
            if (k in ("use", "free") or node in calls) and (other == var or other.startswith((var + "->", var + ".", var + "["))):
                return True
            if k in ("reset", "alloc") and (other == var or var.startswith((other + "->", other + ".", other + "["))
                                            or "[" + other + "]" in var):
                continue
        stack.extend(out.get(node, ()))
    return False


def _acquired(inn, kind, var_of, start, var):
    """True if, going back from `start`, the variable was last given a value by a call (`p = f(..)`) on some path."""
    seen, stack, steps = set(), list(inn.get(start, ())), 0
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        steps += 1
        if steps > MAX_STEPS:
            return None
        if var_of[node] == var and kind[node] in ("reset", "alloc"):
            if kind[node] == "alloc":
                return True
            continue
        stack.extend(inn.get(node, ()))
    return False


def _words(name):
    """The lower-case words of a function name: `ngx_free_chain` and `xmlFreeDoc` give {ngx, free, chain} and {xml, free, doc}."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if len(w) >= 2 and not w.isdigit()}


def _name_model(conn):
    """
    A small model of the words of release function names, learned from this code: the positives are the functions proven to free a
    parameter on every path (and the seed `free`), the negatives the functions with parameters that are proven to free none.
    Returns score(name) -> (sum of the log-odds of the informative words seen in the examples, whether one of them was seen in at least
    MIN_SUPPORT positives).
    """
    positives = {row[0] for row in conn.execute(
        "SELECT DISTINCT f.name FROM summaries s JOIN functions f ON f.id = s.func_id WHERE s.effect = 'frees' AND s.deref = 0")}
    positives |= set(FREE_FUNCTIONS)
    freeing = {row[0] for row in conn.execute("SELECT DISTINCT f.name FROM summaries s JOIN functions f ON f.id = s.func_id "
                                              "WHERE s.effect = 'frees'")}
    with_params = {row[0] for row in conn.execute("SELECT DISTINCT f.name FROM params p JOIN functions f ON f.id = p.func_id")}
    negatives = with_params - freeing - positives
    pos, neg = {}, {}
    for names, table in ((positives, pos), (negatives, neg)):
        for name in names:
            for word in _words(name):
                table[word] = table.get(word, 0) + 1
    p_total, n_total = len(positives), len(negatives)

    def informative(word):
        return (pos.get(word, 0) + neg.get(word, 0)) <= COMMON_WORD * (p_total + n_total)

    def score(name):
        total, supported = 0.0, False
        for word in _words(name):
            if (word not in pos and word not in neg) or not informative(word):
                continue  # a word the code never showed, or one every name has, says nothing
            total += math.log((pos.get(word, 0) + 1) / (p_total + 2)) - math.log((neg.get(word, 0) + 1) / (n_total + 2))
            supported = supported or pos.get(word, 0) >= MIN_SUPPORT
        return total, supported

    return score


def infer_releases(conn):
    """
    Release functions with no usable body (a library, a function pointer such as `xmlFree`, a hook), learned from this code. Three
    things must hold for a callee name and argument position, over its call sites with a plain pointer argument (at least MIN_SITES):
      - the after-use rate, the share of sites where the variable is used, freed or passed again after the call, on some path, before
        it is reassigned, is at most max(RATE_FACTOR x the rate of `free` in the same code, RATE_FLOOR);
      - the variable was acquired (assigned from a call, on some path) at least ACQUIRED_FACTOR times as often as `free`'s argument
        (and at least ACQUIRED_FLOOR): a last use of a parameter or a constant is not a release;
      - the name's words, by `_name_model`, look like the names of the functions the code proves to free their parameters.
    Returns {(name, argument index): (sites, after-use rate, acquired rate, name score)}.
    """
    out, inn, kind, var_of = {}, {}, {}, {}
    for src, dst in conn.execute("SELECT src, dst FROM flow"):
        out.setdefault(src, []).append(dst)
        inn.setdefault(dst, []).append(src)
    for event_id, k, var in conn.execute("SELECT id, kind, var FROM events"):
        kind[event_id], var_of[event_id] = k, var
    call_events = set()
    sites = {}
    for event_id, name, index, var in conn.execute("SELECT call_event, callee_name, arg_index, var FROM call_args WHERE addr = 0"):
        call_events.add(event_id)
        sites.setdefault((name, index), []).append((event_id, var))

    def measure(items):
        step = max(1, len(items) // MAX_SITES)
        used = acq = total = 0
        for event_id, var in items[::step]:
            after = _reaches_use(out, kind, var_of, call_events, event_id, var)
            got = _acquired(inn, kind, var_of, event_id, var)
            if after is None or got is None:
                continue
            total += 1
            used += bool(after)
            acq += bool(got)
        return (used / total, acq / total, total) if total else (None, None, 0)

    direct = [(e, var_of[e]) for e, k in sorted(kind.items()) if k == "free" and e not in call_events and var_of[e]]
    free_used, free_acquired, _ = measure(direct)
    max_used = max(RATE_FACTOR * (free_used or 0.0), RATE_FLOOR)
    min_acquired = max(ACQUIRED_FACTOR * (free_acquired or 0.0), ACQUIRED_FLOOR)
    score = _name_model(conn)
    found = {}
    for (name, index), items in sites.items():
        if len(items) < MIN_SITES or all(kind[e] == "free" for e, _ in items):
            continue
        value, seen_positive = score(name)
        if value <= 0 or not seen_positive:
            continue  # cheapest test first: the name must look like a release function
        used, acquired, total = measure(items)
        if total >= MIN_SITES and used <= max_used and acquired >= min_acquired:
            found[(name, index)] = (len(items), used, acquired, value)
    return found


def resolve_calls(conn, infer=True):
    """Binds call arguments to callees, cuts the flow after functions that never return, summarizes what functions do to their
    parameters and, with `infer`, learns the release functions that have no usable body (see the module docstring)."""
    _bind_callees(conn)
    _cut_noreturn(conn)
    params = _params_of(conn)
    inferred = set()
    _summarize(conn, params, inferred)
    learned = {}
    if infer:
        for _ in range(2):  # a wrapper of a learned release function is a release function too
            found = infer_releases(conn)
            new = {k: v for k, v in found.items() if k not in inferred}
            if not new:
                break
            learned.update(new)
            inferred |= set(new)
            _summarize(conn, params, inferred)
    conn.execute("DELETE FROM inferred_release")
    conn.executemany("INSERT INTO inferred_release VALUES (?, ?, ?, ?, ?, ?)",
                     [(n, i, c, r, a, w) for (n, i), (c, r, a, w) in sorted(learned.items())])
    conn.commit()


def _summarize(conn, params, inferred):
    """Turns each call event into free/use/reset/join from what the callees do to their parameters, to a fixed point."""
    flow_cache = {}

    def flow_of(func_id):
        """(entry event, successors, exits) of a function; the exits are its explicit return and end markers."""
        if func_id not in flow_cache:
            ids = conn.execute("SELECT id, detail FROM events WHERE func_id = ? ORDER BY id", (func_id,)).fetchall()
            out = {}
            for src, dst in conn.execute("SELECT f.src, f.dst FROM flow f JOIN events e ON e.id = f.src WHERE e.func_id = ?",
                                         (func_id,)):
                out.setdefault(src, []).append(dst)
            exits = {i for i, detail in ids if detail in (RETURN, END)}
            flow_cache[func_id] = (ids[0][0] if ids else None, out, exits)
        return flow_cache[func_id]

    def on_every_path(func_id, free_ids):
        """True when no return can be reached from the entry without passing one of the free events."""
        entry, out, exits = flow_of(func_id)
        if entry is None:
            return False
        if entry in free_ids:
            return True
        seen, stack = {entry}, [entry]
        while stack:
            node = stack.pop()
            if node in exits:
                return False
            for nxt in out.get(node, ()):
                if nxt not in free_ids and nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return True

    def summaries():
        effects = set()
        frees = {}
        for event_id, func_id, var, kind in conn.execute("SELECT id, func_id, var, kind FROM events WHERE kind IN ('free', 'use')"):
            idx = params.get(func_id, {}).get(var)
            if idx is None:
                continue
            if kind == "free":
                frees.setdefault((func_id, idx), set()).add(event_id)
            else:
                effects.add((func_id, idx, 0, "uses"))
        for (func_id, idx), ids in frees.items():
            if on_every_path(func_id, ids):
                effects.add((func_id, idx, 0, "frees"))
        for func_id, name, kind in conn.execute("SELECT func_id, param, effect FROM deref_effects"):
            idx = params.get(func_id, {}).get(name)
            if idx is not None:
                effects.add((func_id, idx, 1, {"free": "frees", "use": "uses", "reset": "resets"}[kind]))
        return effects

    calls = conn.execute("SELECT call_event, callee_id, arg_index, addr, callee_name FROM call_args").fetchall()
    for _ in range(MAX_SUMMARY_ROUNDS):
        effects = summaries()
        changed = 0
        for event_id, callee, index, addr, name in calls:
            if callee is not None and (callee, index, addr, "resets") in effects:
                kind = "reset"  # the callee assigns *param: after the call p holds another value (e.g. a pop of a list head)
            elif callee is not None and (callee, index, addr, "frees") in effects:
                kind = "free"
            elif not addr and (name, index) in inferred:
                kind = "free"  # learned from how the code uses it (`infer_releases`)
            elif callee is not None and (callee, index, addr, "uses") in effects:
                kind = "use"
            elif addr:
                kind = "reset"  # `&p` to a function that does not free or read p: it may have assigned it
            elif callee is None:
                kind = "use"  # a call the project does not define: assume it reads its pointer arguments
            else:
                kind = "join"
            changed += conn.execute("UPDATE events SET kind = ? WHERE id = ? AND kind != ?", (kind, event_id, kind)).rowcount
        if not changed:
            break
    conn.execute("DELETE FROM summaries")
    conn.executemany("INSERT INTO summaries (func_id, param, deref, effect) VALUES (?, ?, ?, ?)", sorted(summaries()))
    conn.commit()


_BODY_CACHE = {}


def _macro_body(body):
    """The statements of a macro body as a compound_statement (parsed as the body of a function), or None."""
    if body not in _BODY_CACHE:
        source = ("void __macro(void) {" + body + ";\n}").encode("utf-8")  # a macro body is often an expression
        tree = _PARSER.parse(source)
        function = next((c for c in tree.root_node.children if c.type == "function_definition"), None)
        _BODY_CACHE[body] = (tree, function.child_by_field_name("body") if function is not None else None)
    return _BODY_CACHE[body][1]


_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\(([^)]*)\))?[ \t]*(.*)$")
_CONTINUATION = re.compile(r"\\\r?\n")
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def collect_macros(files):
    """
    {name: [("alias", target) | ("fn", params, body), ...]} of the `#define`s in these files (also those inside `#if`).
    Read as text, not through the parser: headers full of conditional code are often not valid C for it (the `#define`s of curl's
    `curl_setup.h` sit inside an error node), and a definition is a line (with its continuations) anyway.
    """
    found = {}
    for f in files:
        try:
            text = Path(f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in _COMMENT.sub(" ", _CONTINUATION.sub(" ", text)).split("\n"):
            m = _DEFINE.match(line)
            if not m:
                continue
            name, has_params, params, value = m.group(1), m.group(2), m.group(3), m.group(4).strip()
            if has_params is None:
                if re.fullmatch(r"[A-Za-z_]\w*", value):
                    found.setdefault(name, []).append(("alias", value))
                elif value:
                    found.setdefault(name, []).append(("value", value))
            else:
                found.setdefault(name, []).append(("fn", [x.strip() for x in params.split(",") if x.strip()], value))
    return found


def _relevant(params, body):
    """Does the body do something with a parameter that matters for lifetimes: call something with it, assign it?"""
    plain = re.sub(r"\bsizeof\b", " ", body)
    for param in params:
        word = re.escape(param)
        if re.search(r"\b[A-Za-z_]\w*\s*\([^;{}]*\b" + word + r"\b", plain):
            return True
        if re.search(r"\b" + word + r"\b\s*\)?\s*=(?!=)", plain):
            return True
    return False


def macro_table(definitions):
    """
    From the `#define`s: ({name: target} aliases, {name: (parameters, body)} macros to expand, {name} loop macros). An alias of a name
    that frees (the seed `free` or a macro that reaches it) wins over the other definitions of the same name (a project often defines
    one macro several ways, by configuration).
    """
    seeds = FREE_FUNCTIONS | ALLOC_FUNCTIONS | NORETURN_FUNCTIONS
    frees = set(FREE_FUNCTIONS)
    aliases, macros, loops = {}, {}, set()
    for _ in range(MAX_MACRO_DEPTH + 2):
        pattern = re.compile(r"\b(?:" + "|".join(sorted(map(re.escape, frees))) + r")\b\s*\(")
        changed = False
        for name, defs in definitions.items():
            if name in frees or name in seeds:
                continue
            target = next((d[1] for d in defs if d[0] == "alias" and d[1] in frees), None)
            if target is not None:
                aliases[name] = target
                frees.add(name)
                changed = True
                continue
            definition = next((d for d in defs if d[0] == "fn" and pattern.search(d[2])), None)
            if definition is not None:
                macros[name] = (definition[1], definition[2])
                frees.add(name)
                changed = True
        if not changed:
            break
    for name, defs in definitions.items():
        if name in seeds or name in aliases or name in macros:
            continue
        targets = {d[1] for d in defs if d[0] == "alias"}
        fns = [d for d in defs if d[0] == "fn"]
        if len(targets) == 1 and not fns:
            aliases[name] = next(iter(targets))
            continue
        for d in fns:
            body = d[2]
            if re.search(r"\bfor\s*\(|\bwhile\s*\((?!\s*0\s*\))", body):
                loops.add(name)
                break
            if _relevant(d[1], body):
                macros[name] = (d[1], body)
                break
    return aliases, macros, loops


_NORETURN_ATTRIBUTE = r"_Noreturn|__attribute__\s*\(\(\s*_*noreturn_*\s*\)\)|__declspec\s*\(\s*noreturn\s*\)|\[\[\s*noreturn\s*\]\]"


def declared_noreturn(files, definitions):
    """
    Names the code declares as never returning: `_Noreturn void f(..)`, `void f(..) __attribute__((noreturn));`, and the same through a
    macro whose body is that attribute (`#define NORETURN __attribute__((__noreturn__))`); then the function-like macros that call one
    of those names (`#define BUG(...) BUG_fl(__FILE__, __LINE__, __VA_ARGS__)`), to a fixed point.
    """
    attribute = {name for name, defs in definitions.items()
                 if any(d[0] == "value" and re.search(_NORETURN_ATTRIBUTE, d[1]) for d in defs)}
    marker = "|".join([_NORETURN_ATTRIBUTE] + [r"\b" + re.escape(n) + r"\b" for n in sorted(attribute)])
    before = re.compile(r"(?:" + marker + r")[^;{}()]*?\b([A-Za-z_]\w*)\s*\(")
    after = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:" + marker + r")\s*[;{]")
    names = set()
    for f in files:
        try:
            text = _COMMENT.sub(" ", Path(f).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for pattern in (before, after):
            names.update(m.group(1) for m in pattern.finditer(text))
    names -= attribute
    for _ in range(MAX_MACRO_DEPTH + 2):
        pattern = re.compile(r"\b(?:" + "|".join(sorted(map(re.escape, names | NORETURN_FUNCTIONS))) + r")\b\s*\(")
        grown = {name for name, defs in definitions.items() if name not in names
                 and any(d[0] == "fn" and pattern.search(d[2]) for d in defs)}
        if not grown:
            break
        names |= grown
    return names


def build(files, db=":memory:", headers=()):
    """
    Extracts every file into one graph and resolves the calls. Files that fail to parse are skipped and returned. `headers` are
    read only for their `#define`s of release macros (see the module docstring).
    """
    conn = paths.connect(db)
    extractor = Extractor(conn)
    sources = list(files) + list(headers)
    definitions = collect_macros(sources)
    extractor.aliases, extractor.fn_macros, extractor.loop_macros = macro_table(definitions)
    extractor.noreturn |= declared_noreturn(sources, definitions)
    failed = []
    for f in files:
        try:
            extract_file(conn, f, extractor)
        except (OSError, ValueError) as error:
            failed.append((str(f), str(error)))
    extractor.flush()
    resolve_calls(conn)
    return conn, failed
