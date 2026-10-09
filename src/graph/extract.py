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

Known limits (the graph is path-insensitive and intraprocedural except for the call summaries): conditions are not evaluated
(both sides of a branch are feasible), `&p` passed to a function and aliases (`q = p`) are not followed, a summary says "frees
its parameter somewhere", not "on every path", and macros are seen as the calls they look like.
"""

import re
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Parser

from src.graph import paths

FREE_FUNCTIONS = {"free", "kfree", "kvfree", "vfree", "g_free", "xfree", "av_free", "av_freep", "OPENSSL_free", "CRYPTO_free"}
ALLOC_FUNCTIONS = {"malloc", "calloc", "realloc", "strdup", "strndup", "kmalloc", "kzalloc", "kcalloc", "g_malloc", "g_malloc0",
                   "xmalloc", "xcalloc", "xrealloc", "xstrdup", "av_malloc", "OPENSSL_malloc", "alloca"}
FREE_AND_RESET = {"FREE_AND_NULL", "free_and_null", "SAFE_FREE", "g_clear_pointer"}  # free the argument and set it to NULL
NORETURN_FUNCTIONS = {"exit", "_exit", "abort", "quick_exit", "die", "die_errno", "BUG", "usage", "panic", "longjmp", "pthread_exit"}
ALLOC_MACRO = re.compile(r"^[A-Z][A-Z0-9_]*ALLOC[A-Z0-9_]*$")  # CALLOC_ARRAY(p, n), FLEX_ALLOC_STR(p, ...): assign their first argument
ITERATION_MACRO = re.compile(r"for_?each", re.IGNORECASE)  # kh_foreach_value(h, v, free(v)), hashmap_for_each_entry(m, it, e, f)
ALWAYS_TRUE = {"1", "true", "TRUE"}
MAX_SUMMARY_ROUNDS = 6

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
        return _text(node)
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
    def event(self, kind, var, node):
        eid = self.x.next_id()
        row = node.start_point[0]
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
        value = _strip(value)
        return value is not None and value.type == "call_expression" and _called_name(value) in ALLOC_FUNCTIONS

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
        if args and (any(a.type == "compound_statement" for a in args) or (name and ITERATION_MACRO.search(name))):
            self.iteration_macro(args)
            return
        for arg in args:
            self.expr(arg)
        if name in FREE_FUNCTIONS or name in FREE_AND_RESET:
            if args and path_of(args[0]):
                self.event("free", path_of(args[0]), n)
                if name in FREE_AND_RESET:
                    self.event("reset", path_of(args[0]), n)
            return
        if name in ALLOC_FUNCTIONS:
            if name in ("realloc", "xrealloc") and args:
                self.use(path_of(args[0]), n)
            return
        if name and ALLOC_MACRO.match(name) and args and path_of(args[0]):
            self.event("alloc", path_of(args[0]), n)
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
        for index, arg in enumerate(args):  # `&p`: the callee may free, use or fill in p (decided when the callee is known)
            if arg.type == "pointer_expression" and arg.children and arg.children[0].type == "&":
                target = path_of(arg.child_by_field_name("argument"))
                if not target:
                    continue
                if name is None:
                    self.reset(target, arg)
                else:
                    eid = self.event("call", target, arg)
                    self.x.call_args.append((eid, name, index, target, 1))
        if name in NORETURN_FUNCTIONS:
            self.frontier = set()

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

    def s_compound_statement(self, n):
        self.scopes.append([])
        for child in n.named_children:
            self.stmt(child)
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
        return not (condition is not None and _text(_strip(condition) or condition) in ALWAYS_TRUE)

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
        builder.stmt(body)
        count += 1
    if own:
        extractor.flush()
    return count


def resolve_calls(conn):
    """Binds call arguments to callees and turns each call event into free/use/join (see the module docstring)."""
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
    params = {}
    for func_id, idx, name in conn.execute("SELECT func_id, idx, name FROM params"):
        params.setdefault(func_id, {})[name] = idx

    def summaries():
        effects = set()
        for func_id, var, kind in conn.execute("SELECT func_id, var, kind FROM events WHERE kind IN ('free', 'use')"):
            idx = params.get(func_id, {}).get(var)
            if idx is not None:
                effects.add((func_id, idx, 0, "frees" if kind == "free" else "uses"))
        for func_id, name, kind in conn.execute("SELECT func_id, param, effect FROM deref_effects"):
            idx = params.get(func_id, {}).get(name)
            if idx is not None:
                effects.add((func_id, idx, 1, {"free": "frees", "use": "uses", "reset": "resets"}[kind]))
        return effects

    calls = conn.execute("SELECT call_event, callee_id, arg_index, addr FROM call_args").fetchall()
    for _ in range(MAX_SUMMARY_ROUNDS):
        effects = summaries()
        changed = 0
        for event_id, callee, index, addr in calls:
            if callee is not None and (callee, index, addr, "resets") in effects:
                kind = "reset"  # the callee assigns *param: after the call p holds another value (e.g. a pop of a list head)
            elif callee is not None and (callee, index, addr, "frees") in effects:
                kind = "free"
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


def build(files, db=":memory:"):
    """Extracts every file into one graph and resolves the calls. Files that fail to parse are skipped and returned."""
    conn = paths.connect(db)
    extractor = Extractor(conn)
    failed = []
    for f in files:
        try:
            extract_file(conn, f, extractor)
        except (OSError, ValueError) as error:
            failed.append((str(f), str(error)))
    extractor.flush()
    resolve_calls(conn)
    return conn, failed
