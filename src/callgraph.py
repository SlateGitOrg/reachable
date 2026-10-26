"""Call-graph construction that is honest about what it cannot resolve.

Scanners report many advisories, and most sit in code paths the application
never executes. Engineers spend weeks upgrading libraries to fix
vulnerabilities that were never exploitable, while the few that genuinely are
get the same priority as the rest.

Reachability analysis fixes that, and it introduces a far worse failure mode if
done carelessly: a confident "not reachable" on something that IS reachable
means the real vulnerability gets closed as noise. Python makes this easy to
get wrong, because `getattr`, dynamic imports, decorators and duck typing all
defeat static resolution.

So this analyser has THREE outcomes, not two. Anything it cannot resolve is
INDETERMINATE and is reported, never silently dropped. The design rule
throughout: when in doubt, assume reachable.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    RESOLVED = "resolved"
    # A construct the analyser cannot follow. Everything downstream of it is
    # unknown, not safe.
    DYNAMIC = "dynamic"


@dataclass
class Function:
    qualname: str
    module: str
    calls: set[str] = field(default_factory=set)
    #: Genuinely UNBOUNDED dispatch - getattr, eval, exec, dynamic import.
    #: The callee could be anything, so anything downstream is unknown and
    #: these taint the whole reachable set.
    dynamic_sites: list[str] = field(default_factory=list)
    #: A method call on a value the analyser cannot type, e.g.
    #: `hashlib.sha256(x).hexdigest()`. These are bounded - the receiver is a
    #: concrete object - but this analyser has no type inference to follow
    #: them. Counted and reported, deliberately NOT tainting.
    #:
    #: Treating these as unbounded is the obvious "safe" choice and it is
    #: wrong: real code is full of chained method calls, so every verdict
    #: becomes INDETERMINATE and the tool stops distinguishing anything. The
    #: limitation is reported as a number instead of being hidden inside a
    #: blanket verdict.
    unresolved_receivers: list[str] = field(default_factory=list)

    @property
    def has_dynamic_calls(self) -> bool:
        return bool(self.dynamic_sites)


DYNAMIC_BUILTINS = {
    "getattr", "eval", "exec", "__import__", "importlib", "globals", "locals",
    "vars", "compile",
}


class ModuleAnalyser(ast.NodeVisitor):
    """Extract functions and their call edges from one module."""

    def __init__(self, module: str) -> None:
        self.module = module
        self.functions: dict[str, Function] = {}
        self.imports: dict[str, str] = {}  # local name -> qualified name
        self._stack: list[str] = []

    # -- imports ------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                # `import a.b as x` binds x directly to a.b
                self.imports[alias.asname] = alias.name
            else:
                # `import a.b` binds only the TOP-LEVEL name `a`, and the rest
                # of the path is resolved by attribute access at the call site.
                # Binding `a` to "a.b" instead corrupts every other `a.*` call
                # in the module - with two such imports, the second silently
                # rewrites the first one's call targets.
                top = alias.name.split(".")[0]
                self.imports[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = f"{mod}.{alias.name}" if mod else alias.name
        self.generic_visit(node)

    # -- functions ----------------------------------------------------------

    def _enter(self, name: str) -> str:
        qual = ".".join([self.module, *self._stack, name])
        self.functions.setdefault(qual, Function(qual, self.module))
        return qual

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        qual = self._enter(node.name)
        self._stack.append(node.name)
        # A decorator is itself a call, and decorators routinely wrap the
        # function in something the analyser cannot follow.
        for dec in node.decorator_list:
            target = self._resolve(dec)
            if target:
                self.functions[qual].calls.add(target)
            else:
                self.functions[qual].dynamic_sites.append(
                    f"decorator at line {node.lineno}")
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    # -- calls --------------------------------------------------------------

    def _current(self) -> Function | None:
        if not self._stack:
            return None
        qual = ".".join([self.module, *self._stack])
        return self.functions.get(qual)

    def _resolve(self, node: ast.expr) -> str | None:
        """Best-effort resolution of a call target to a qualified name."""
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, f"{self.module}.{node.id}")
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            cur: ast.expr = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                base = self.imports.get(cur.id, cur.id)
                return ".".join([base, *reversed(parts)])
            return None
        return None

    def visit_Call(self, node: ast.Call) -> None:
        fn = self._current()
        if fn is not None:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            attr_base = (
                func.value.id
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                else None
            )
            if name in DYNAMIC_BUILTINS or attr_base in DYNAMIC_BUILTINS:
                # Everything reachable through here is unknown.
                fn.dynamic_sites.append(f"{name or attr_base} at line {node.lineno}")
            else:
                target = self._resolve(func)
                if target:
                    fn.calls.add(target)
                else:
                    fn.unresolved_receivers.append(
                        f"method call on an untyped receiver at line {node.lineno}")
        self.generic_visit(node)


def analyse_sources(sources: dict[str, str]) -> dict[str, Function]:
    """sources: {module_name: python source}."""
    graph: dict[str, Function] = {}
    for module, src in sources.items():
        analyser = ModuleAnalyser(module)
        analyser.visit(ast.parse(src))
        graph.update(analyser.functions)
    return graph
