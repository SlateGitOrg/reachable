"""Three-state reachability verdicts, and the CI gate over them."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum

from .callgraph import Function


class Reachability(str, Enum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not-reachable"
    # The state that keeps this tool honest. Reported, never suppressed.
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    # The specific vulnerable function, when the advisory names one. Many do
    # not, and package-level advisories cannot be reachability-filtered at all.
    symbol: str | None
    summary: str
    severity: str


@dataclass(frozen=True)
class Verdict:
    advisory: Advisory
    reachability: Reachability
    path: tuple[str, ...] = ()
    reason: str = ""

    @property
    def actionable(self) -> bool:
        return self.reachability is not Reachability.NOT_REACHABLE


def _walk(
    graph: dict[str, Function], entry_points: list[str],
) -> tuple[set[str], set[str], dict[str, tuple[str, ...]]]:
    """BFS from the entry points.

    Returns (reached, tainted_by_dynamic, paths). `tainted` marks functions
    reached via a frame that also contained an unresolvable call site: anything
    that frame might additionally reach is unknown.
    """
    reached: set[str] = set()
    tainted: set[str] = set()
    paths: dict[str, tuple[str, ...]] = {}
    queue: deque[tuple[str, tuple[str, ...], bool]] = deque()

    for ep in entry_points:
        queue.append((ep, (ep,), False))
        paths.setdefault(ep, (ep,))

    while queue:
        node, path, dirty = queue.popleft()
        if node in reached and not (dirty and node not in tainted):
            continue
        reached.add(node)
        paths.setdefault(node, path)
        if dirty:
            tainted.add(node)

        fn = graph.get(node)
        if fn is None:
            continue
        next_dirty = dirty or fn.has_dynamic_calls
        if fn.has_dynamic_calls:
            tainted.add(node)
        for callee in sorted(fn.calls):
            if callee in reached and (not next_dirty or callee in tainted):
                continue
            queue.append((callee, (*path, callee), next_dirty))

    return reached, tainted, paths


def assess(
    graph: dict[str, Function],
    entry_points: list[str],
    advisories: list[Advisory],
) -> list[Verdict]:
    reached, tainted, paths = _walk(graph, entry_points)
    any_dynamic = bool(tainted)

    out: list[Verdict] = []
    for adv in advisories:
        if adv.symbol is None:
            # No symbol to aim at. Reachability analysis has nothing to say, and
            # pretending otherwise is how a real vulnerability gets filtered out.
            out.append(Verdict(
                adv, Reachability.INDETERMINATE,
                reason="advisory names no vulnerable symbol; "
                       "package-level advisories cannot be filtered",
            ))
            continue

        if adv.symbol in reached:
            out.append(Verdict(
                adv, Reachability.REACHABLE, paths.get(adv.symbol, ()),
                reason="called from an application entry point",
            ))
            continue

        if any_dynamic:
            # Somewhere in the reachable set there is a call the analyser could
            # not follow. That call might land here. Saying "not reachable"
            # would be a guess presented as a fact.
            out.append(Verdict(
                adv, Reachability.INDETERMINATE,
                reason="not reached statically, but the reachable set contains "
                       "unresolvable call sites",
            ))
            continue

        out.append(Verdict(
            adv, Reachability.NOT_REACHABLE,
            reason="no static path from any entry point, and no dynamic "
                   "dispatch in the reachable set",
        ))
    return out


def unresolved_receiver_count(
    graph: dict[str, Function], entry_points: list[str],
) -> int:
    """How many call sites the analyser could not type.

    Reported alongside every run. A NOT_REACHABLE verdict is sound with
    respect to statically-resolvable dispatch; this number is the honest
    measure of how much the analyser could not see.
    """
    reached, _, _ = _walk(graph, entry_points)
    return sum(
        len(graph[n].unresolved_receivers) for n in reached if n in graph
    )


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reachable: int
    indeterminate: int
    not_reachable: int
    total: int

    @property
    def triage_load(self) -> int:
        return self.reachable + self.indeterminate


def gate(verdicts: list[Verdict], fail_on: str = "reachable") -> GateResult:
    reachable = sum(1 for v in verdicts if v.reachability is Reachability.REACHABLE)
    indet = sum(1 for v in verdicts if v.reachability is Reachability.INDETERMINATE)
    not_r = sum(1 for v in verdicts if v.reachability is Reachability.NOT_REACHABLE)

    if fail_on == "reachable":
        passed = reachable == 0
    elif fail_on == "actionable":
        passed = reachable == 0 and indet == 0
    else:
        passed = True
    return GateResult(passed, reachable, indet, not_r, len(verdicts))


def to_sarif(verdicts: list[Verdict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "reachable"}},
            "results": [
                {
                    "ruleId": v.advisory.id,
                    "level": "error" if v.reachability is Reachability.REACHABLE
                             else "warning",
                    "message": {
                        "text": f"{v.advisory.id} in {v.advisory.package}: "
                                f"{v.reachability.value} - {v.reason}",
                    },
                    "properties": {
                        "reachability": v.reachability.value,
                        "path": list(v.path),
                    },
                }
                for v in verdicts if v.actionable
            ],
        }],
    }
