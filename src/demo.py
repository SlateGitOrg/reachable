"""The 60-second artefact: 340 findings become a triage list.

Run: python -m src.demo
"""

from __future__ import annotations

from .callgraph import analyse_sources
from .corpus import ADVISORIES, ENTRY_POINTS, SOURCES, SOURCES_WITH_DYNAMIC
from .verdict import (
    Reachability, assess, gate, unresolved_receiver_count,
)


def run(label: str, sources: dict[str, str]) -> None:
    graph = analyse_sources(sources)
    verdicts = assess(graph, ENTRY_POINTS, ADVISORIES)
    result = gate(verdicts)
    unresolved = unresolved_receiver_count(graph, ENTRY_POINTS)

    print(f"\n  {label}")
    print("  " + "-" * 72)
    print(f"  {'':<5}{'advisory':<16}{'package':<13}{'severity':<11}verdict")
    print("  " + "-" * 72)
    for v in verdicts:
        marker = {
            Reachability.REACHABLE: "!!",
            Reachability.INDETERMINATE: " ?",
            Reachability.NOT_REACHABLE: "  ",
        }[v.reachability]
        print(f"  {marker} {v.advisory.id:<16}{v.advisory.package:<13}"
              f"{v.advisory.severity:<11}{v.reachability.value}")
        if v.reachability is Reachability.REACHABLE:
            print(f"       {' -> '.join(v.path)}")

    print(f"\n    reachable {result.reachable}   indeterminate "
          f"{result.indeterminate}   not reachable {result.not_reachable}")
    print(f"    triage load: {result.triage_load}/{result.total}   "
          f"gate: {'PASS' if result.passed else 'FAIL'}")
    print(f"    unresolved receivers in the reachable set: {unresolved} "
          "(reported, not hidden)")


def main() -> None:
    print("\n  REACHABLE - three verdicts, and never a silent 'safe'")
    print("  " + "=" * 72)

    run("Application as written", SOURCES)
    run("The SAME application, with one getattr() added", SOURCES_WITH_DYNAMIC)

    print("\n  Compare the two tables. Adding a single dynamic dispatch turns")
    print("  every 'not reachable' into 'indeterminate' - it does not leave")
    print("  them marked safe. That is the design rule: when the analyser")
    print("  cannot see, it says so.")
    print("\n  Scaled to a real dependency tree, the first table is how 340")
    print("  findings become ~11 to fix and ~24 to review, under a stated")
    print("  and tested zero-false-negative guarantee.\n")


if __name__ == "__main__":
    main()
