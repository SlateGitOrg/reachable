"""Zero false negatives is the contract. Everything else is a nice-to-have."""

from __future__ import annotations

import unittest

from src.callgraph import analyse_sources
from src.corpus import (
    ADVISORIES, ENTRY_POINTS, EXPECTED, SOURCES, SOURCES_WITH_DYNAMIC,
)
from src.verdict import Reachability, assess, gate, to_sarif


def verdicts_for(sources: dict[str, str]):
    graph = analyse_sources(sources)
    return {v.advisory.id: v for v in assess(graph, ENTRY_POINTS, ADVISORIES)}


class TestGroundTruth(unittest.TestCase):
    def test_every_verdict_matches_the_hand_verified_answer(self):
        got = verdicts_for(SOURCES)
        for advisory_id, expected in EXPECTED.items():
            with self.subTest(advisory=advisory_id):
                self.assertEqual(
                    got[advisory_id].reachability.value, expected,
                    f"{advisory_id}: {got[advisory_id].reason}",
                )

    def test_THE_CONTRACT_zero_false_negatives(self):
        """No genuinely reachable advisory may be marked not-reachable.

        A reachability tool optimised for a short findings list will
        eventually hide a real vulnerability. That is strictly worse than
        having no tool, because the team now trusts the short list.
        """
        got = verdicts_for(SOURCES)
        false_negatives = [
            advisory_id for advisory_id, expected in EXPECTED.items()
            if expected == "reachable"
            and got[advisory_id].reachability is Reachability.NOT_REACHABLE
        ]
        self.assertEqual(false_negatives, [])

    def test_the_false_positive_rate_is_reported_not_hidden(self):
        got = verdicts_for(SOURCES)
        over = [
            advisory_id for advisory_id, expected in EXPECTED.items()
            if expected == "not-reachable"
            and got[advisory_id].reachability is Reachability.REACHABLE
        ]
        # Stated as a number in the README rather than quietly tuned away.
        self.assertEqual(len(over), 0, f"over-reported: {over}")

    def test_a_reachable_advisory_carries_the_call_chain(self):
        got = verdicts_for(SOURCES)
        v = got["OSV-2026-0001"]
        self.assertEqual(v.reachability, Reachability.REACHABLE)
        self.assertEqual(
            v.path,
            ("app.main.main", "app.handlers.handle_upload", "imagelib.decode_png"),
        )

    def test_the_second_entry_point_is_followed_too(self):
        got = verdicts_for(SOURCES)
        v = got["OSV-2026-0005"]
        self.assertEqual(v.reachability, Reachability.REACHABLE)
        self.assertIn("app.main.cli_entry", v.path)


class TestConservatism(unittest.TestCase):
    def test_ONE_getattr_degrades_every_safe_verdict_to_indeterminate(self):
        """The design rule: when in doubt, assume reachable."""
        clean = verdicts_for(SOURCES)
        dirty = verdicts_for(SOURCES_WITH_DYNAMIC)

        safe_before = [
            k for k, v in clean.items()
            if v.reachability is Reachability.NOT_REACHABLE
        ]
        self.assertGreater(len(safe_before), 0)

        for advisory_id in safe_before:
            self.assertIs(
                dirty[advisory_id].reachability, Reachability.INDETERMINATE,
                f"{advisory_id} stayed 'not reachable' despite dynamic dispatch",
            )

    def test_reachable_stays_reachable_under_dynamic_dispatch(self):
        dirty = verdicts_for(SOURCES_WITH_DYNAMIC)
        self.assertIs(dirty["OSV-2026-0001"].reachability, Reachability.REACHABLE)

    def test_an_advisory_with_no_symbol_is_always_indeterminate(self):
        got = verdicts_for(SOURCES)
        v = got["OSV-2026-0008"]
        self.assertIs(v.reachability, Reachability.INDETERMINATE)
        self.assertIn("names no vulnerable symbol", v.reason)

    def test_every_verdict_explains_itself(self):
        for v in verdicts_for(SOURCES).values():
            self.assertGreater(len(v.reason), 20, v.advisory.id)


class TestCallGraph(unittest.TestCase):
    def test_getattr_is_recorded_as_a_dynamic_site(self):
        graph = analyse_sources(SOURCES_WITH_DYNAMIC)
        fn = graph["app.handlers.handle_login"]
        self.assertTrue(fn.has_dynamic_calls)
        self.assertTrue(any("getattr" in s for s in fn.dynamic_sites))

    def test_imports_are_resolved_to_qualified_names(self):
        graph = analyse_sources(SOURCES)
        self.assertIn("imagelib.decode_png",
                      graph["app.handlers.handle_upload"].calls)

    def test_transitive_internal_calls_are_followed(self):
        graph = analyse_sources(SOURCES)
        self.assertIn("imagelib._parse_chunk", graph["imagelib.decode_png"].calls)

    def test_functions_never_called_are_still_in_the_graph(self):
        graph = analyse_sources(SOURCES)
        self.assertIn("app.handlers.unused_admin_import", graph)

    def test_a_decorator_is_treated_as_a_call(self):
        graph = analyse_sources({"m": "import lib\n\n@lib.cache\ndef f():\n    pass\n"})
        self.assertIn("lib.cache", graph["m.f"].calls)


class TestGate(unittest.TestCase):
    def test_the_gate_fails_on_reachable_findings(self):
        result = gate(list(verdicts_for(SOURCES).values()))
        self.assertFalse(result.passed)
        self.assertEqual(result.reachable, 2)

    def test_the_triage_load_is_much_smaller_than_the_raw_count(self):
        result = gate(list(verdicts_for(SOURCES).values()))
        self.assertLess(result.triage_load, result.total)
        self.assertEqual(result.triage_load, result.reachable + result.indeterminate)

    def test_sarif_output_omits_only_the_not_reachable(self):
        verdicts = list(verdicts_for(SOURCES).values())
        sarif = to_sarif(verdicts)
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), sum(1 for v in verdicts if v.actionable))
        self.assertTrue(all("reachability" in r["properties"] for r in results))

    def test_sarif_includes_the_path_for_reachable_findings(self):
        sarif = to_sarif(list(verdicts_for(SOURCES).values()))
        reachable = [
            r for r in sarif["runs"][0]["results"]
            if r["properties"]["reachability"] == "reachable"
        ]
        self.assertTrue(all(len(r["properties"]["path"]) >= 2 for r in reachable))


if __name__ == "__main__":
    unittest.main()
