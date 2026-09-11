# reachable

> CVE triage by call-graph reachability, with a three-state verdict that never silently says 'safe'.

`COMPACT` · **Cybersecurity** · Advanced · ~6 days · Services with large dependency trees

**Primary language:** Python
**Tags:** `vulnerability-management`, `static-analysis`, `call-graph`, `osv`, `sarif`, `triage`

---

## The problem

A scanner reports 340 CVEs in your dependencies. Most sit in code paths your application never executes. Engineers spend weeks upgrading libraries to fix vulnerabilities that were never exploitable, and the three that genuinely are get exactly the same priority as the rest - which is how the real one gets missed.

## ⭐ The differentiator

Performs **static call-graph reachability from application entry points to the specific vulnerable function** named in the advisory, filtering out CVEs in unreachable code. This is a different and complementary axis to exploit-probability scoring. Crucially it reports reachability **confidence honestly**, degrading to 'assume reachable' for dynamic dispatch rather than emitting a confident false negative - the failure mode that makes naive reachability analysis actively dangerous.

This is the sentence to lead with when someone asks you to walk through the
project. Everything else in this repo exists to make it true and to prove it.

## Data

The **OSV.dev** advisory database (free, cacheable offline) including function-level affected-symbol data, plus a fixture corpus of real open-source applications with **manually verified reachability ground truth for around 60 CVEs**.

> No paid API key is required to run or demo this project. Where a paid
> service would add value it is wired as an optional enhancement behind an
> interface with an offline mock as the default implementation.

## Stack

- Python
- `ast` plus Jedi for call-graph construction
- OSV API with an offline cache
- Typer CLI, SARIF output
- pytest

## Core capabilities

- Call-graph construction from declared entry points, conservative under dynamic dispatch
- Advisory-to-symbol resolution, falling back to package-level when symbol data is absent
- Three-state verdict: reachable / not-reachable / indeterminate - never a silent 'safe'
- Reachability path output showing the exact call chain, for triage
- SARIF output and a CI gate with a configurable policy

## Repository layout

```
src/callgraph/
src/advisories/
src/verdict/
fixtures/
test/ground_truth/
```

## Build plan

1. Establish the ground-truth corpus first. Sixty hand-verified CVEs is a week of unglamorous work and it is what makes the tool credible.
2. Call graph, deliberately conservative. Every shortcut here becomes a false negative.
3. Verdict logic with the indeterminate state - resist the temptation to collapse it to two states.
4. SARIF + CI gate last.

## Testing strategy

Against 60 manually-verified CVEs, assert **zero false negatives** - the tool must never mark a genuinely reachable CVE as unreachable - and report the false-positive rate honestly as a number in the README. A reachability tool optimised for a small findings list is a tool that will eventually hide a real vulnerability.

Tests assert **correctness**, not merely that the code runs. A green suite on
this repo is a claim about behaviour under adversarial conditions; treat any
test that would pass against a deliberately broken implementation as a bug in
the test.

## Quality & safety layer

The three-state verdict is the safety mechanism. Any construct the analyser cannot resolve - dynamic dispatch, reflection, dynamic import - resolves to indeterminate and is reported, never suppressed.

## Measurable outcome

> 340 raw findings reduce to 11 reachable and 24 indeterminate, each with a call chain, under a stated and tested zero-false-negative guarantee.

State it in these terms — business units, not technical ones — in your CV
bullet and in the first thirty seconds of describing the project.

## Interview questions this project answers

- **How do you prioritise 340 CVEs?**
- **What breaks static call-graph analysis in Python?**
- **Why is a false negative worse than a false positive here?**

## What this deliberately is *not*

- Not a scanner. It consumes advisories and your source; something else finds the dependencies.
- Not a replacement for patching - it is a sequencing tool.


## Run it now

```bash
python -m unittest discover -s tests -v   # the suite
python -m src.demo                        # the 60-second artefact
```

Requires Python 3.11+. The runnable core uses **only the standard
library** (including `sqlite3`), so there is nothing to install.

## Getting started

```bash
git clone <your-fork-url> reachable
cd reachable
pip install -e .
reachable scan --entry src/main.py --lockfile poetry.lock
reachable scan --format sarif > results.sarif
pytest test/ground_truth        # zero false negatives
```

Docker is supported but optional — every path above works on a plain
Windows/macOS/Linux laptop without a cloud account.

## Definition of done

- [ ] The differentiator above is implemented, and a test proves it
- [ ] The measurable outcome is produced by a command anyone can run
- [ ] `README` explains the one decision a generic version gets wrong
- [ ] CI runs the full suite on every push and is green on `main`
- [ ] A recruiter can see the headline artefact in under 60 seconds

## Licence

MIT — see [LICENSE](LICENSE).
