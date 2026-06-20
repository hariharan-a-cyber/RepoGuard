# RepoGuard Detection Benchmark

This harness measures the **actual** precision and recall of RepoGuard's rule engine
against a labeled corpus. It runs the real `RuleEngine` (no network, no external
tools needed) and reports a number you can track over time as you improve detection.

## Why this exists

Before this, RepoGuard's detection accuracy was unmeasured — nobody could state
its precision or recall. This harness replaces "it seems good" with a real number
and, more importantly, names the **specific** files where the engine fails so you
know exactly what to fix.

## How to run

```bash
# from the project root, with the venv active
python benchmark/run_benchmark.py
```

It prints overall precision/recall/F1, a per-rule breakdown, and the exact list of
missed detections and false alarms. A machine-readable copy is written to
`benchmark/last_result.json` so you can track the trend across changes.

## Structure

```
benchmark/
  corpus/
    vulnerable/   # files with planted vulnerabilities (should be detected)
    safe/         # safe code, incl. look-alike traps (should NOT be flagged)
  labels.json     # ground truth: which rule each vulnerable file should fire
  run_benchmark.py
  last_result.json
```

## What the metrics mean

- **Recall** — of the real vulnerabilities, how many did the engine catch?
  Low recall = it misses real bugs.
- **Precision** — of the alarms it raised, how many were real?
  Low precision = it cries wolf and developers stop trusting it.
- **F1** — the harmonic mean; a single balanced score.

## Current baseline (as measured)

Run against 15 vulnerable + 16 safe files:

| Metric | Score |
|--------|-------|
| Precision | 80.0% |
| Recall | 80.0% |
| F1 | 80.0% |

### Known gaps the benchmark identified

**Missed detections (recall):**
- SQL injection built by concatenating through an intermediate variable
- `os.popen(...)` command sink (not in the command-injection pattern)
- Python `eval(...)` (no core rule)

**False alarms (precision):**
- Allowlisted redirect still flagged as open redirect
- `Math.random()` for cosmetic (non-security) use flagged as weak crypto
- Obvious test-fixture secret flagged as a real hardcoded secret

## How to improve the score

1. Run the benchmark to see current standing.
2. Fix one named failure (e.g. add an `os.popen` alternative to the command rule).
3. Re-run the benchmark and confirm the number went up and nothing else regressed.
4. Repeat. Every change is now measurable instead of guessed.

## Important caveat

This corpus is small and the samples are hand-written. Real-world repositories are
messier, so production precision/recall will differ. The value here is the
**repeatable measurement loop** and the per-case failure list — not the headline
number in isolation. To make the number credible to outsiders, extend the corpus
with real labeled datasets (e.g. OWASP Benchmark, known-vulnerable open-source
project snapshots) and re-run.
