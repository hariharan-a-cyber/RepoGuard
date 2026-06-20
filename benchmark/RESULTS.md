# Benchmark Results — Detection Engine Improvement Log

Measured with `python benchmark/run_benchmark.py` against the real engine
(RuleEngine + secret scanner + taint service), no network/external tools.

## Progression

| Round | Corpus (vuln+safe) | Precision | Recall | F1 | What changed |
|-------|--------------------|-----------|--------|-----|--------------|
| Baseline (regex only) | 12 + 13 | 92.3% | 100% | 96.0% | initial, easy corpus |
| Baseline (harder) | 15 + 16 | 80.0% | 80.0% | 80.0% | added adversarial cases |
| Combined engine | 15 + 16 | 81.2% | 86.7% | 83.9% | run rule+secret+taint together |
| Round 1 fixes | 15 + 16 | 100% | 93.3% | 96.6% | os.popen, placeholder secrets, weak-random context, allowlist redirect |
| Round 2 (held-out) | 19 + 20 | 94.4% | 89.5% | 91.9% | unseen cases exposed Stripe-key miss + .get() FP |
| Round 2 fixes | 19 + 20 | 100% | 94.7% | 97.3% | Stripe/Slack/Google/PEM patterns, .get() sanitizer |
| Round 3 (held-out) | 23 + 24 | 90.9% | 87.0% | 88.9% | unseen cases exposed NoSQL + path-traversal gaps |
| **Round 3 fixes (final)** | **23 + 24** | **95.7%** | **95.7%** | **95.7%** | path-traversal + NoSQL rules, log-string suppression |

## What the engine now detects (categories with measured coverage)

code injection, command injection (incl. os.popen), credential-in-URL,
hardcoded secrets (incl. Stripe/Slack/Google/AWS/GitHub/PEM), insecure auth,
JWT-without-expiry, NoSQL injection, open redirect (allowlist-aware),
path traversal, SQL injection, SSTI, unsafe deserialization, weak randomness.

## Known remaining limitations (honest)

1. **Cross-variable SQL injection** (`base = "SELECT..."; full = base + x`) is
   missed by the regex layer. This is a data-flow problem; the taint service
   handles JS/Go/C# but not Python. Correct fix is Python taint support, not a
   regex hack.
2. **`random.random()` for retry backoff** can produce a LOW-severity false
   positive when the only context (a "backoff" comment) is on another line.
   Accepted rather than risk suppressing real weak-RNG in security code.

## Critical caveat

This corpus is hand-authored. The samples are realistic but not real scraped
production code, and the benchmark author also wrote the fixes — single-author
benchmarks carry inherent bias. The ~96% F1 here is a measure of progress on a
controlled corpus, **not** a claim of 96% accuracy on arbitrary real-world repos.
To validate externally: drop real labeled datasets (OWASP Benchmark, known-CVE
project snapshots) into `corpus/` and re-run.
