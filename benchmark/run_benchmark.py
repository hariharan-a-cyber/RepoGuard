#!/usr/bin/env python3
"""
RepoGuard detection benchmark — combined-engine edition.

Runs the REAL detection layers that work without network/external tools:
  - RuleEngine        (regex rules, all languages)
  - scan_secrets      (secret detection with test-file suppression)
  - TaintService      (source->sink taint for JS/Go/C#)

Reports precision / recall / F1 overall and per category, and names every
missed detection and false alarm so gaps are actionable.

  TP: a vulnerable file triggers ANY finding from the expected category
  FN: a vulnerable file triggers nothing for its category (missed)
  FP: a safe file triggers any finding (false alarm)

Usage:  python benchmark/run_benchmark.py
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.services.rule_engine import RuleEngine          # noqa: E402
from backend.services.secret_scanner import scan_secrets      # noqa: E402
from backend.services.taint_service import TaintService       # noqa: E402

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
LABELS = json.loads((HERE / "labels.json").read_text())

# Map every engine finding onto a normalized category token so ground-truth
# labels can be category-based rather than tied to one rule_id.
RULE_TO_CATEGORY = {
    "regex.sql-injection": "sql_injection",
    "regex.command-injection": "command_injection",
    "regex.eval-usage": "code_injection",
    "node.eval_usage": "code_injection",
    "python.exec_usage": "code_injection",
    "node.sql_injection": "sql_injection",
    "python.sql_injection": "sql_injection",
    "regex.hardcoded-secret": "hardcoded_secret",
    "regex.credential-url": "credential_url",
    "regex.weak-random": "weak_random",
    "regex.unsafe-yaml-load": "unsafe_deserialization",
    "regex.unsafe-pickle-load": "unsafe_deserialization",
    "regex.ssti": "ssti",
    "regex.open-redirect": "open_redirect",
    "regex.insecure-auth": "insecure_auth",
    "regex.jwt-no-expiry": "jwt_no_expiry",
    "regex.insecure-cors": "insecure_cors",
    "regex.path-traversal": "path_traversal",
    "regex.nosql-injection": "nosql_injection",
}


def categories_for_file(engine, taint, repo_dir, rel_path) -> set[str]:
    """Run all standalone layers against ONE file (in an isolated dir) and
    return the set of normalized vulnerability categories detected."""
    cats: set[str] = set()

    # 1. rule engine (regex)
    rule_result = engine.scan_repository(repo_dir)
    for m in rule_result.matches:
        if m.file_path == rel_path:
            cats.add(RULE_TO_CATEGORY.get(m.rule_id, m.rule_id))

    # 2. secret scanner
    for s in scan_secrets(repo_dir):
        sp = str(s.get("file") or s.get("file_path") or "").replace("\\", "/")
        if sp.endswith(rel_path) or rel_path.endswith(sp) or sp == rel_path:
            cats.add("hardcoded_secret")

    # 3. taint (JS/Go/C#) -> any UNSANITIZED flow is an injection-class finding.
    # The real scanner drops sanitized flows when selecting issues to report.
    for flow in taint.scan_repository(repo_dir):
        if getattr(flow, "sanitized", False):
            continue
        fp = str(getattr(flow, "file_path", "")).replace("\\", "/")
        if fp == rel_path or fp.endswith(rel_path):
            cats.add(_taint_category(flow))

    return cats


def _taint_category(flow) -> str:
    sink = str(getattr(flow, "sink_symbol", "")).lower()
    if "query" in sink or "sql" in sink or "execute" in sink:
        return "sql_injection"
    if "exec" in sink or "spawn" in sink or "system" in sink or "popen" in sink:
        return "command_injection"
    if "redirect" in sink:
        return "open_redirect"
    if "eval" in sink:
        return "code_injection"
    return "taint_flow"


def run_one(engine, taint, base_dir, fname) -> set[str]:
    """Isolate a single corpus file in its own temp dir so cross-file noise
    doesn't pollute the per-file result."""
    import shutil, tempfile
    tmp = Path(tempfile.mkdtemp(prefix="bench_"))
    try:
        src = base_dir / fname
        dst = tmp / fname
        dst.write_text(src.read_text(encoding="utf-8", errors="replace"))
        return categories_for_file(engine, taint, tmp, fname)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    engine = RuleEngine()
    engine.load_external_rules()
    taint = TaintService()

    tp = fp = fn = 0
    per_cat = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    fp_detail, fn_detail = [], []

    for fname, expected in LABELS["vulnerable"].items():
        cats = run_one(engine, taint, CORPUS / "vulnerable", fname)
        # expected is a list of category tokens (normalized)
        for want in expected:
            if want in cats:
                tp += 1; per_cat[want]["tp"] += 1
            else:
                fn += 1; per_cat[want]["fn"] += 1
                fn_detail.append((fname, want, sorted(cats)))

    for fname in LABELS["safe"]:
        cats = run_one(engine, taint, CORPUS / "safe", fname)
        for got in cats:
            fp += 1; per_cat[got]["fp"] += 1
            fp_detail.append((fname, got))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("=" * 64)
    print("REPOGUARD DETECTION BENCHMARK  (rule + secret + taint)")
    print("=" * 64)
    print(f"Corpus: {len(LABELS['vulnerable'])} vulnerable, {len(LABELS['safe'])} safe files")
    print("-" * 64)
    print(f"True Positives  (caught real vulns):  {tp}")
    print(f"False Negatives (missed real vulns):  {fn}")
    print(f"False Positives (flagged safe code):  {fp}")
    print("-" * 64)
    print(f"Precision: {precision:.1%}")
    print(f"Recall:    {recall:.1%}")
    print(f"F1 score:  {f1:.1%}")
    print("=" * 64)

    print("\nPER-CATEGORY")
    print(f"{'category':<26}{'TP':>4}{'FN':>4}{'FP':>4}{'recall':>8}")
    for cat in sorted(per_cat):
        s = per_cat[cat]
        rec = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 0.0
        print(f"{cat:<26}{s['tp']:>4}{s['fn']:>4}{s['fp']:>4}{rec:>7.0%}")

    if fn_detail:
        print("\nMISSED (false negatives):")
        for fname, cat, got in fn_detail:
            print(f"  - {fname}: missed [{cat}]  (engine saw: {got or 'nothing'})")
    if fp_detail:
        print("\nFALSE ALARMS (false positives):")
        for fname, cat in fp_detail:
            print(f"  - {fname}: wrongly flagged [{cat}]")

    result = {"precision": round(precision,4), "recall": round(recall,4), "f1": round(f1,4),
              "tp": tp, "fn": fn, "fp": fp,
              "false_negatives": [[f,c] for f,c,_ in fn_detail],
              "false_positives": fp_detail}
    (HERE / "last_result.json").write_text(json.dumps(result, indent=2))
    print(f"\nResult -> benchmark/last_result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
