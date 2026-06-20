"""
Full-pipeline benchmark: rule-engine + secret + taint + AST (production path).

Runs run_ast_scan() via the real ScannerService — the same code path the
production scanner uses — so findings pass through _finalize_issue and
_should_emit_issue exactly as they do in production.

Runs twice:
  BEFORE: regex fires on all languages (monkeypatched _is_valid_match)
  AFTER:  regex suppressed for .py; AST covers those categories

Both runs include the AST layer so this measures the true full-pipeline F1.
"""
import json, sys, shutil, tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import backend.services.rule_engine as _re_mod
from backend.services.rule_engine import RuleEngine
from backend.services.secret_scanner import scan_secrets
from backend.services.taint_service import TaintService
from backend.services.scanner_service import ScannerService

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
LABELS = json.loads((HERE / "labels.json").read_text())

# Map scanner category strings → benchmark category keys
CAT_TO_BENCH = {
    "SQL Injection": "sql_injection",
    "Command Injection": "command_injection",
    "Hardcoded Secrets": "hardcoded_secret",
    "Credential in URL": "credential_url",
    "Weak Random Generator Usage": "weak_random",
    "Unsafe YAML Deserialization": "unsafe_deserialization",
    "Unsafe Pickle Deserialization": "unsafe_deserialization",
    "Server-Side Template Injection": "ssti",
    "Open Redirect": "open_redirect",
    "Insecure Auth Logic": "insecure_auth",
    "JWT Missing Expiry": "jwt_no_expiry",
    "JWT No Expiry": "jwt_no_expiry",
    "Insecure CORS Configuration": "insecure_cors",
    "Path Traversal": "path_traversal",
    "NoSQL Injection": "nosql_injection",
    "Dynamic Code Execution (eval/exec)": "code_injection",
}

# Rule engine rule_id → benchmark category.
# Covers both built-in (regex.*) and external (node.*, python.*) rules that
# load from backend/rules/node/ and backend/rules/python/.
RULE_TO_CAT = {
    # built-in regex rules
    "regex.sql-injection": "sql_injection",
    "regex.command-injection": "command_injection",
    "regex.eval-usage": "code_injection",
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
    # external rules: backend/rules/node/
    "node.eval_usage": "code_injection",
    "node.sql_injection": "sql_injection",
    # external rules: backend/rules/python/
    "python.exec_usage": "code_injection",
    "python.sql_injection": "sql_injection",
}

PY_SUPPRESSED = {"regex.unsafe-pickle-load", "regex.unsafe-yaml-load",
                 "regex.command-injection", "regex.weak-random"}


def _taint_bench_cat(flow) -> str:
    sink = str(getattr(flow, "sink_symbol", "")).lower()
    if any(t in sink for t in ("query", "sql", "execute")):
        return "sql_injection"
    if any(t in sink for t in ("exec", "spawn", "system", "popen")):
        return "command_injection"
    if "redirect" in sink:
        return "open_redirect"
    if "eval" in sink:
        return "code_injection"
    return "taint_flow"


# ---- monkeypatch helpers -----------------------------------------------

def _make_patched_is_valid():
    """Return a version of _is_valid_match with the .py suppression block removed."""
    import re

    def _patched(rule_id, snippet, file_path):
        if RuleEngine._is_test_file(file_path):
            return False
        # .py suppression block deliberately absent here
        lowered_snip = snippet.lower()
        is_log_line = any(t in lowered_snip for t in [
            "logging.", "logger.", "log.info", "log.debug",
            "log.warn", "log.error", "print(", "console.log"])
        if is_log_line and "sql" in rule_id.lower():
            return False
        if rule_id == "regex.hardcoded-secret":
            return RuleEngine._valid_secret(snippet)
        if rule_id == "regex.sql-injection":
            lowered = snippet.lower()
            if any(t in lowered for t in [
                "logging.", "logger.", "log.info", "log.debug",
                "print(", "console.log", "# ", "-style", "example"]):
                return False
            return any(t in lowered for t in ["request", "input", "user", "query", "params", "+"])
        if rule_id == "regex.path-traversal":
            lowered = snippet.lower()
            return any(t in lowered for t in ["request", "req.", "input", "args", "params", "query", "+", "join"])
        if rule_id == "regex.nosql-injection":
            return True
        if rule_id == "regex.command-injection":
            s = snippet.lower()
            if s.strip().startswith(("import ", "from ")):
                return False
            return any(t in s for t in ["request", "input", "args", "shell=true", "+", "os.system(", "exec("])
        if rule_id == "regex.jwt-no-expiry":
            return "expiresin" not in snippet.lower()
        if rule_id == "regex.open-redirect":
            lowered = snippet.lower()
            if not any(t in lowered for t in ["next", "returnurl", "redirect", "req.", "request.", "query"]):
                return False
            if re.search(r"\[\s*(req|request)\.[^\]]+\]", snippet, re.IGNORECASE):
                return False
            if re.search(r"\.(?:get|has|includes|find|indexof)\s*\(\s*(req|request)\.", snippet, re.IGNORECASE):
                return False
            return True
        if rule_id == "regex.weak-random":
            fname = (file_path or "").lower()
            if any(t in fname for t in ("generate", "dataset", "seed", "mock", "fixture", "sample", "factory", "/data/", "/test")):
                return False
            lowered = snippet.lower()
            cosmetic = ["color", "colour", "confetti", "animation", "animate",
                "particle", "shuffle", "jitter", "delay", "css", "style",
                "pixel", "rgb", "hsl", "emoji", "sample text",
                "backoff", "retry", "sleep", "timeout", "fuzz"]
            return not any(t in lowered for t in cosmetic)
        if rule_id in {"regex.unsafe-yaml-load", "regex.unsafe-pickle-load"}:
            lowered = snippet.lower()
            return any(t in lowered for t in ["request", "input", "payload", "body", "file", "yaml.load", "pickle.load", "pickle.loads"])
        if rule_id == "regex.eval-usage":
            return any(t in snippet.lower() for t in ["request", "input", "user", "payload", "eval", "exec"])
        if rule_id == "regex.credential-url":
            return "@" in snippet and "://" in snippet
        return True
    return _patched


def _monkeypatch(fn):
    _re_mod.RuleEngine._is_valid_match = staticmethod(fn)


def _restore(original):
    _re_mod.RuleEngine._is_valid_match = staticmethod(original)


# ---- per-file runner ---------------------------------------------------

def _run_one(svc, engine, taint, base_dir, fname):
    tmp = Path(tempfile.mkdtemp(prefix="bench_"))
    try:
        src = base_dir / fname
        dst = tmp / fname
        dst.write_text(src.read_text(encoding="utf-8", errors="replace"))
        cats = set()

        # 1. Rule engine
        rule_result = engine.scan_repository(tmp)
        for m in rule_result.matches:
            if m.file_path == fname:
                cats.add(RULE_TO_CAT.get(m.rule_id, m.rule_id))

        # 2. Secret scanner
        for s in scan_secrets(tmp):
            sp = str(s.get("file") or s.get("file_path") or "").replace("\\", "/")
            if sp.endswith(fname) or fname.endswith(sp) or sp == fname:
                cats.add("hardcoded_secret")

        # 3. Taint
        for flow in taint.scan_repository(tmp):
            if getattr(flow, "sanitized", False):
                continue
            fp2 = str(getattr(flow, "file_path", "")).replace("\\", "/")
            if fp2 == fname or fp2.endswith(fname):
                cats.add(_taint_bench_cat(flow))

        # 4. AST scanner (production path through ScannerService.run_ast_scan)
        for issue in svc.run_ast_scan(tmp, strict_mode=False):
            f = str(issue.file or "").replace("\\", "/")
            if f.endswith(fname) or fname.endswith(f) or f == fname:
                bench_cat = CAT_TO_BENCH.get(issue.category)
                if bench_cat:
                    cats.add(bench_cat)

        return cats
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def score(svc, engine, taint, label=""):
    tp = fp = fn = 0
    per_cat = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    fn_detail, fp_detail = [], []

    for fname, expected in LABELS["vulnerable"].items():
        cats = _run_one(svc, engine, taint, CORPUS / "vulnerable", fname)
        for want in expected:
            if want in cats:
                tp += 1; per_cat[want]["tp"] += 1
            else:
                fn += 1; per_cat[want]["fn"] += 1
                fn_detail.append((fname, want, sorted(cats)))

    for fname in LABELS["safe"]:
        cats = _run_one(svc, engine, taint, CORPUS / "safe", fname)
        for got in cats:
            fp += 1; per_cat[got]["fp"] += 1
            fp_detail.append((fname, got))

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return dict(tp=tp, fp=fp, fn=fn, prec=prec, rec=rec, f1=f1,
                per_cat=per_cat, fn_detail=fn_detail, fp_detail=fp_detail)


def print_result(label, r):
    print()
    print("=" * 64)
    print(f"  {label}")
    print("=" * 64)
    print(f"  TP={r['tp']}  FP={r['fp']}  FN={r['fn']}")
    print(f"  Precision={r['prec']:.1%}  Recall={r['rec']:.1%}  F1={r['f1']:.1%}")
    print()
    print(f"  {'category':<26}{'TP':>4}{'FN':>4}{'FP':>4}{'recall':>8}")
    for cat in sorted(r['per_cat']):
        s = r['per_cat'][cat]
        rec = s['tp'] / (s['tp'] + s['fn']) if (s['tp'] + s['fn']) else 0.0
        print(f"  {cat:<26}{s['tp']:>4}{s['fn']:>4}{s['fp']:>4}{rec:>7.0%}")
    if r['fn_detail']:
        print()
        print("  MISSED:")
        for fname, cat, got in r['fn_detail']:
            print(f"    - {fname}: [{cat}]  (saw: {sorted(got) if got else 'nothing'})")
    if r['fp_detail']:
        print()
        print("  FALSE ALARMS (safe files triggered):")
        for fname, cat in r['fp_detail']:
            print(f"    - {fname}: [{cat}]")


if __name__ == "__main__":
    svc    = ScannerService()
    engine = svc.rule_engine
    taint  = svc.taint_service

    original = _re_mod.RuleEngine._is_valid_match
    patched  = _make_patched_is_valid()

    print("Running BEFORE (no .py suppression, full pipeline including AST)...")
    _monkeypatch(patched)
    before = score(svc, engine, taint)
    _restore(original)

    print("Running AFTER  (with .py suppression + AST, current production code)...")
    after = score(svc, engine, taint)

    print_result("BEFORE  -- regex all languages + AST (no suppression)", before)
    print_result("AFTER   -- regex suppressed for .py + AST (current production)", after)

    dp = after['prec'] - before['prec']
    dr = after['rec']  - before['rec']
    df = after['f1']   - before['f1']
    sign = lambda v: ("+" if v >= 0 else "") + f"{v:.1%}"

    print()
    print("=" * 64)
    print("  DELTA  (after - before, full pipeline)")
    print("=" * 64)
    print(f"  Precision  {before['prec']:.1%} -> {after['prec']:.1%}   ({sign(dp)})")
    print(f"  Recall     {before['rec']:.1%} -> {after['rec']:.1%}   ({sign(dr)})")
    print(f"  F1         {before['f1']:.1%} -> {after['f1']:.1%}   ({sign(df)})")
    print()
    print("  This run includes the AST layer (run_ast_scan via ScannerService),")
    print("  so AFTER numbers reflect the true production pipeline.")
