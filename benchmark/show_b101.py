"""Show B101 findings before/after suppression, using any available bandit."""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANDIT_CANDIDATES = [
    "bandit",
    sys.executable.replace("python.exe", "bandit.exe"),
    r"C:\Users\aramy\Downloads\My Projects\New\.venv\Scripts\bandit.exe",
]

def run_bandit(target):
    for exe in BANDIT_CANDIDATES:
        for cmd in [[exe, "-r", str(target), "-f", "json", "-q"],
                    [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q"]]:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if r.stdout.strip():
                    return json.loads(r.stdout)
            except Exception:
                continue
    return {}

NONPROD_TOKENS_OLD = ("generate", "dataset", "seed", "mock", "fixture",
                      "sample", "factory", "/data/", "/scripts/", "_test", "test_", "/tests/")
NONPROD_TOKENS_NEW = (
    "/tests/", "/test/", "test_", "_test", "conftest",
    "/fixtures/", "fixture", "/data/", "/scripts/",
    "generate", "dataset", "seed", "mock", "sample", "factory",
)
NOISE_OLD = {"B311", "B322", "B330"}
NOISE_NEW = {"B101", "B311", "B322", "B330"}


def count_suppressed(results, noise_rules, nonprod_tokens):
    suppressed, kept = [], []
    for r in results:
        tid = r.get("test_id", "")
        fname = r.get("filename", "").lower().replace("\\", "/")
        if tid in noise_rules and any(t in fname for t in nonprod_tokens):
            suppressed.append(r)
        else:
            kept.append(r)
    return kept, suppressed


if __name__ == "__main__":
    target = ROOT
    print(f"Running bandit on {target} ...")
    data = run_bandit(target)
    results = data.get("results", [])

    if not results and not data:
        print("ERROR: bandit not available or returned no output.")
        sys.exit(1)

    b101 = [r for r in results if r.get("test_id") == "B101"]
    in_tests = [r for r in b101 if any(t in r.get("filename","").lower().replace("\\","/")
                                        for t in NONPROD_TOKENS_NEW)]
    other_noise = [r for r in results if r.get("test_id") in {"B311","B322","B330"}]

    kept_old, sup_old = count_suppressed(results, NOISE_OLD, NONPROD_TOKENS_OLD)
    kept_new, sup_new = count_suppressed(results, NOISE_NEW, NONPROD_TOKENS_NEW)

    print(f"\nRaw bandit findings (whole repo):  {len(results)}")
    print(f"  B101 assert_used total:           {len(b101)}")
    print(f"  B101 in test/non-prod files:      {len(in_tests)}  <- these are suppressed by the fix")
    print(f"  B101 in production files:         {len(b101) - len(in_tests)}  <- these still fire")
    print(f"  B311/B322/B330 noise:             {len(other_noise)}")

    print(f"\nBEFORE fix (old suppression — B311/B322/B330 only in nonprod):")
    print(f"  Findings emitted to report:       {len(kept_old)}")

    print(f"\nAFTER fix (new suppression — B101 added, tokens expanded):")
    print(f"  Findings emitted to report:       {len(kept_new)}")
    print(f"  Net reduction:                    {len(kept_old) - len(kept_new)} fewer findings")

    if in_tests:
        print(f"\nSample B101 findings that are now suppressed (test files):")
        for r in in_tests[:5]:
            fn = r.get("filename","").replace("\\","/")
            short = fn.split(str(ROOT).replace("\\","/"))[-1].lstrip("/")
            code = r.get("code","").strip().splitlines()[0][:70]
            print(f"  [{r['test_id']}] {short}:{r.get('line_number')}  {code}")

    # Show kept dangerous findings in test files (must still fire)
    dangerous_in_tests = [
        r for r in kept_new
        if any(t in r.get("filename","").lower().replace("\\","/") for t in NONPROD_TOKENS_NEW)
        and r.get("test_id") not in NOISE_NEW
    ]
    if dangerous_in_tests:
        print(f"\nDangerous rules in test files that still fire (EXPECTED):")
        for r in dangerous_in_tests[:5]:
            fn = r.get("filename","").replace("\\","/")
            short = fn.split(str(ROOT).replace("\\","/"))[-1].lstrip("/")
            print(f"  [{r['test_id']}] {short}:{r.get('line_number')}  {r.get('issue_text','')[:60]}")
