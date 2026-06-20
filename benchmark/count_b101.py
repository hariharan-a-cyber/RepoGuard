"""Count bandit B101 findings before/after suppression logic."""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

def run_bandit(target):
    for cmd in [["bandit", "-r", str(target), "-f", "json", "-q"],
                [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q"]]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            return json.loads(r.stdout or "{}")
        except Exception:
            continue
    return {}

NONPROD_TOKENS = (
    "/tests/", "/test/", "test_", "_test", "conftest",
    "/fixtures/", "fixture", "/data/", "/scripts/",
    "generate", "dataset", "seed", "mock", "sample", "factory",
)
NOISE_RULES = {"B101", "B311", "B322", "B330"}

def classify(results):
    kept, suppressed_b101, suppressed_other = [], [], []
    for r in results:
        tid = r.get("test_id", "")
        fname = r.get("filename", "").lower().replace("\\", "/")
        is_nonprod = any(t in fname for t in NONPROD_TOKENS)
        if tid in NOISE_RULES and is_nonprod:
            if tid == "B101":
                suppressed_b101.append(r)
            else:
                suppressed_other.append(r)
        else:
            kept.append(r)
    return kept, suppressed_b101, suppressed_other

if __name__ == "__main__":
    target = ROOT / "tests"
    print(f"Running bandit on {target} ...")
    data = run_bandit(target)
    results = data.get("results", [])
    kept, s_b101, s_other = classify(results)

    print(f"\nRaw bandit findings in tests/:   {len(results)}")
    print(f"  B101 (assert_used) findings:   {len([r for r in results if r.get('test_id')=='B101'])}")
    print(f"  Other noise (B311/B322/B330):  {len([r for r in results if r.get('test_id') in {'B311','B322','B330'}])}")
    print(f"  Other rules:                   {len([r for r in results if r.get('test_id') not in {'B101','B311','B322','B330'}])}")
    print(f"\nAfter new suppression logic:")
    print(f"  Suppressed B101:               {len(s_b101)}")
    print(f"  Suppressed B311/B322/B330:     {len(s_other)}")
    print(f"  Still emitted (all rules):     {len(kept)}")
    if kept:
        print(f"\n  Kept findings (sample):")
        for r in kept[:10]:
            fname = r.get("filename","").replace("\\","/").split("/tests/")[-1]
            print(f"    [{r.get('test_id')}] tests/{fname}:{r.get('line_number')}  {r.get('issue_text','')[:60]}")

    # Also run on the full project to show total self-scan before/after
    print(f"\n--- Full project self-scan ---")
    data2 = run_bandit(ROOT)
    results2 = data2.get("results", [])
    kept2, s_b101_2, s_other2 = classify(results2)
    print(f"Raw bandit findings (whole repo): {len(results2)}")
    print(f"  of which B101:                 {len([r for r in results2 if r.get('test_id')=='B101'])}")
    print(f"After suppression:")
    print(f"  Emitted (before this change):  {len(results2) - len(s_other2)}  (old: only B311/B322/B330 suppressed in nonprod)")
    print(f"  Emitted (after  this change):  {len(kept2)}")
    print(f"  Net reduction from B101 fix:   {len(s_b101_2)} fewer findings")
