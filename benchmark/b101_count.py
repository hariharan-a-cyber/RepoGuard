"""
Count B101 before/after suppression using bandit JSON file.
Usage: python benchmark/b101_count.py <bandit_json_file>
       OR python benchmark/b101_count.py  (reads from $TEMP/bandit_out.json)
"""
import json, sys
from pathlib import Path

src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Users\aramy\AppData\Local\Temp\bandit_out.json")
data = json.loads(src.read_text(encoding="utf-8-sig"))
results = data.get("results", [])

NONPROD_OLD = ("generate","dataset","seed","mock","fixture","sample","factory",
               "/data/","/scripts/","_test","test_","/tests/")
NONPROD_NEW = ("/tests/","/test/","test_","_test","conftest","/fixtures/","fixture",
               "/data/","/scripts/","generate","dataset","seed","mock","sample","factory")
NOISE_OLD = {"B311","B322","B330"}
NOISE_NEW = {"B101","B311","B322","B330"}

def suppress_old(r):
    tid = r.get("test_id","")
    fn  = r.get("filename","").lower().replace("\\","/")
    return tid in NOISE_OLD and any(t in fn for t in NONPROD_OLD)

def suppress_new(r):
    tid = r.get("test_id","")
    fn  = r.get("filename","").lower().replace("\\","/")
    return tid in NOISE_NEW and any(t in fn for t in NONPROD_NEW)

b101_all      = [r for r in results if r.get("test_id")=="B101"]
b101_in_tests = [r for r in b101_all if suppress_new(r)]
b101_in_prod  = [r for r in b101_all if not suppress_new(r)]
other_noise   = [r for r in results if r.get("test_id") in {"B311","B322","B330"}]

kept_old = [r for r in results if not suppress_old(r)]
kept_new = [r for r in results if not suppress_new(r)]

print(f"Raw bandit findings scanned:        {len(results)}")
print(f"  B101 (assert_used) total:         {len(b101_all)}")
print(f"    in test/non-prod files:         {len(b101_in_tests)}  <- suppressed by fix")
print(f"    in production files:            {len(b101_in_prod)}  <- still fire")
print(f"  B311/B322/B330 noise:             {len(other_noise)}")
print()
print(f"BEFORE fix  (B311/B322/B330 suppressed in nonprod only):")
print(f"  Findings emitted:                 {len(kept_old)}")
print()
print(f"AFTER  fix  (B101 also suppressed in test/nonprod files):")
print(f"  Findings emitted:                 {len(kept_new)}")
print(f"  Net reduction:                    {len(kept_old)-len(kept_new)} fewer findings")
print()

# Sample suppressed B101s
if b101_in_tests:
    print("Examples suppressed (B101 in test files):")
    for r in b101_in_tests[:3]:
        fn = r.get("filename","").replace("\\","/")
        parts = fn.rsplit("/tests/",1)
        short = "tests/" + parts[-1] if len(parts)>1 else fn
        code = r.get("code","").strip().splitlines()[0][:65]
        print(f"  [B101] {short}:{r.get('line_number')}  {code}")

# Dangerous rules in test files that still fire
danger_in_tests = [
    r for r in kept_new
    if any(t in r.get("filename","").lower().replace("\\","/") for t in NONPROD_NEW)
    and r.get("test_id") not in NOISE_NEW
]
if danger_in_tests:
    print()
    print("Dangerous rules in test files that still fire (correct):")
    for r in danger_in_tests[:3]:
        fn = r.get("filename","").replace("\\","/")
        parts = fn.rsplit("/tests/",1)
        short = "tests/" + parts[-1] if len(parts)>1 else fn
        print(f"  [{r['test_id']}] {short}:{r.get('line_number')}  {r.get('issue_text','')[:60]}")
