#!/usr/bin/env python3
"""Detection-as-code CI gate.

Runs entirely offline against the committed files -- no live cluster
reachable from GitHub Actions (everything in this project sits behind
Tailscale), so this validates structure and known regression classes, not
"does this actually fire." That's still done by hand, live, against the real
cluster (see detections/tests/validation.yml and docs/build-log.md) --  this
script's job is to catch a broken rule *before* it reaches deploy.sh, not to
replace live-fire validation.

Checks, in order:
  1. Every detections/rules/*.yml has a matching detections/deployed/*.json
     (same filename stem) and vice versa -- no orphaned rule on either side.
  2. The Sigma rule's `id` matches the deployed rule's `rule_id`.
  3. Every deployed JSON is valid JSON with all required fields present,
     including the `sentinel-sigma` tag every live rule is expected to carry
     (the n8n triage pipelines filter on it).
  4. Every deployed rule_id has a detections/tests/validation.yml entry.
  5. Regression checks for two real bugs found live-firing rules this
     project has already hit once (see docs/build-log.md Phase 21): a
     `regex~` query must not contain the invalid `(?i)` inline flag, and
     must anchor its pattern with `.*...*` on both ends, since Elasticsearch
     EQL's `regex~` requires a full-string match, not a substring search.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "detections" / "rules"
DEPLOYED_DIR = REPO_ROOT / "detections" / "deployed"
VALIDATION_FILE = REPO_ROOT / "detections" / "tests" / "validation.yml"

REQUIRED_DEPLOYED_FIELDS = [
    "rule_id", "name", "type", "language", "query", "index",
    "severity", "risk_score", "enabled", "from", "interval",
    "tags", "references", "false_positives", "author",
]

errors = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"FAIL: {msg}")


def run_sigma_check() -> None:
    rule_files = sorted(RULES_DIR.glob("*.yml"))
    if not rule_files:
        fail("no Sigma rules found under detections/rules/")
        return
    result = subprocess.run(
        ["sigma", "check", *[str(f) for f in rule_files]],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        fail("sigma check reported rule errors (see output above)")
    else:
        print(f"OK: sigma check passed for {len(rule_files)} rules")


def load_deployed() -> dict:
    deployed = {}
    for path in sorted(DEPLOYED_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            fail(f"{path.name}: invalid JSON ({e})")
            continue
        deployed[path.stem] = (path, data)
    return deployed


def load_rules() -> dict:
    rules = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            fail(f"{path.name}: invalid YAML ({e})")
            continue
        rules[path.stem] = (path, data)
    return rules


def check_pairing(rules: dict, deployed: dict) -> None:
    rule_stems = set(rules)
    deployed_stems = set(deployed)

    for stem in sorted(rule_stems - deployed_stems):
        fail(f"{stem}.yml has no matching detections/deployed/{stem}.json")
    for stem in sorted(deployed_stems - rule_stems):
        fail(f"{stem}.json has no matching detections/rules/{stem}.yml")

    for stem in sorted(rule_stems & deployed_stems):
        _, rule_data = rules[stem]
        _, deployed_data = deployed[stem]
        rule_id = rule_data.get("id")
        deployed_id = deployed_data.get("rule_id")
        if rule_id != deployed_id:
            fail(f"{stem}: rules/ id ({rule_id}) != deployed/ rule_id ({deployed_id})")


def check_required_fields(deployed: dict) -> None:
    for stem, (path, data) in deployed.items():
        for field in REQUIRED_DEPLOYED_FIELDS:
            if field not in data:
                fail(f"{path.name}: missing required field '{field}'")
        tags = data.get("tags", [])
        if "sentinel-sigma" not in tags:
            fail(f"{path.name}: missing the 'sentinel-sigma' tag the triage pipelines filter on")


def check_validation_coverage(deployed: dict) -> None:
    if not VALIDATION_FILE.exists():
        fail("detections/tests/validation.yml does not exist")
        return
    entries = yaml.safe_load(VALIDATION_FILE.read_text(encoding="utf-8")) or []
    validated_ids = {e.get("rule_id") for e in entries}
    for stem, (path, data) in deployed.items():
        rule_id = data.get("rule_id")
        if rule_id not in validated_ids:
            fail(f"{path.name}: rule_id {rule_id} has no entry in detections/tests/validation.yml")


REGEX_OP_PATTERN = re.compile(r'regex~\s*"((?:[^"\\]|\\.)*)"')


def check_regex_anchoring(deployed: dict) -> None:
    """Regression check for the Phase 21 bug: EQL's regex~ operator requires
    a full-string match and doesn't support the (?i) inline flag."""
    for stem, (path, data) in deployed.items():
        query = data.get("query", "")
        if data.get("type") != "eql" or "regex~" not in query:
            continue
        matches = REGEX_OP_PATTERN.findall(query)
        if not matches:
            fail(f"{path.name}: uses regex~ but the pattern couldn't be extracted for checking "
                 f"(unexpected quoting?) -- verify by hand")
            continue
        for pattern in matches:
            if "(?i)" in pattern:
                fail(f"{path.name}: regex~ pattern contains the invalid (?i) flag "
                     f"(Lucene automaton regex, not PCRE -- matched as literal text, silently "
                     f"kills every match; regex~ is already case-insensitive). See Phase 21.")
            if not (pattern.startswith(".*") and pattern.endswith(".*")):
                fail(f"{path.name}: regex~ pattern isn't wrapped in .*...* -- EQL's regex~ "
                     f"requires a full-string match, not a substring search. See Phase 21.")


def main() -> int:
    run_sigma_check()
    rules = load_rules()
    deployed = load_deployed()
    check_pairing(rules, deployed)
    check_required_fields(deployed)
    check_validation_coverage(deployed)
    check_regex_anchoring(deployed)

    print()
    if errors:
        print(f"{len(errors)} check(s) failed:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"All checks passed: {len(rules)} rule pairs, {len(deployed)} deployed rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
