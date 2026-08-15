#!/usr/bin/env python3
"""Generate an ATT&CK Navigator layer from the attack.t#### tags on Sigma rules.

Usage: python build_attack_navigator.py > ../../docs/attack_coverage.json
Then import docs/attack_coverage.json at https://mitre-attack.github.io/attack-navigator/
"""
import json
import re
import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"
TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def collect_techniques() -> dict[str, list[str]]:
    techniques: dict[str, list[str]] = {}
    for rule_file in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text())
        for tag in rule.get("tags", []):
            match = TECHNIQUE_TAG.match(tag)
            if match:
                technique_id = match.group(1).upper()
                techniques.setdefault(technique_id, []).append(rule_file.name)
    return techniques


def build_layer(techniques: dict[str, list[str]]) -> dict:
    return {
        "name": "Sentinel Detection Coverage",
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from Sigma rule attack.t#### tags in detections/rules/",
        "techniques": [
            {
                "techniqueID": tid,
                "score": 1,
                "comment": ", ".join(files),
                "color": "#4caf50",
            }
            for tid, files in sorted(techniques.items())
        ],
        "gradient": {
            "colors": ["#ffffff", "#4caf50"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [{"label": "Covered by a Sigma rule", "color": "#4caf50"}],
    }


if __name__ == "__main__":
    techniques = collect_techniques()
    json.dump(build_layer(techniques), sys.stdout, indent=2)
    print(file=sys.stderr)
    print(f"{len(techniques)} ATT&CK technique(s) covered", file=sys.stderr)
