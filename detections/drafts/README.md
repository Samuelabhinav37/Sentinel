# Detection drafts

Output of `detections/scripts/detection_advisor.py` — proposed Sigma rules and
refinement suggestions from the human-review queue (`sentinel-triage` docs where
the dual-AI cross-check disagreed, or a model rated an alert high/critical
severity without a low false-positive likelihood).

**Nothing in this directory is live, validated, or deployed.** It's deliberately
invisible to `detections/scripts/validate_rules.py` and `.github/workflows/sigma-ci.yml`
— both only glob `detections/rules/*.yml` / `detections/deployed/*.json`, never this
directory — so a draft sitting here can't accidentally reach CI, `sigma check`, or a
live deploy. Each `<date>-<slug>/` subdirectory holds:

- `assessment.md` — the advisor's verdict, its reasoning, and the source
  `alert_id`/triage doc id so you can pull up the real alert in Kibana and check its
  work.
- `draft_rule.yml` — a proposed Sigma rule, only present when the verdict was
  `rule_refinement_suggested` or `new_rule_suggested` and the LLM's output had the
  required fields. `id`, `status`, `author`, and `date` are assigned by the script
  itself (never trusted from the LLM), everything else is exactly as proposed and
  unreviewed.

## Promoting a draft

A draft re-enters this project's existing Definition of Done (CLAUDE.md Section 8) with
no shortcuts:

1. Read `assessment.md`, pull the cited alert in Kibana, and confirm the reasoning
   actually holds up against the real event.
2. `sigma check` the `draft_rule.yml` and fix anything it flags.
3. Hand-write the paired `detections/deployed/<stem>.json` (see any existing file in
   `detections/deployed/` for the required fields), matching `rule_id` to the draft's
   `id`.
4. Live-fire it (Atomic Red Team, a hand-run command, or a Mordor replay/synthetic
   event per `detections/scripts/`) and confirm a negative control doesn't fire on
   benign use of the same tool.
5. Add a `detections/tests/validation.yml` entry with the real evidence.
6. Move the file into `detections/rules/`, delete the draft directory, and run
   `python detections/scripts/validate_rules.py`.
7. A human runs `scripts/redeploy.sh` — never automated.
