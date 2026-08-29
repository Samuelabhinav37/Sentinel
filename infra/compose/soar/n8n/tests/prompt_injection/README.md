# Prompt-injection corpus for the LLM triage stage

The triage pipeline runs attacker-influenced alert data through an LLM
(`infra/compose/soar/n8n/workflows/llm-triage*.json`, the "Build Prompt"
node). CLAUDE.md §6 treats that as a live injection surface. This directory
is the regression corpus for it.

## Two layers

**`test_prompt_guard.py` — structural, runs in CI (Infra CI / python job).**
No model call. Asserts that both workflow files still carry the injection
guard sentence and the JSON schema line verbatim, that the guard comes
*before* any attacker-controlled field in the prompt, and that every payload
in `payloads.json`, when rendered, lands after the guard and never disturbs
the fixed preamble. `render.py` holds the Python port of the prompt and the
guard/schema constants; if the node's wording changes, update `render.py`
and this test fails until they match again.

**`run_live_check.py` — behavioural, human-run, not in CI.**
Sends each payload through the real model(s), mirroring the workflow's exact
calls, and checks the reply still satisfies the payload's `live_assert`
(valid JSON, only the schema keys, severity not talked up or down, no prompt
text leaked, no shell command echoed into `recommended_action`).

```
OLLAMA_URL=http://localhost:11434 \
ANTHROPIC_API_KEY=sk-... \
./run_live_check.py
```

Set only the model(s) you want to exercise. Non-zero exit on any failure.

## Adding a payload

Append to `payloads.json`: a unique `id`, the `field` it arrives in
(`rule_name` / `host` / `description` / `raw`), the `payload` text, a short
`intent`, and a `live_assert` from the set `run_live_check.py` understands.
The structural test picks it up automatically.
