"""
engine.py
----------
Orchestrator. For a given case, it:
  1. Runs the deterministic rule checker first (checker.py).
  2. If the rule checker found nothing, it builds the diagnose prompt
     and asks the AI model, then parses the JSON it returns.
  3. Always returns the SAME structured shape either way, so app.py
     doesn't need to know which path produced the answer.

No result from this file is ever auto-applied to a device. Every
result goes to a human for Approve / Edit / Reject (see app.py).
"""

import json
import os
import re
from pathlib import Path

from checker import check_case

BASE_DIR = Path(__file__).resolve().parent
PROMPT_PATH = BASE_DIR / "diagnose_prompt.md"


def _build_user_prompt(symptom, topology_note, show_outputs):
    return (
        f"Symptom: {symptom}\n"
        f"Topology: {topology_note}\n"
        f"show_outputs: {show_outputs}\n\n"
        "Return the JSON diagnosis now."
    )


def _call_ai_model(symptom, topology_note, show_outputs):
    """
    Calls the Anthropic API to diagnose a case the rule checker could not
    resolve. Requires ANTHROPIC_API_KEY to be set as an environment
    variable (or in Streamlit secrets — see app.py). If no key is
    available, returns an honest low-confidence placeholder instead of
    making anything up.
    """
    system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
    user_prompt = _build_user_prompt(symptom, topology_note, show_outputs)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "root_cause": "AI diagnosis unavailable — no ANTHROPIC_API_KEY configured. "
                           "Set it in your environment or Streamlit secrets to enable this case.",
            "osi_layer": "Unknown",
            "confidence": "Low",
            "evidence": show_outputs,
            "next_command": "Configure ANTHROPIC_API_KEY, then re-run diagnosis",
            "fix_steps": [],
            "source": "ai_unavailable",
        }

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw_text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        cleaned = re.sub(r"^```json|```$", "", raw_text.strip(), flags=re.M).strip()
        parsed = json.loads(cleaned)
        parsed["source"] = "ai_model"
        return parsed
    except Exception as exc:  # noqa: BLE001 — surface any failure plainly to the operator
        return {
            "root_cause": f"AI diagnosis failed: {exc}",
            "osi_layer": "Unknown",
            "confidence": "Low",
            "evidence": show_outputs,
            "next_command": "Retry diagnosis or investigate manually",
            "fix_steps": [],
            "source": "ai_error",
        }


def diagnose(case: dict) -> dict:
    """
    case: a dict with at least symptom, topology_note, show_outputs, osi_layer (from cases.csv row)
    Returns a structured diagnosis dict, always with the same fields,
    regardless of whether the rule checker or the AI produced it.
    """
    symptom = case.get("symptom", "")
    topology_note = case.get("topology_note", "")
    show_outputs = case.get("show_outputs", "")

    rule_result = check_case(show_outputs, topology_note, symptom)

    if rule_result.status == "ERRORS_DETECTED":
        return {
            "root_cause": rule_result.root_cause,
            "osi_layer": case.get("osi_layer", "Unknown"),
            "confidence": "High",
            "evidence": rule_result.evidence,
            "next_command": rule_result.next_command,
            "fix_steps": rule_result.fix_steps,
            "source": "rule_engine",
            "rule_name": rule_result.rule_name,
        }

    ai_result = _call_ai_model(symptom, topology_note, show_outputs)
    ai_result.setdefault("osi_layer", case.get("osi_layer", "Unknown"))
    return ai_result
