"""
Agent: Executive Reporter
Reads EVERYTHING stored for a session - API maps, CVE matches, anything
future agents add - and drafts a Markdown report in one shot. This is the
one-agent-no-pipeline behavior you wanted: it doesn't care which agents ran
or in what order, only what's sitting in the findings table.
"""

import json
import requests

import db

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:latest"

PROMPT_TEMPLATE = """You are a professional penetration test report writer.
Using ONLY the findings data below, write a concise Markdown bug bounty / pentest report.
Structure it with: Executive Summary, Scope, Findings (grouped by type), Recommendations.
If a section has no data, say "No findings of this type." Do not invent details not present in the data.

FINDINGS DATA:
{findings}

ANALYST NOTES:
{notes}
"""


def run(session_id, notes=""):
    findings = db.get_findings(session_id=session_id)
    if not findings:
        return "No findings recorded for this session."

    # raw_traffic can be huge and isn't itself a "finding" - summarize it
    # as a count instead of dumping every captured request into the prompt
    summary = []
    raw_count = 0
    for f in findings:
        if f["finding_type"] == "raw_traffic":
            raw_count += 1
            continue
        summary.append(
            {
                "type": f["finding_type"],
                "agent": f["agent"],
                "target": f["target"],
                "data": f["data"],
            }
        )
    if raw_count:
        summary.append({"type": "raw_traffic_summary", "count": raw_count})

    prompt = PROMPT_TEMPLATE.format(
        findings=json.dumps(summary, indent=2)[:14000],
        notes=notes or "None provided.",
    )

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=300,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            "Can't reach Ollama at localhost:11434 - is 'ollama serve' running?"
        ) from e
    except requests.exceptions.Timeout as e:
        raise RuntimeError(
            f"Ollama didn't respond within 300s. Try 'ollama run {MODEL} \"hi\"' "
            "manually to see how slow it actually is on this machine."
        ) from e

    report = resp.json()["response"].strip()

    db.add_finding(
        session_id=session_id,
        agent="reporter",
        finding_type="report",
        data={"markdown": report, "notes": notes},
    )
    return report