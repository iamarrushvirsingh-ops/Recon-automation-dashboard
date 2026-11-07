"""
Agent 1: API Mapper (Passive Recon)
Reads 'raw_traffic' findings for a target and asks a local Ollama model to
turn them into an OpenAPI 3.0 YAML document. Writes the result back as an
'api_endpoint' finding. This is the agent you didn't have yet - it's new.
"""

import json
import requests

import db

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:7b"

PROMPT_TEMPLATE = """You are an API documentation generator. Below is a list of captured HTTP request/response pairs in JSON.
Convert them into a valid OpenAPI 3.0 YAML document describing these endpoints.
Output ONLY valid YAML. Do not include any explanation, conversational text, or markdown code fences.

CAPTURED TRAFFIC:
{traffic}
"""


def _sanitize_yaml(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("yaml\n"):
            text = text[5:]
    return text.strip()


def run(session_id, target=None):
    findings = db.get_findings(session_id=session_id, finding_type="raw_traffic", target=target)
    if not findings:
        return None

    traffic = [f["data"] for f in findings]
    # Guard against blowing the model's context window on large capture sets
    prompt = PROMPT_TEMPLATE.format(traffic=json.dumps(traffic, indent=2)[:12000])

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

    yaml_output = _sanitize_yaml(resp.json()["response"])

    db.add_finding(
        session_id=session_id,
        agent="api_mapper",
        finding_type="api_endpoint",
        data={"yaml": yaml_output, "source_request_count": len(traffic)},
        target=target,
    )
    return yaml_output