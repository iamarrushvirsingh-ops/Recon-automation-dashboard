"""
Agent: Automated API Hunter (active fuzzing)
Asks the LLM for plausible undocumented API paths given a short app
description, then actually fires requests at the target to see which
exist. Finds "shadow" endpoints the crawler can't - because nothing in the
UI links to them.
"""

import re

import requests

import db

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:7b"

PROMPT_TEMPLATE = """You are an API security researcher. Given a web application with context "{context}",
generate a comma-separated list of 20 highly probable, undocumented REST API paths an engineer might have
built for it (e.g. /api/v1/users, /api/internal/debug). Output ONLY the comma-separated list, nothing else -
no numbering, no markdown, no explanation.
"""

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

# Anything other than these is treated as "nothing here" and skipped
INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403, 405, 500}


def _generate_candidate_paths(context):
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": PROMPT_TEMPLATE.format(context=context),
                "stream": False,
            },
            # Ollama can take a while on first call while it loads the model
            # into memory - 60s was too tight for a 7B model on modest hardware
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

    raw = resp.json()["response"]

    # Sanitize: the model is told "comma-separated only" but frequently
    # ignores that - newlines, numbered lists ("1. /api/..."), bullets, and
    # stray quotes all show up in practice. Normalize all of it.
    raw = re.sub(r"```.*?```", "", raw, flags=re.DOTALL)
    raw = raw.replace("\n", ",")

    paths = []
    for chunk in raw.split(","):
        c = chunk.strip().strip("\"'` ")
        c = re.sub(r"^\s*\d+[.\)]\s*", "", c)   # "1. " / "1) "
        c = re.sub(r"^[-*]\s*", "", c)          # "- " / "* "
        if not c:
            continue
        if not c.startswith("/"):
            c = f"/{c}"
        if " " in c:  # still looks like prose, not a path - discard
            continue
        paths.append(c)
    return paths


def run(session_id, base_url, app_context):
    base_url = base_url.rstrip("/")
    paths = _generate_candidate_paths(app_context)
    found = []
    status_counts = {}  # e.g. {404: 17, 200: 1, "error": 2} - surfaced to the UI

    for path in paths:
        url = f"{base_url}{path}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=5, allow_redirects=False)
        except requests.RequestException as e:
            status_counts["error"] = status_counts.get("error", 0) + 1
            status_counts.setdefault("error_examples", []).append(f"{url} -> {e.__class__.__name__}")
            continue

        status_counts[resp.status_code] = status_counts.get(resp.status_code, 0) + 1

        if resp.status_code in INTERESTING_CODES:
            entry = {"url": url, "status": resp.status_code, "method": "GET"}
            found.append(entry)
            db.add_finding(
                session_id=session_id,
                agent="api_hunter",
                finding_type="api_endpoint",
                data=entry,
                target=urlparse_netloc(base_url),
            )

    return {"found": found, "paths_tried": paths, "status_counts": status_counts}


def urlparse_netloc(url):
    from urllib.parse import urlparse

    return urlparse(url).netloc