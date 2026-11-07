"""
Flask ingress for traffic POSTed from ai_parser.py on the Kali VM.
Unchanged on the mitmdump/Kali side - same POST shape, same /ingest route,
same port. The only change on this end: instead of (or alongside) writing
captured_traffic.json, each capture is stored as a 'raw_traffic' finding in
the unified SQLite store, tagged with whichever session is currently active
in the Streamlit dashboard.
"""

from flask import Flask, request, jsonify
from urllib.parse import urlparse
import db

app = Flask(__name__)
db.init_db()


@app.route("/ingest", methods=["POST"])
def ingest():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "empty or invalid JSON payload"}), 400

    session_id = db.get_config("active_session", "default")
    target = urlparse(payload.get("url", "")).netloc or "unknown"

    db.add_finding(
        session_id=session_id,
        agent="mitm_capture",
        finding_type="raw_traffic",
        data=payload,
        target=target,
    )

    return jsonify({"status": "stored", "session": session_id, "target": target}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)