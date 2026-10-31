from datetime import datetime

from flask import Flask, jsonify, request, abort, render_template, render_template, render_template

from lokey.store import (
    append_event,
    read_events,
    read_assessments,
    signed_tree_head,
    proof_for,
    consistency_proof_for,
    read_tree_heads,
    canonical_observation,
)

from lokey.merkle import leaf_hash
from lokey.signing import verify_tree_head

import logging

from lokey.notifications import send_telegram_alert

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CHANGE_TYPES = {
    "NS_CHANGED",
    "DS_ADDED",
    "DS_REMOVED",
    "DS_ALL_REMOVED",
    "DS_REPLACED",
    "DNSKEY_CHANGED",
    "CDS_PUBLISHED",
    "CDS_REMOVED",
}

DNS_FIELDS = {"ns", "ds", "dnskey", "cds"}


@app.get("/")
def dashboard():
    return render_template("index.html")


@app.get("/api/dashboard")
def dashboard_data():
    events = read_events()
    assessments = read_assessments()

    # Join assessments to observations using their Merkle leaf hashes.
    assessment_map = {
        item["leaf_hash"]: item["assessment"]
        for item in assessments
    }

    timeline = []

    for index, observation in enumerate(events):
        digest = leaf_hash(
            canonical_observation(observation)
        ).hex()

        assessment = assessment_map.get(digest, {})

        timeline.append({
            "index": index,
            "observation": observation,
            "leaf_hash": digest,
            "assessment": assessment,
        })

    risk_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for item in timeline:
        risk = item["assessment"].get("risk", "unknown").lower()

        if risk not in risk_counts:
            risk = "unknown"

        risk_counts[risk] += 1

    tree_heads = read_tree_heads()

    latest_tree_head = None

    if tree_heads:
        latest_tree_head = tree_heads[-1]
        latest_tree_head = {
            **latest_tree_head,
            "signature_valid": verify_tree_head(latest_tree_head),
        }

    return jsonify({
        "stats": {
            "total_events": len(events),
            "total_assessments": len(assessments),
            "risk_counts": risk_counts,
            "tree_size": len(events),
            "tree_head_count": len(tree_heads),
        },
        "latest_event": timeline[-1] if timeline else None,
        "latest_tree_head": latest_tree_head,
        "events": timeline,
    })


@app.get("/api/tree-heads")
def historical_tree_heads():
    heads = read_tree_heads()

    return jsonify([
        {
            **head,
            "signature_valid": verify_tree_head(head),
        }
        for head in reversed(heads)
    ])

def validate_event(body):
    if not isinstance(body, dict):
        return "Expected a JSON object"

    if set(body) != {"observation", "assessment"}:
        return "Event must contain observation and assessment only"

    observation = body["observation"]
    assessment = body["assessment"]

    if not isinstance(observation, dict):
        return "observation must be an object"

    required_observation = {
        "domain", "observed_at", "changes", "before", "after"
    }

    if set(observation) != required_observation:
        return "Invalid observation fields"

    if not isinstance(observation["domain"], str) or not observation["domain"].strip():
        return "Invalid domain"

    if not isinstance(observation["observed_at"], str):
        return "observed_at must be an ISO 8601 string"

    try:
        timestamp = datetime.fromisoformat(
            observation["observed_at"].replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            return "observed_at must include a timezone"
    except ValueError:
        return "Invalid observed_at timestamp"

    changes = observation["changes"]

    if not isinstance(changes, list) or not changes:
        return "changes must be a non-empty array"

    if any(
        not isinstance(change, str) or change not in CHANGE_TYPES
        for change in changes
    ):
        return "Unknown change type"

    if len(changes) != len(set(changes)):
        return "Duplicate change types are not allowed"

    for section in ("before", "after"):
        records = observation[section]

        if not isinstance(records, dict) or set(records) != DNS_FIELDS:
            return f"{section} must contain ns, ds, dnskey and cds"

        for field in DNS_FIELDS:
            values = records[field]

            if not isinstance(values, list):
                return f"{section}.{field} must be an array"

            if any(not isinstance(value, str) for value in values):
                return f"{section}.{field} must contain strings"

    if not isinstance(assessment, dict):
        return "assessment must be an object"

    if set(assessment) != {"risk", "reasons", "rules_version"}:
        return "Invalid assessment fields"

    if not isinstance(assessment["risk"], str) or not assessment["risk"]:
        return "assessment.risk must be a non-empty string"

    if not isinstance(assessment["reasons"], list):
        return "assessment.reasons must be an array"

    if any(not isinstance(reason, str) for reason in assessment["reasons"]):
        return "assessment.reasons must contain strings"

    if not isinstance(assessment["rules_version"], str) or not assessment["rules_version"]:
        return "assessment.rules_version must be a non-empty string"

    return None


@app.get("/health")
def health():
    return jsonify(status="ok", service="lokey-log")


@app.get("/events")
def events():
    return jsonify(read_events())


@app.get("/assessments")
def assessments():
    return jsonify(read_assessments())


@app.post("/events")
def add_event():
    body = request.get_json(silent=True)

    error = validate_event(body)

    if error:
        abort(400, description=error)

    result = append_event(body)

    # Notification failure must never invalidate a stored event.
    try:
        send_telegram_alert(result)
    except Exception:
        logger.exception("Unexpected Telegram notification failure")

    return jsonify(result), 201

@app.get("/tree-head")
def tree_head():
    return jsonify(signed_tree_head())


@app.get("/proof/<int:index>")
def inclusion(index):
    try:
        return jsonify(proof_for(index))
    except IndexError:
        abort(404, description="No event at that index")


@app.get("/consistency/<int:old_size>")
def consistency(old_size):
    try:
        return jsonify(consistency_proof_for(old_size))
    except ValueError as error:
        abort(400, description=str(error))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
