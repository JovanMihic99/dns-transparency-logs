from flask import Flask, jsonify, request, abort
from lokey.store import append_event, read_events, signed_tree_head, proof_for

app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify(status="ok", service="lokey-log")

@app.get("/events")
def events():
    return jsonify(read_events())

@app.post("/events")
def add_event():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, description="Expected a JSON object")
    if not body.get("domain") or not body.get("change"):
        abort(400, description="'domain' and 'change' are required")
    return jsonify(append_event(body)), 201

@app.get("/tree-head")
def tree_head():
    return jsonify(signed_tree_head())

@app.get("/proof/<int:index>")
def inclusion(index):
    try:
        return jsonify(proof_for(index))
    except IndexError:
        abort(404, description="No event at that index")

if __name__ == "__main__":
    # Development only. Put behind an authenticated service in real deployments.
    app.run(host="127.0.0.1", port=5000, debug=True)
