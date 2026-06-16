"""Minimal Flask app that references requests so both deps are genuine."""
import requests
from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/upstream")
def upstream():
    # Demonstrates a real use of the requests dependency.
    resp = requests.get("https://example.com", timeout=5)
    return jsonify(upstream_status=resp.status_code)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
