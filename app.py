"""
TapnTrack Backend
=================
- POST /api/receipt        → receives S3 URL from watcher, returns short link
- GET  /r/<code>           → receipt landing page for customers
- GET  /api/health         → health check for Render
"""

import os
import json
import random
import string
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, render_template, abort, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ─── Config ─────────────────────────────────────────────────────────────────
API_KEY   = os.environ.get("TAPNTRACK_API_KEY", "change-this-key")
BASE_URL  = os.environ.get("BASE_URL", "https://tapntrack.com")
DB_PATH   = os.environ.get("DB_PATH", "tapntrack.db")
CODE_LEN  = 8
EXPIRY_H  = 24  # hours until receipt link expires


# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                code      TEXT UNIQUE NOT NULL,
                s3_url    TEXT NOT NULL,
                store_id  TEXT,
                created   TEXT NOT NULL,
                expires   TEXT NOT NULL,
                tapped    INTEGER DEFAULT 0
            )
        """)
        db.commit()


# ─── Auth ────────────────────────────────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Helpers ─────────────────────────────────────────────────────────────────

def generate_code():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=CODE_LEN))


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "TapnTrack"})


@app.route("/api/receipt", methods=["POST"])
@require_api_key
def create_receipt():
    """
    Called by tapntrack_watcher.py when a new PDF is uploaded to S3.
    Body: { "s3_url": "...", "store_id": "optional" }
    Returns: { "url": "https://tapntrack.com/r/ABC12345", "code": "ABC12345" }
    """
    data = request.get_json()
    if not data or not data.get("s3_url"):
        return jsonify({"error": "Missing s3_url"}), 400

    s3_url   = data["s3_url"]
    store_id = data.get("store_id", "default")

    # Generate unique code
    db = get_db()
    for _ in range(10):
        code = generate_code()
        existing = db.execute("SELECT id FROM receipts WHERE code = ?", (code,)).fetchone()
        if not existing:
            break

    now     = datetime.utcnow()
    expires = now + timedelta(hours=EXPIRY_H)

    db.execute(
        "INSERT INTO receipts (code, s3_url, store_id, created, expires) VALUES (?, ?, ?, ?, ?)",
        (code, s3_url, store_id, now.isoformat(), expires.isoformat())
    )
    db.commit()

    short_url = f"{BASE_URL}/r/{code}"
    return jsonify({"url": short_url, "code": code}), 201


@app.route("/r/<code>")
def receipt_page(code):
    """
    Customer lands here after tapping NFC tag.
    Shows a clean receipt page with the PDF embedded.
    """
    db = get_db()
    row = db.execute("SELECT * FROM receipts WHERE code = ?", (code,)).fetchone()

    if not row:
        abort(404)

    # Check expiry
    expires = datetime.fromisoformat(row["expires"])
    if datetime.utcnow() > expires:
        return render_template("expired.html"), 410

    # Track tap
    db.execute("UPDATE receipts SET tapped = tapped + 1 WHERE code = ?", (code,))
    db.commit()

    return render_template("receipt.html",
        code=code,
        s3_url=row["s3_url"],
        store_id=row["store_id"],
        created=row["created"][:16].replace("T", " ")
    )


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
