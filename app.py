"""
TapnTrack Backend v2
====================
- Supabase (PostgreSQL) for data storage
- Secure store provisioning (AWS bucket + IAM per store)
- Per-store API keys
- Admin dashboard
- Receipt management
"""

import os
import re
import json
import hmac
import boto3
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template, abort, g, session, redirect, url_for
from flask_cors import CORS
from supabase import create_client, Client

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# ─── Config ─────────────────────────────────────────────────────────────────
SUPABASE_URL        = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_KEY        = os.environ.get("SUPABASE_KEY", "").strip()
MASTER_AWS_KEY_ID   = os.environ.get("MASTER_AWS_KEY_ID", "")
MASTER_AWS_SECRET   = os.environ.get("MASTER_AWS_SECRET", "")
MASTER_AWS_REGION   = os.environ.get("MASTER_AWS_REGION", "us-east-1")
PROVISIONING_KEY    = os.environ.get("PROVISIONING_KEY", "change-this-provisioning-key")
BASE_URL            = os.environ.get("BASE_URL", "https://tapntrack.com")
EXPIRY_HOURS        = 24
CODE_LEN            = 8


# ─── Supabase Client ─────────────────────────────────────────────────────────

def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_api_key() -> str:
    alphabet = string.ascii_letters + string.digits
    return "tnk_" + "".join(secrets.choice(alphabet) for _ in range(40))

def generate_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(CODE_LEN))

def slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug[:40]


# ─── Auth Decorators ─────────────────────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key:
            return jsonify({"error": "Missing API key"}), 401
        sb = get_supabase()
        result = sb.table("stores").select("*").eq("api_key", key).eq("status", "active").execute()
        if not result.data:
            return jsonify({"error": "Invalid or inactive API key"}), 401
        g.store = result.data[0]
        return f(*args, **kwargs)
    return decorated

def require_provisioning_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Provisioning-Key")
        if key != PROVISIONING_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


# ─── AWS Provisioning ────────────────────────────────────────────────────────

def provision_store_aws(slug: str):
    """
    Create a dedicated S3 bucket and IAM user for a store.
    Returns (bucket_name, iam_user, access_key_id, secret_access_key)
    """
    bucket_name = f"tapntrack-{slug}"
    iam_user    = f"tapntrack-{slug}"
    region      = MASTER_AWS_REGION

    s3 = boto3.client("s3",
        region_name=region,
        aws_access_key_id=MASTER_AWS_KEY_ID,
        aws_secret_access_key=MASTER_AWS_SECRET
    )
    iam = boto3.client("iam",
        region_name=region,
        aws_access_key_id=MASTER_AWS_KEY_ID,
        aws_secret_access_key=MASTER_AWS_SECRET
    )

    # Create S3 bucket
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region}
        )

    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )

    # Add lifecycle rule — auto-delete receipts after 24 hours
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket_name,
        LifecycleConfiguration={
            "Rules": [{
                "ID": "auto-delete-receipts",
                "Filter": {"Prefix": "receipts/"},
                "Status": "Enabled",
                "Expiration": {"Days": 1}
            }]
        }
    )

    # Create IAM user
    iam.create_user(UserName=iam_user)

    # Attach policy — only access their own bucket
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetObject"],
            "Resource": f"arn:aws:s3:::{bucket_name}/receipts/*"
        }]
    })
    iam.put_user_policy(
        UserName=iam_user,
        PolicyName=f"tapntrack-{slug}-policy",
        PolicyDocument=policy
    )

    # Create access keys
    keys = iam.create_access_key(UserName=iam_user)["AccessKey"]

    return bucket_name, iam_user, keys["AccessKeyId"], keys["SecretAccessKey"]


# ─── Routes — Health ─────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "TapnTrack", "version": "2.0"})


# ─── Routes — Provisioning ───────────────────────────────────────────────────

@app.route("/api/provision", methods=["POST"])
@require_provisioning_key
def provision():
    """
    Called by the installer exe to set up a new store.
    Body: { "name": "Megatron Store" }
    Returns: { "api_key": "tnk_...", "store_id": "...", "bucket": "..." }
    """
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"error": "Missing store name"}), 400

    name = data["name"].strip()
    slug = slugify(name)

    sb = get_supabase()

    # Check if slug already exists
    existing = sb.table("stores").select("id").eq("slug", slug).execute()
    if existing.data:
        slug = slug + "-" + secrets.token_hex(3)

    # Provision AWS resources
    try:
        bucket, iam_user, aws_key_id, aws_secret = provision_store_aws(slug)
    except Exception as e:
        return jsonify({"error": f"AWS provisioning failed: {str(e)}"}), 500

    # Generate store API key
    api_key = generate_api_key()

    # Save to Supabase
    store = sb.table("stores").insert({
        "name": name,
        "slug": slug,
        "api_key": api_key,
        "s3_bucket": bucket,
        "iam_user": iam_user,
        "aws_access_key": aws_key_id,
        "aws_secret_key": aws_secret,
        "status": "active",
        "plan": "trial",
        "receipt_count": 0,
    }).execute()

    return jsonify({
        "store_id": store.data[0]["id"],
        "name": name,
        "api_key": api_key,
        "bucket": bucket,
        "region": MASTER_AWS_REGION,
        "aws_access_key_id": aws_key_id,
        "aws_secret_access_key": aws_secret,
    }), 201


# ─── Routes — Receipts ───────────────────────────────────────────────────────

@app.route("/api/receipt", methods=["POST"])
@require_api_key
def create_receipt():
    """
    Called by tapntrack_watcher.py.
    Uploads PDF to store's S3 bucket, registers receipt, returns short URL.
    Body: { "pdf_b64": "base64...", "filename": "receipt.pdf" }
    OR:   { "s3_url": "already uploaded url" }  (legacy support)
    """
    data     = request.get_json()
    store    = g.store
    sb       = get_supabase()

    # Support both direct upload and pre-uploaded S3 URL
    if data.get("s3_url"):
        s3_url = data["s3_url"]
    elif data.get("pdf_b64") and data.get("filename"):
        import base64
        import boto3 as _boto3
        pdf_bytes   = base64.b64decode(data["pdf_b64"])
        filename    = data["filename"]
        timestamp   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        s3_key      = f"receipts/{timestamp}_{filename}"

        s3 = _boto3.client("s3",
            region_name=MASTER_AWS_REGION,
            aws_access_key_id=store["aws_access_key"],
            aws_secret_access_key=store["aws_secret_key"]
        )
        s3.put_object(
            Bucket=store["s3_bucket"],
            Key=s3_key,
            Body=pdf_bytes,
            ContentType="application/pdf"
        )
        s3_url = s3.generate_presigned_url("get_object",
            Params={"Bucket": store["s3_bucket"], "Key": s3_key},
            ExpiresIn=EXPIRY_HOURS * 3600
        )
    else:
        return jsonify({"error": "Missing pdf_b64+filename or s3_url"}), 400

    # Generate unique short code
    for _ in range(10):
        code = generate_code()
        existing = sb.table("receipts").select("id").eq("code", code).execute()
        if not existing.data:
            break

    now     = datetime.utcnow()
    expires = now + timedelta(hours=EXPIRY_HOURS)

    sb.table("receipts").insert({
        "store_id":   store["id"],
        "code":       code,
        "s3_url":     s3_url,
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "tapped":     0
    }).execute()

    # Increment store receipt count
    sb.table("stores").update({
        "receipt_count": store["receipt_count"] + 1,
        "last_active": now.isoformat()
    }).eq("id", store["id"]).execute()

    short_url = f"{BASE_URL}/r/{code}"
    return jsonify({"url": short_url, "code": code}), 201


# ─── Routes — Receipt Page ───────────────────────────────────────────────────

@app.route("/r/<code>")
def receipt_page(code):
    sb  = get_supabase()
    row = sb.table("receipts").select("*").eq("code", code).execute()

    if not row.data:
        abort(404)

    receipt = row.data[0]
    expires = datetime.fromisoformat(receipt["expires_at"].replace("Z", ""))

    if datetime.utcnow() > expires:
        return render_template("expired.html"), 410

    # Track tap
    sb.table("receipts").update({
        "tapped": receipt["tapped"] + 1
    }).eq("code", code).execute()

    # Get store info for branding
    store = sb.table("stores").select("name").eq("id", receipt["store_id"]).execute()
    store_name = store.data[0]["name"] if store.data else "Store"

    return render_template("receipt.html",
        code=code,
        s3_url=receipt["s3_url"],
        store_name=store_name,
        created=receipt["created_at"][:16].replace("T", " ")
    )


# ─── Admin — Login ───────────────────────────────────────────────────────────

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        hashed   = hash_password(password)
        app.logger.info(f"Login attempt: user='{username}' hash='{hashed}'")

        sb = get_supabase()
        result = sb.table("admin_users").select("*") \
            .eq("username", username) \
            .eq("password_hash", hashed) \
            .execute()
        app.logger.info(f"Query result count: {len(result.data)}")

        if result.data:
            session["admin"] = username
            return redirect(url_for("admin_dashboard"))
        else:
            error = "Invalid username or password"

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


# ─── Admin — Dashboard ───────────────────────────────────────────────────────

@app.route("/admin/dashboard")
@require_admin
def admin_dashboard():
    sb     = get_supabase()
    stores = sb.table("stores").select("*").order("created_at", desc=True).execute()
    return render_template("admin_dashboard.html",
        stores=stores.data,
        admin=session.get("admin")
    )


@app.route("/admin/store/<store_id>")
@require_admin
def admin_store_detail(store_id):
    sb       = get_supabase()
    store    = sb.table("stores").select("*").eq("id", store_id).execute()
    receipts = sb.table("receipts").select("*").eq("store_id", store_id) \
                 .order("created_at", desc=True).limit(20).execute()

    if not store.data:
        abort(404)

    return render_template("admin_store.html",
        store=store.data[0],
        receipts=receipts.data,
        admin=session.get("admin")
    )


@app.route("/admin/store/<store_id>/toggle", methods=["POST"])
@require_admin
def admin_toggle_store(store_id):
    sb    = get_supabase()
    store = sb.table("stores").select("status").eq("id", store_id).execute()
    if not store.data:
        abort(404)

    new_status = "suspended" if store.data[0]["status"] == "active" else "active"
    sb.table("stores").update({"status": new_status}).eq("id", store_id).execute()
    return redirect(url_for("admin_dashboard"))


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
