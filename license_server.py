"""
JMTWEAKS lifetime license server.

Flow:
  Stripe Checkout -> checkout.session.completed webhook -> generate unique key
  -> store in SQLite -> email key to buyer (if SMTP is configured)
  JMTWEAKS.exe -> POST /verify -> tier returned when key is valid.

Run locally:
  pip install -r requirements-server.txt
  set STRIPE_SECRET_KEY=sk_test_...
  set STRIPE_WEBHOOK_SECRET=whsec_...
  set STRIPE_PRO_PRICE_ID=price_...
  python license_server.py

For production, deploy this service over HTTPS and set JMTWEAKS_LICENSE_API_URL
in the Windows app to the public API URL.
"""

import os
import secrets
import sqlite3
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timezone
from flask import Flask, jsonify, request
import stripe

app = Flask(__name__)
DB_PATH = os.environ.get("JMTWEAKS_DB_PATH", "licenses.db")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRO_PRICE_ID = os.environ.get("STRIPE_PRO_PRICE_ID", "")

stripe.api_key = STRIPE_SECRET_KEY

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            tier TEXT NOT NULL,
            stripe_session_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    return conn

def generate_key():
    while True:
        key = "JMT-PRO-" + "-".join(
            "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(5))
            for _ in range(3)
        )
        with db() as conn:
            if not conn.execute("SELECT 1 FROM licenses WHERE license_key=?", (key,)).fetchone():
                return key

def send_license_email(email, key):
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("FROM_EMAIL", user or "")
    if not all([host, user, password, sender, email]):
        app.logger.warning("SMTP not configured; license generated but email was not sent.")
        return False

    msg = EmailMessage()
    msg["Subject"] = "Your JMTWEAKS Pro lifetime license"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        "Thanks for purchasing JMTWEAKS Pro!\n\n"
        f"Your lifetime license key is:\n\n{key}\n\n"
        "Open JMTWEAKS, go to the Pricing/License area, enter the key, and click Activate.\n\n"
        "Keep this key private."
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.starttls(context=context)
        smtp.login(user, password)
        smtp.send_message(msg)
    return True

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "JMTWEAKS licensing"})

@app.post("/verify")
def verify():
    body = request.get_json(silent=True) or {}
    key = str(body.get("license_key", "")).strip().upper()
    if not key:
        return jsonify({"valid": False}), 400
    with db() as conn:
        row = conn.execute(
            "SELECT tier, revoked FROM licenses WHERE license_key=?", (key,)
        ).fetchone()
    if not row or row["revoked"]:
        return jsonify({"valid": False})
    return jsonify({"valid": True, "tier": row["tier"], "license_type": "lifetime"})

@app.post("/stripe/webhook")
def stripe_webhook():
    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")
    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "STRIPE_WEBHOOK_SECRET is not configured"}), 500
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify({"error": f"Invalid webhook: {e}"}), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        session_id = session["id"]
        customer_email = (
            (session.get("customer_details") or {}).get("email")
            or session.get("customer_email")
            or ""
        ).strip()

        # Confirm this was the Pro price.
        price_id = None
        try:
            full = stripe.checkout.Session.retrieve(
                session_id, expand=["line_items.data.price"]
            )
            items = full.get("line_items", {}).get("data", [])
            if items:
                price_id = (items[0].get("price") or {}).get("id")
        except Exception as e:
            app.logger.exception("Could not retrieve line items: %s", e)

        if STRIPE_PRO_PRICE_ID and price_id != STRIPE_PRO_PRICE_ID:
            return jsonify({"received": True, "ignored": "unknown price"})

        with db() as conn:
            existing = conn.execute(
                "SELECT license_key FROM licenses WHERE stripe_session_id=?",
                (session_id,),
            ).fetchone()
            if existing:
                return jsonify({"received": True, "license_key": existing["license_key"]})

            if not customer_email:
                return jsonify({"error": "Stripe checkout has no customer email"}), 400

            key = generate_key()
            conn.execute(
                """INSERT INTO licenses
                   (license_key,email,tier,stripe_session_id,created_at)
                   VALUES (?,?,?,?,?)""",
                (key, customer_email, "PRO", session_id,
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()

        try:
            sent = send_license_email(customer_email, key)
        except Exception:
            app.logger.exception("License email failed")
            sent = False

        return jsonify({"received": True, "license_created": True, "email_sent": sent})

    return jsonify({"received": True})

if __name__ == "__main__":
    db().close()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
