from flask import Flask, jsonify, request, redirect, url_for, render_template_string
from werkzeug.security import generate_password_hash
import json
import os
from datetime import datetime

app = Flask(__name__)

MODE = {"value": "verified"}
DB_FILE = "password_store.json"

HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Trusted Compute Demo</title>
    <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 16px; }
    .card { border: 1px solid white; border-radius: 12px; padding: 16px; margin-top: 16px; }
    input { padding: 10px; width: 100%; border-radius: 10px; border: 1px solid #ccc; }
    button { padding: 10px 14px; border-radius: 10px; border: 0; cursor: pointer; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 6px; }
    .small { color: #666; font-size: 13px; }
    h1 { color: purple; }
    #hint { color: black; font-weight: 600; margin-top: 10px; }
    .mode {
        padding: 10px 16px;
        border-radius: 10px;
        font-weight: bold;
        cursor: pointer;
        background: #f2f2f2;
    }
    .mode.verified { border: 2px solid #4CAF50; color: #4CAF50; }
    .mode.unverified { border: 2px solid #f44336; color: #f44336; }
    .mode.verified.active { background: #4CAF50; color: white; }
    .mode.unverified.active { background: #f44336; color: white; }
    .row { display: flex; gap: 10px; align-items: center; }
    .input-neutral { border: 2px solid #ccc !important; }
    .input-bad { border: 2px solid #f44336 !important; }
    pre {
        background: #f8f8f8;
        padding: 12px;
        border-radius: 10px;
        overflow-x: auto;
    }
    </style>
</head>
<body>
    <div class="row">
        <h1>Attestation Demo Server</h1>
        <div class="card">
            <button onclick="setMode('verified')"
                class="mode verified {{ 'active' if mode == 'verified' else '' }}">
                ✅
            </button>
            <button onclick="setMode('unverified')"
                class="mode unverified {{ 'active' if mode == 'unverified' else '' }}">
                ❌
            </button>
        </div>
    </div>

    <div class="small">Attestation endpoint: <code>/.well-known/attestation</code></div>

    <form id="form" method="POST" action="/submit">
        <input
            type="password"
            id="passwordField"
            name="secret"
            class="input-neutral"
            placeholder="Enter password"
        >
        <div class="row" style="margin-top: 10px;">
            <button type="submit" id="submitBtn">Submit</button>
            <a href="/records">View stored records</a>
        </div>
    </form>

    <div class="small" id="hint"></div>

<script>
function setMode(mode) {
    window.location.href = "/set-mode?mode=" + mode;
}

let attestationVerified = false;

async function checkAttestation() {
    try {
        const res = await fetch("/.well-known/attestation", { cache: "no-store" });
        const data = await res.json().catch(() => ({}));
        attestationVerified = res.ok && data.status === "verified";
    } catch (e) {
        attestationVerified = false;
    }
}

document.getElementById("form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const field = document.getElementById("passwordField");
    const hint = document.getElementById("hint");

    hint.textContent = "";
    field.classList.remove("input-bad");
    field.classList.add("input-neutral");

    await checkAttestation();

    if (!attestationVerified) {
        field.classList.remove("input-neutral");
        field.classList.add("input-bad");
        hint.textContent = "Site not verified";
        return;
    }

    const formData = new FormData(e.target);

    const res = await fetch("/submit", {
        method: "POST",
        body: formData
    });

    const data = await res.json().catch(() => ({}));
    field.value = "";   
});

checkAttestation();
</script>
</body>
</html>
"""

def load_records():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_records(records):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

@app.get("/")
def index():
    return render_template_string(HTML, mode=MODE["value"])

@app.get("/set-mode")
def set_mode():
    m = (request.args.get("mode") or "").lower()
    if m in ("verified", "unverified", "tampered"):
        MODE["value"] = m
    return redirect(url_for("index"))

@app.get("/.well-known/attestation")
def attestation():
    m = MODE["value"]
    if m == "verified":
        return jsonify({"status": "verified", "evidence": {"mock": True, "provider": "demo"}})
    if m == "tampered":
        return jsonify({"status": "unverified", "reason": "measurement_mismatch"}), 400
    return jsonify({"status": "unverified", "reason": "no_trusted_compute"}), 400

@app.post("/submit")
def submit():
    if MODE["value"] != "verified":
        return jsonify({"ok": False, "error": "Server not verified. Rejected."}), 403

    secret = request.form.get("secret", "").strip()
    if not secret:
        return jsonify({"ok": False, "error": "Password is empty."}), 400

    password_hash = generate_password_hash(secret)

    records = load_records()
    records.append({
        "created_at": datetime.utcnow().isoformat() + "Z",
        "password_hash": password_hash,
        "password_length": len(secret)
    })
    save_records(records)

    return jsonify({
        "ok": True,
        "message": "Accepted and stored as hash only."
    })

@app.get("/records")
def records():
    data = load_records()
    return f"""
    <h2>Stored password records</h2>
    <p>Only hashes are stored. Plaintext passwords are never saved.</p>
    <pre>{json.dumps(data, indent=2)}</pre>
    <p><a href="/">Back</a></p>
    """

if __name__ == "__main__":
    app.run(port=3000, debug=True)
