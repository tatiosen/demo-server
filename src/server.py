import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify, redirect, render_template_string, request, url_for
from werkzeug.security import generate_password_hash

DEFAULT_PORT = 5005
DEFAULT_REPO_URL = "https://github.com/rusyaew/micrus"
DEFAULT_PROJECT_REPO_URL = "https://github.com/rusyaew/ztbrowser"
DEFAULT_WORKLOAD_ID = "ztbrowser-aws-nitro"
DEFAULT_MODULE_ID = "i-demo-instance-enc-demo"
DEFAULT_OCI_IMAGE_DIGEST = (
    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)
DEFAULT_NSM_ATTESTOR_BIN = "nsm-attestor"

app = Flask(__name__)

MODE = {"value": "unset"}
ATTESTATION_SOURCE = os.environ.get("ATTESTATION_SOURCE", "demo").strip().lower()
ATTESTATION_MODE = {"value": os.environ.get("ATTESTATION_MODE", "tampered").strip().lower()}
DB_FILE = os.environ.get("DB_FILE", "password_store.json")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_PKI_DIR = os.path.join(BASE_DIR, "..", "fixtures", "demo-pki")
ROOT_CERT_PATH = os.environ.get("DEMO_ROOT_CERT_PATH", os.path.join(DEMO_PKI_DIR, "root-cert.pem"))
LEAF_CERT_PATH = os.environ.get("DEMO_LEAF_CERT_PATH", os.path.join(DEMO_PKI_DIR, "leaf-cert.pem"))
LEAF_KEY_PATH = os.environ.get("DEMO_LEAF_KEY_PATH", os.path.join(DEMO_PKI_DIR, "leaf-key.pem"))

REPO_URL = os.environ.get("REPO_URL", DEFAULT_REPO_URL)
PROJECT_REPO_URL = os.environ.get("PROJECT_REPO_URL", DEFAULT_PROJECT_REPO_URL)
WORKLOAD_ID = os.environ.get("WORKLOAD_ID", DEFAULT_WORKLOAD_ID)
MODULE_ID = os.environ.get("MODULE_ID", DEFAULT_MODULE_ID)
OCI_IMAGE_DIGEST = os.environ.get("OCI_IMAGE_DIGEST", DEFAULT_OCI_IMAGE_DIGEST)
NSM_ATTESTOR_BIN = os.environ.get("NSM_ATTESTOR_BIN", DEFAULT_NSM_ATTESTOR_BIN)

if ATTESTATION_SOURCE not in ("demo", "nitro"):
    ATTESTATION_SOURCE = "demo"

if ATTESTATION_MODE["value"] not in ("valid", "tampered"):
    ATTESTATION_MODE["value"] = "tampered"


def normalize_pcr_hex(value: str, fallback_byte: str) -> str:
    clean = re.sub(r"^0x", "", value, flags=re.IGNORECASE).lower()
    if re.fullmatch(r"[0-9a-f]{96}", clean):
        return clean
    return fallback_byte * 96


PCRS = {
    "pcr0": normalize_pcr_hex(os.environ.get("PCR0", ""), "0"),
    "pcr1": normalize_pcr_hex(os.environ.get("PCR1", ""), "0"),
    "pcr2": normalize_pcr_hex(os.environ.get("PCR2", ""), "0"),
    "pcr8": normalize_pcr_hex(os.environ.get("PCR8", ""), "0"),
}


def pem_to_der(pem_text: str) -> bytes:
    stripped = re.sub(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+", "", pem_text)
    return base64.b64decode(stripped)


def load_demo_cert_material() -> dict:
    if all(os.path.exists(path) for path in (ROOT_CERT_PATH, LEAF_CERT_PATH, LEAF_KEY_PATH)):
        with open(ROOT_CERT_PATH, "r", encoding="utf-8") as root_file:
            root_cert_pem = root_file.read()
        with open(LEAF_CERT_PATH, "r", encoding="utf-8") as leaf_file:
            leaf_cert_pem = leaf_file.read()
        with open(LEAF_KEY_PATH, "r", encoding="utf-8") as key_file:
            leaf_key_pem = key_file.read()
        return {
            "root_cert_der": pem_to_der(root_cert_pem),
            "leaf_cert_der": pem_to_der(leaf_cert_pem),
            "leaf_private_key": serialization.load_pem_private_key(leaf_key_pem.encode(), password=None),
        }
    return generate_demo_cert_material()


def generate_demo_cert_material() -> dict:
    now = datetime.utcnow()
    not_valid_before = now - timedelta(minutes=1)
    not_valid_after_root = now + timedelta(days=3650)
    not_valid_after_leaf = now + timedelta(days=730)

    root_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())

    root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Micrus Demo Root CA")])
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Micrus Demo Leaf")])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after_root)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA384())
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(root_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after_leaf)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA384())
    )

    return {
        "root_cert_der": root_cert.public_bytes(serialization.Encoding.DER),
        "leaf_cert_der": leaf_cert.public_bytes(serialization.Encoding.DER),
        "leaf_private_key": leaf_key,
    }


CERT_MATERIAL = load_demo_cert_material()
ROOT_CERT_DER = CERT_MATERIAL["root_cert_der"]
LEAF_CERT_DER = CERT_MATERIAL["leaf_cert_der"]
LEAF_PRIVATE_KEY = CERT_MATERIAL["leaf_private_key"]


def parse_nonce_to_bytes(nonce: str) -> bytes:
    clean = (nonce or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]+", clean) and len(clean) % 2 == 0:
        return bytes.fromhex(clean)
    return hashlib.sha256(clean.encode()).digest()


def build_nitro_attestation_doc(nonce: str) -> str:
    nonce_bytes = parse_nonce_to_bytes(nonce)
    try:
        completed = subprocess.run(
            [NSM_ATTESTOR_BIN, nonce_bytes.hex()],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"NSM attestor binary not found: {NSM_ATTESTOR_BIN}. "
            "Set NSM_ATTESTOR_BIN to the compiled helper path."
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(f"NSM attestation failed: {stderr or exc}") from exc

    doc_b64 = completed.stdout.strip()
    if not doc_b64:
        raise RuntimeError("NSM attestation helper returned an empty document")
    return doc_b64


def build_attestation_doc(nonce: str) -> str:
    if ATTESTATION_SOURCE == "nitro":
        return build_nitro_attestation_doc(nonce)

    nonce_bytes = parse_nonce_to_bytes(nonce)
    payload = cbor2.dumps(
        {
            "module_id": MODULE_ID,
            "digest": "SHA384",
            "timestamp": int(time.time() * 1000),
            "pcrs": {
                0: bytes.fromhex(PCRS["pcr0"]),
                1: bytes.fromhex(PCRS["pcr1"]),
                2: bytes.fromhex(PCRS["pcr2"]),
                8: bytes.fromhex(PCRS["pcr8"]),
            },
            "certificate": LEAF_CERT_DER,
            "cabundle": [ROOT_CERT_DER],
            "public_key": None,
            "user_data": None,
            "nonce": nonce_bytes,
        },
        canonical=True,
    )

    protected_header = cbor2.dumps({1: -35}, canonical=True)
    sig_structure = cbor2.dumps(["Signature1", protected_header, b"", payload], canonical=True)
    signature = LEAF_PRIVATE_KEY.sign(sig_structure, ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(signature)
    key_size = (LEAF_PRIVATE_KEY.key_size + 7) // 8
    raw_signature = r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")
    cose_doc = cbor2.dumps([protected_header, {}, payload, raw_signature], canonical=True)

    if ATTESTATION_MODE["value"] == "tampered":
        tampered = bytearray(cose_doc)
        tampered[-1] = tampered[-1] ^ 0xFF
        return base64.b64encode(bytes(tampered)).decode()
    return base64.b64encode(cose_doc).decode()


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
                verified
            </button>
            <button onclick="setMode('unverified')"
                class="mode unverified {{ 'active' if mode == 'unverified' else '' }}">
                unverified
            </button>
        </div>
    </div>

    <div class="small">Attestation endpoint: <code>POST /.well-known/attestation</code></div>
    <div class="small">Page mode: <code>{{ mode }}</code></div>
    <div class="small">Attestation mode: <code>{{ attestation_mode }}</code></div>

    <form id="form" method="POST" action="/register">
        <input
            type="text"
            id="usernameField"
            name="username"
            class="input-neutral"
            placeholder="Enter username"
            style="margin-bottom: 10px;"
        >
        <input
            type="password"
            id="passwordField"
            name="secret"
            class="input-neutral"
            placeholder="Enter password for registration"
        >
        <div class="row" style="margin-top: 10px;">
            <button type="submit" id="submitBtn">Register</button>
            <a href="/records">View stored records</a>
        </div>
    </form>

    <div class="small" id="hint"></div>

<script>
function setMode(mode) {
    window.location.href = "/set-mode?mode=" + mode;
}

document.getElementById("form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const usernameField = document.getElementById("usernameField");
    const field = document.getElementById("passwordField");
    const hint = document.getElementById("hint");

    hint.textContent = "";
    usernameField.classList.remove("input-bad");
    usernameField.classList.add("input-neutral");
    field.classList.remove("input-bad");
    field.classList.add("input-neutral");

    const formData = new FormData(e.target);

    const res = await fetch("/register", {
        method: "POST",
        body: formData
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
        usernameField.classList.remove("input-neutral");
        usernameField.classList.add("input-bad");
        field.classList.remove("input-neutral");
        field.classList.add("input-bad");
        hint.textContent = data.error || "Registration failed";
        return;
    }

    usernameField.value = "";
    field.value = "";
    hint.textContent = data.message || "Registered successfully";
});
</script>
</body>
</html>
"""


def load_records() -> list:
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r", encoding="utf-8") as records_file:
        return json.load(records_file)


def save_records(records: list) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as records_file:
        json.dump(records, records_file, indent=2)


@app.get("/")
def index():
    return render_template_string(
        HTML,
        mode=MODE["value"],
        attestation_mode=ATTESTATION_MODE["value"],
    )


@app.get("/set-mode")
def set_mode():
    mode = (request.args.get("mode") or "").lower()
    if mode in ("verified", "unverified"):
        MODE["value"] = mode
        ATTESTATION_MODE["value"] = "valid" if mode == "verified" else "tampered"
    return redirect(url_for("index"))


@app.post("/.well-known/attestation")
def attestation():
    body = request.get_json(silent=True) or {}
    nonce = body.get("NONCE", "")
    doc_b64 = build_attestation_doc(nonce)
    return jsonify(
        {
            "platform": "aws_nitro_eif",
            "nonce": nonce,
            "workload": {
                "workload_id": WORKLOAD_ID,
                "repo_url": REPO_URL,
                "project_repo_url": PROJECT_REPO_URL,
                "oci_image_digest": OCI_IMAGE_DIGEST,
                "eif_pcrs": PCRS,
            },
            "evidence": {
                "nitro_attestation_doc_b64": doc_b64,
            },
        }
    )


@app.post("/register")
def register():
    if MODE["value"] != "verified":
        return jsonify({"ok": False, "error": "Server is not in verified mode."}), 403

    username = request.form.get("username", "").strip()
    secret = request.form.get("secret", "").strip()
    if not username:
        return jsonify({"ok": False, "error": "Username is empty."}), 400
    if not secret:
        return jsonify({"ok": False, "error": "Password is empty."}), 400

    records = load_records()
    if any(record.get("username", "").lower() == username.lower() for record in records):
        return jsonify({"ok": False, "error": "Username already exists."}), 409

    password_hash = generate_password_hash(secret)
    session_token = secrets.token_urlsafe(32)
    session_token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    records.append(
        {
            "username": username,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "password_hash": password_hash,
            "password_length": len(secret),
            "session_token_hash": session_token_hash,
        }
    )
    save_records(records)

    return jsonify(
        {
            "ok": True,
            "message": "Registered and stored as hash only.",
            "session_token": session_token,
        }
    )


@app.get("/records")
def records():
    return f"""
    <h2>Stored registration records</h2>
    <p>Usernames and password hashes are stored. Plaintext passwords are never saved.</p>
    <pre>{json.dumps(load_records(), indent=2)}</pre>
    <p><a href="/">Back</a></p>
    """


if __name__ == "__main__":
    port = int(os.environ.get("PORT", str(DEFAULT_PORT)))
    debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
    app.run(host="0.0.0.0", port=port, debug=debug)
