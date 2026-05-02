import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify, redirect, render_template_string, request, url_for
from werkzeug.security import generate_password_hash

DEFAULT_PORT = 5005
DEFAULT_REPO_URL = "https://github.com/tatiosen/demo-server"
DEFAULT_PROJECT_REPO_URL = "https://github.com/rusyaew/ztbrowser"
DEFAULT_WORKLOAD_ID = "ztbrowser-aws-nitro"
DEFAULT_MODULE_ID = "i-demo-instance-enc-demo"
DEFAULT_OCI_IMAGE_DIGEST = (
    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)
DEFAULT_NSM_ATTESTOR_BIN = "nsm-attestor"
DEFAULT_COCO_CONFIG_PATH = "/app/coco-runtime-config.json"
ATTESTED_RESPONSE_VERSION = "zt-attested-response/v1"
NITRO_PLATFORM = "aws_nitro_eif"
COCO_PLATFORM = "aws_coco_snp"

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
RUNTIME_MODE = os.environ.get("RUNTIME_MODE", "").strip().lower()
COCO_RUNTIME_CONFIG_PATH = os.environ.get("COCO_RUNTIME_CONFIG_PATH", DEFAULT_COCO_CONFIG_PATH)

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


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


RESPONSE_SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def response_public_jwk() -> dict:
    numbers = RESPONSE_SIGNING_KEY.public_key().public_numbers()
    size = 32
    return {
        "crv": "P-256",
        "ext": True,
        "key_ops": ["verify"],
        "kty": "EC",
        "x": b64url(numbers.x.to_bytes(size, "big")),
        "y": b64url(numbers.y.to_bytes(size, "big")),
    }


def response_key_id(public_jwk: dict | None = None) -> str:
    jwk = public_jwk or response_public_jwk()
    return "sha256:" + b64url(hashlib.sha256(canonical_json(jwk).encode()).digest())


def response_key_binding_hash(
    nonce: str,
    key_id: str,
    public_jwk: dict,
    service: str,
    release_id: str,
    platform: str,
    algorithm: str,
) -> str:
    context = {
        "key_id": key_id,
        "platform": platform,
        "public_jwk": public_jwk,
        "release_id": release_id,
        "service": service,
        "nonce": nonce,
        "version": ATTESTED_RESPONSE_VERSION,
    }
    data = canonical_json(context).encode()
    return (hashlib.sha512(data) if algorithm == "sha512" else hashlib.sha256(data)).hexdigest()


def content_digest(body: bytes) -> str:
    return f"sha-256=:{b64(hashlib.sha256(body).digest())}:"


def normalize_content_type(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def signed_response_headers(
    *,
    body: bytes,
    method: str,
    path: str,
    status: int,
    content_type: str,
    challenge: str,
    service: str,
    release_id: str,
    platform: str,
) -> dict[str, str]:
    key_id = response_key_id()
    digest = content_digest(body)
    signed_at = int(time.time() * 1000)
    payload = {
        "challenge": challenge,
        "content_digest": digest,
        "content_type": normalize_content_type(content_type),
        "key_id": key_id,
        "method": method.upper(),
        "path": path,
        "platform": platform,
        "release_id": release_id,
        "service": service,
        "signed_at": signed_at,
        "status": int(status),
        "version": ATTESTED_RESPONSE_VERSION,
    }
    der_signature = RESPONSE_SIGNING_KEY.sign(
        canonical_json(payload).encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = utils.decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        "X-ZT-Signature-Version": ATTESTED_RESPONSE_VERSION,
        "X-ZT-Key-Id": key_id,
        "X-ZT-Content-Digest": digest,
        "X-ZT-Signature": b64url(raw_signature),
        "X-ZT-Signed-At": str(signed_at),
        "X-ZT-Challenge": challenge,
    }


def signed_response_wire(headers: dict[str, str]) -> dict:
    return {
        "version": headers["X-ZT-Signature-Version"],
        "key_id": headers["X-ZT-Key-Id"],
        "content_digest": headers["X-ZT-Content-Digest"],
        "signature": headers["X-ZT-Signature"],
        "signed_at": int(headers["X-ZT-Signed-At"]),
        "challenge": headers["X-ZT-Challenge"],
    }


def release_id() -> str:
    return os.environ.get("RELEASE_ID") or os.environ.get("RELEASE_TAG") or WORKLOAD_ID


def service_name() -> str:
    return os.environ.get("SERVICE") or "demo-server"


def current_platform() -> str:
    return COCO_PLATFORM if RUNTIME_MODE == "coco_http" or os.environ.get("COCO_HTTP_MODE") == "1" else NITRO_PLATFORM


def runtime_identity() -> tuple[str, str, str]:
    platform = current_platform()
    if platform == COCO_PLATFORM:
        try:
            config = load_coco_config()
            return (
                str(config.get("service") or service_name()),
                str(config.get("release_id") or release_id()),
                str(config.get("platform") or platform),
            )
        except Exception:
            return service_name(), release_id(), platform
    return service_name(), release_id(), platform


def build_nitro_attestation_doc(nonce: str, public_jwk: dict, binding: str) -> str:
    nonce_bytes = parse_nonce_to_bytes(nonce)
    public_key_b64 = b64(canonical_json(public_jwk).encode())
    try:
        completed = subprocess.run(
            [NSM_ATTESTOR_BIN, nonce_bytes.hex(), public_key_b64, binding],
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


def build_attestation_doc(nonce: str, public_jwk: dict, binding: str) -> str:
    if ATTESTATION_SOURCE == "nitro":
        return build_nitro_attestation_doc(nonce, public_jwk, binding)

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
            "public_key": canonical_json(public_jwk).encode(),
            "user_data": bytes.fromhex(binding),
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


def load_coco_config() -> dict:
    with open(COCO_RUNTIME_CONFIG_PATH, "r", encoding="utf-8") as config_file:
        return json.load(config_file)


def fetch_coco_aa_evidence(aa_evidence_url: str, runtime_data_hex: str) -> object:
    parsed = urlparse(aa_evidence_url)
    if parsed.scheme != "http":
        raise RuntimeError("only http:// AA evidence URLs are supported")
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key != "runtime_data"
    ]
    query.append(("runtime_data", runtime_data_hex))
    url = urlunparse(parsed._replace(query=urlencode(query)))
    request_obj = Request(url, headers={"Accept": "application/json"})
    with urlopen(request_obj, timeout=10) as response:
        return json.loads(response.read().decode())


def build_attestation_envelope(
    nonce: str,
    platform: str | None = None,
    service_override: str | None = None,
    release_override: str | None = None,
    facts_url_override: str | None = None,
) -> dict:
    platform = platform or current_platform()
    public_jwk = response_public_jwk()
    key_id = response_key_id(public_jwk)
    service = service_override or service_name()
    rel = release_override or release_id()
    if platform == COCO_PLATFORM:
        config = load_coco_config()
        service = str(config.get("service") or service)
        rel = str(config.get("release_id") or rel)
        binding = response_key_binding_hash(
            nonce, key_id, public_jwk, service, rel, platform, "sha256"
        )
        evidence = fetch_coco_aa_evidence(
            str(config.get("aa_evidence_url") or "http://127.0.0.1:8006/aa/evidence"),
            binding,
        )
        return {
            "version": "ztinfra-attestation/v1",
            "service": service,
            "release_id": rel,
            "platform": platform,
            "nonce": nonce,
            "claims": {
                "workload_pubkey": config.get("workload_pubkey"),
                "identity_hint": config.get("identity_hint"),
                "response_signing_key": public_jwk,
                "response_signing_key_id": key_id,
                "response_signing_key_binding": binding,
            },
            "evidence": {
                "type": "coco_trustee_evidence",
                "payload": evidence,
            },
            "facts_url": facts_url_override or config.get("facts_url"),
        }

    binding = response_key_binding_hash(nonce, key_id, public_jwk, service, rel, platform, "sha256")
    doc_b64 = build_attestation_doc(nonce, public_jwk, binding)
    return {
        "version": "ztinfra-attestation/v1",
        "service": service,
        "release_id": rel,
        "platform": platform,
        "nonce": nonce,
        "claims": {
            "workload_pubkey": None,
            "identity_hint": None,
            "response_signing_key": public_jwk,
            "response_signing_key_id": key_id,
            "response_signing_key_binding": binding,
        },
        "evidence": {
            "type": "aws_nitro_attestation_doc",
            "payload": {
                "nitro_attestation_doc_b64": doc_b64,
            },
        },
        "facts_url": facts_url_override or os.environ.get("FACTS_URL", "https://facts-db.onrender.com"),
    }


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


@app.after_request
def sign_challenged_response(response):
    challenge = request.headers.get("X-ZT-Challenge", "").strip()
    if not challenge:
        return response
    response.direct_passthrough = False
    body = response.get_data()
    path = request.full_path[:-1] if request.full_path.endswith("?") else request.full_path
    service, rel, platform = runtime_identity()
    headers = signed_response_headers(
        body=body,
        method=request.method,
        path=path,
        status=response.status_code,
        content_type=response.headers.get("Content-Type", ""),
        challenge=challenge,
        service=service,
        release_id=rel,
        platform=platform,
    )
    for name, value in headers.items():
        response.headers[name] = value
    return response


@app.post("/.well-known/attestation")
def attestation():
    body = request.get_json(silent=True) or {}
    nonce = body.get("NONCE", "")
    return jsonify(build_attestation_envelope(str(nonce)))


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


def render_index_html() -> str:
    with app.app_context():
        return render_template_string(
            HTML,
            mode=MODE["value"],
            attestation_mode=ATTESTATION_MODE["value"],
        )


def vsock_response(payload: dict) -> bytes:
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def handle_vsock_request(raw_request: bytes) -> bytes:
    message = json.loads(raw_request.decode().strip())
    action = message.get("action")
    challenge = message.get("response_challenge")
    method = message.get("method") or ("POST" if action == "attestation" else "GET")
    path = message.get("path") or ("/.well-known/attestation" if action == "attestation" else "/")
    service = message.get("service") or service_name()
    rel = message.get("release_id") or release_id()
    platform = message.get("platform") or NITRO_PLATFORM
    if action == "index":
        html = render_index_html()
        response = {
            "content_type": "text/html; charset=utf-8",
            "html": html,
        }
        if challenge:
            response["signed_response"] = signed_response_wire(
                signed_response_headers(
                    body=html.encode(),
                    method=method,
                    path=path,
                    status=200,
                    content_type="text/html; charset=utf-8",
                    challenge=challenge,
                    service=service,
                    release_id=rel,
                    platform=platform,
                )
            )
        return vsock_response(response)

    if action == "attestation":
        nonce = str(message.get("nonce_hex") or "")
        envelope = build_attestation_envelope(
            nonce,
            platform,
            service_override=service,
            release_override=rel,
            facts_url_override=message.get("facts_url"),
        )
        body = json.dumps(envelope, separators=(",", ":")).encode()
        response = {
            "attestation_json": body.decode(),
        }
        if challenge:
            response["signed_response"] = signed_response_wire(
                signed_response_headers(
                    body=body,
                    method=method,
                    path=path,
                    status=200,
                    content_type="application/json",
                    challenge=challenge,
                    service=service,
                    release_id=rel,
                    platform=platform,
                )
            )
        return vsock_response(response)

    if action == "http":
        body_b64 = message.get("body_b64") or ""
        body = base64.b64decode(body_b64) if body_b64 else b""
        headers = {}
        if message.get("content_type"):
            headers["Content-Type"] = message["content_type"]
        with app.test_client() as client:
            flask_response = client.open(path=path, method=method, data=body, headers=headers)
        response_body = flask_response.get_data()
        response = {
            "status": flask_response.status_code,
            "content_type": flask_response.headers.get("Content-Type", "application/octet-stream"),
            "body_b64": b64(response_body),
        }
        if challenge:
            response["signed_response"] = signed_response_wire(
                signed_response_headers(
                    body=response_body,
                    method=method,
                    path=path,
                    status=flask_response.status_code,
                    content_type=response["content_type"],
                    challenge=challenge,
                    service=service,
                    release_id=rel,
                    platform=platform,
                )
            )
        return vsock_response(response)

    raise ValueError(f"Unsupported action: {action}")


def run_vsock_server() -> None:
    port = int(os.environ.get("VSOCK_PORT", str(DEFAULT_PORT)))
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((socket.VMADDR_CID_ANY, port))
    listener.listen()
    print(f"Micrus trusted service listening on vsock port {port}", flush=True)
    while True:
        conn, _ = listener.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            try:
                conn.sendall(handle_vsock_request(data))
            except Exception as exc:
                conn.sendall(vsock_response({"error": str(exc)}))


if __name__ == "__main__":
    if RUNTIME_MODE in ("http", "coco_http") or os.environ.get("COCO_HTTP_MODE") == "1":
        port = int(os.environ.get("PORT", str(DEFAULT_PORT)))
        debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
        app.run(host="0.0.0.0", port=port, debug=debug)
    else:
        run_vsock_server()
