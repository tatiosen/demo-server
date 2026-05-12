import base64
import hashlib
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from src import server


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class ResponseSigningTests(unittest.TestCase):
    def setUp(self) -> None:
        server.ATTESTATION_MODE["value"] = "valid"
        server.MODE["value"] = "verified"
        self._submit_log = tempfile.NamedTemporaryFile(delete=False)
        self._submit_log.close()
        server.SUBMIT_LOG = self._submit_log.name
        with open(server.SUBMIT_LOG, "w", encoding="utf-8") as submit_log:
            json.dump([], submit_log)

    def tearDown(self) -> None:
        if os.path.exists(self._submit_log.name):
            os.unlink(self._submit_log.name)

    def test_key_id_and_binding_hashes_are_well_formed(self) -> None:
        jwk = server.response_public_jwk()
        key_id = server.response_key_id(jwk)
        self.assertTrue(key_id.startswith("sha256:"))
        self.assertEqual(
            key_id,
            "sha256:" + server.b64url(hashlib.sha256(server.canonical_json(jwk).encode()).digest()),
        )
        nitro = server.response_key_binding_hash(
            "ab" * 32,
            key_id,
            jwk,
            "demo-server",
            "v0.1.0",
            server.NITRO_PLATFORM,
            "sha256",
        )
        coco = server.response_key_binding_hash(
            "ab" * 32,
            key_id,
            jwk,
            "demo-server",
            "v0.1.0",
            server.COCO_PLATFORM,
            "sha256",
        )
        self.assertEqual(len(nitro), 64)
        self.assertEqual(len(coco), 64)

    def test_challenged_landing_page_is_signed(self) -> None:
        challenge = "cd" * 32
        client = server.app.test_client()
        response = client.get("/", headers={"X-ZT-Challenge": challenge})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-ZT-Signature-Version"], server.ATTESTED_RESPONSE_VERSION)
        self.assertEqual(response.headers["X-ZT-Challenge"], challenge)

        digest = "sha-256=:" + base64.b64encode(hashlib.sha256(response.data).digest()).decode() + ":"
        self.assertEqual(response.headers["X-ZT-Content-Digest"], digest)

        payload = {
            "challenge": challenge,
            "content_digest": digest,
            "content_type": "text/html",
            "key_id": response.headers["X-ZT-Key-Id"],
            "method": "GET",
            "path": "/",
            "platform": server.NITRO_PLATFORM,
            "release_id": server.release_id(),
            "service": server.service_name(),
            "signed_at": int(response.headers["X-ZT-Signed-At"]),
            "status": 200,
            "version": server.ATTESTED_RESPONSE_VERSION,
        }
        signature = b64url_decode(response.headers["X-ZT-Signature"])
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64url_decode(server.response_public_jwk()["x"]), "big"),
            int.from_bytes(b64url_decode(server.response_public_jwk()["y"]), "big"),
            ec.SECP256R1(),
        )
        public_numbers.public_key().verify(
            utils.encode_dss_signature(r, s),
            server.canonical_json(payload).encode(),
            ec.ECDSA(hashes.SHA256()),
        )

    def test_attestation_envelope_declares_response_key(self) -> None:
        nonce = "01" * 32
        envelope = server.build_attestation_envelope(nonce, server.NITRO_PLATFORM)
        claims = envelope["claims"]
        self.assertEqual(envelope["version"], "ztinfra-attestation/v1")
        self.assertEqual(envelope["nonce"], nonce)
        self.assertEqual(envelope["evidence"]["type"], "aws_nitro_attestation_doc")
        self.assertEqual(claims["response_signing_key_id"], server.response_key_id(claims["response_signing_key"]))
        self.assertEqual(len(claims["response_signing_key_binding"]), 64)
        self.assertEqual(json.loads(claims["workload_pubkey"])["kty"], "EC")
        self.assertEqual(claims["trusted_input_service"]["version"], "ztbrowser-trusted-inputs/v1")
        self.assertEqual(
            claims["trusted_input_service"]["profiles"][0]["submit"]["url"],
            "http://localhost:9999/v1/submit",
        )

    def test_landing_page_contains_trusted_input_manifest_and_fields(self) -> None:
        client = server.app.test_client()
        response = client.get("/", base_url="http://demo.example")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('type="application/ztbrowser-trusted-inputs+json"', html)
        self.assertIn('data-ztf-group="demo-group"', html)
        self.assertIn('data-ztf-field="secret"', html)
        self.assertIn('data-zts-group="demo-group"', html)
        self.assertIn("http://demo.example/.well-known/attestation", html)

    def test_attestation_route_uses_request_origin_for_trusted_input_claim(self) -> None:
        client = server.app.test_client()
        response = client.post(
            "/.well-known/attestation",
            json={"NONCE": "02" * 32},
            base_url="http://demo.example",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        claim = payload["claims"]["trusted_input_service"]
        self.assertEqual(claim["endpoint_origin"], "http://demo.example")
        self.assertIn("http://demo.example", claim["allowed_page_origins"])
        self.assertEqual(claim["profiles"][0]["submit"]["url"], "http://demo.example/v1/submit")
        self.assertIn("http://localhost", claim["allowed_page_origins"])
        self.assertIn("http://127.0.0.1", claim["allowed_page_origins"])
        self.assertNotIn("http://localhost:80", claim["allowed_page_origins"])
        self.assertNotIn("http://127.0.0.1:80", claim["allowed_page_origins"])

    def test_secure_submit_plaintext_fallback_redacts_values(self) -> None:
        client = server.app.test_client()
        response = client.post(
            "/v1/submit",
            json={"secret": "hunter2", "username": "alice"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["ok"], True)
        with open(server.SUBMIT_LOG, "r", encoding="utf-8") as submit_log:
            entries = json.load(submit_log)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["encrypted"], False)
        self.assertEqual(entries[0]["fields"], {"secret": "[redacted]"})
        self.assertEqual(entries[0]["username"], "alice")
        self.assertEqual(entries[0]["password_length"], 7)

    def test_vsock_http_action_runs_app_inside_trusted_process(self) -> None:
        challenge = "ef" * 32
        response = json.loads(
            server.handle_vsock_request(
                json.dumps(
                    {
                        "action": "http",
                        "method": "GET",
                        "path": "/records",
                        "response_challenge": challenge,
                        "service": "demo-server",
                        "release_id": "v0.1.0",
                        "platform": server.NITRO_PLATFORM,
                    }
                ).encode()
                + b"\n"
            )
        )
        self.assertEqual(response["status"], 200)
        self.assertIn("text/html", response["content_type"])
        self.assertEqual(response["signed_response"]["challenge"], challenge)
        self.assertEqual(response["signed_response"]["version"], server.ATTESTED_RESPONSE_VERSION)


if __name__ == "__main__":
    unittest.main()
