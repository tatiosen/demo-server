import base64
import hashlib
import json
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
            "sha512",
        )
        self.assertEqual(len(nitro), 64)
        self.assertEqual(len(coco), 128)

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
