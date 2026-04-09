# micrus

Canonical source repository for the measured enclave workload used by ZTBrowser.

This repo builds the `micrus` Python attestation demo service into the enclave image and owns its reproducible release process. It does not own the parent proxy, browser extension, checker, or facts node.

## What Lives Here

- [`src/server.py`](/Users/tati/tanyaserver/src/server.py): the `micrus` service. It returns enclave-produced HTML for `{"action":"index"}` and a demo Nitro-shaped attestation document for `{"action":"attestation","nonce_hex":"..."}`.
- [`scripts/build-enclave.sh`](/Users/tati/tanyaserver/scripts/build-enclave.sh): builds the Docker image, then produces `ztbrowser-enclave.eif` and `describe-eif.json` with `nitro-cli`.
- [`tools/generate_provenance.py`](/Users/tati/tanyaserver/tools/generate_provenance.py): generates the canonical `provenance.json`.
- [`tools/rebuild-verify.sh`](/Users/tati/tanyaserver/tools/rebuild-verify.sh): reruns the public rebuild flow and compares the resulting provenance against a published release.
- [`tools/render_facts_row.py`](/Users/tati/tanyaserver/tools/render_facts_row.py) and [`tools/upsert_facts_db.py`](/Users/tati/tanyaserver/tools/upsert_facts_db.py): prepare and publish the facts-node update consumed by `ztbrowser`.

## Release Contract

Canonical releases publish:

- `ztbrowser-enclave.eif`
- `describe-eif.json`
- `provenance.json`
- `SHA256SUMS`

`ztbrowser` consumes those release artifacts directly for real AWS deploys.

## Local Build Prerequisites

- Linux host
- Docker
- `nitro-cli` installed on `PATH`
- Rust toolchain available on the host if you want to run the rebuild verifier locally

Build locally:

```bash
scripts/build-enclave.sh
```

That produces:

- `build/ztbrowser-enclave.eif`
- `build/describe-eif.json`

## Rebuild Verification

Rebuild and compare against a published release manifest:

```bash
tools/rebuild-verify.sh \
  --repo-url https://github.com/rusyaew/ztinfra-enclaveproducedhtml \
  --ref v0.1.0 \
  --expected-provenance-url https://github.com/rusyaew/ztinfra-enclaveproducedhtml/releases/download/v0.1.0/provenance.json
```

The verifier clones the target repo, rebuilds the enclave artifacts, regenerates provenance, and compares the critical measured fields.

## GitHub Workflows

- [release-enclave.yml](/Users/tati/tanyaserver/.github/workflows/release-enclave.yml) builds the canonical EIF release, publishes release assets, generates `SHA256SUMS`, and opens a PR against `rusyaew/ztbrowser` to update facts.
- [rebuild-verify.yml](/Users/tati/tanyaserver/.github/workflows/rebuild-verify.yml) reruns the public rebuild flow from `repo_url + ref + provenance_url` and uploads the comparison output as a workflow artifact.

Required secret for the release workflow:

- `ZTINFRA_FACTS_PR_TOKEN`: token with permission to push a branch and open a PR against `rusyaew/ztbrowser`

## Local Service Run

For local development of the service itself:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 src/server.py
```

The service listens on `VSOCK_PORT`, then `PORT`, otherwise `5005`.

## Run In Docker Without An Enclave

You can run `micrus` as a normal container without AWS Nitro Enclaves.

This uses the Flask app in [`src/server.py`](/Users/tati/tanyaserver/src/server.py) directly and does not require EIF build or enclave runtime.

```bash
docker build -t micrus .
docker run --rm -p 5005:5005 -e PORT=5005 -e ATTESTATION_SOURCE=demo micrus
```

Then open:

```text
http://localhost:5005
```

Notes:

- `ATTESTATION_SOURCE=demo` works in a normal container.
- `ATTESTATION_SOURCE=nitro` requires a real Nitro Enclave with `/dev/nsm` available and the `nsm-attestor` helper binary on `PATH` or configured via `NSM_ATTESTOR_BIN`.
- This container flow is for local development and UI testing, not for producing canonical enclave release artifacts.

## Current Scope

- `ATTESTATION_SOURCE=demo` generates a demo Nitro-shaped attestation document using demo certificates or in-memory generated certificates.
- `ATTESTATION_SOURCE=nitro` shells out to the Rust `nsm-attestor` helper, which requests a real attestation document from NSM. This path only works inside a Nitro Enclave.
