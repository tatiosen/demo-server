#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--provenance', required=True)
    args = parser.parse_args()
    provenance = json.loads(Path(args.provenance).read_text())
    row = {
        'workload_id': provenance['workload_id'],
        'repo_url': provenance['repo_url'],
        'project_repo_url': provenance['project_repo_url'],
        'oci_image_digest': provenance['oci_image_digest'],
        'pcr0': provenance['pcr0'],
        'pcr1': provenance['pcr1'],
        'pcr2': provenance['pcr2'],
        'pcr8': provenance.get('pcr8'),
        'nitro_cli_version': provenance['nitro_cli_version'],
        'build_timestamp': provenance['build_timestamp'],
        'last_updated': provenance['build_timestamp'],
        'release_tag': provenance['release_tag'],
        'commit_sha': provenance['commit_sha'],
        'eif_sha256': provenance['eif_sha256'],
        'describe_eif_sha256': provenance['describe_eif_sha256'],
        'release_url': provenance['release_url'],
        'canonical': True,
        'notes': f"Canonical facts row for {provenance['release_tag']} from {provenance['repo_url']}"
    }
    print(json.dumps(row, indent=2))


if __name__ == '__main__':
    main()
