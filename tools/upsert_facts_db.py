#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--facts-db', required=True)
    parser.add_argument('--facts-row', required=True)
    args = parser.parse_args()

    db_path = Path(args.facts_db)
    row = json.loads(Path(args.facts_row).read_text())
    rows = json.loads(db_path.read_text())

    updated = False
    for index, existing in enumerate(rows):
        if existing.get('workload_id') == row['workload_id']:
            rows[index] = row
            updated = True
            break
    if not updated:
        rows.append(row)

    db_path.write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
