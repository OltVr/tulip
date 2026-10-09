#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
import uuid

import database
from triage import triage_groups


def client_bytes(flow) -> bytes:
    return b"".join(
        item.data
        for item in flow.kind_items()
        if item.direction == "c"
    )


def flow_uuid(value) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify generated Rose Firegex rules against representative local flows."
    )
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()

    failures: list[str] = []
    with database.Pool(os.environ["TIMESCALE"]) as pool, pool.connection() as connection:
        groups = triage_groups(connection, limit=args.limit)
        attacks = [group for group in groups if group["classification"] == "attack"]
        checkers = [group for group in groups if group["classification"] == "checker"]

        rules = []
        for attack in attacks:
            rule = attack["firegex"]
            flags = 0 if rule["case_sensitive"] else re.IGNORECASE
            pattern = re.compile(rule["pattern"].encode(), flags)
            flow = connection.flow_detail(flow_uuid(attack["representative_flow_id"]))
            if flow is None or not pattern.search(client_bytes(flow)):
                failures.append(f"rule did not match attack group {attack['fingerprint']}")
            rules.append((attack["fingerprint"], pattern))

        for checker in checkers:
            flow = connection.flow_detail(flow_uuid(checker["representative_flow_id"]))
            if flow is None:
                failures.append(f"missing checker flow {checker['representative_flow_id']}")
                continue
            payload = client_bytes(flow)
            for fingerprint, pattern in rules:
                if pattern.search(payload):
                    failures.append(
                        f"attack rule {fingerprint} matched checker group {checker['fingerprint']}"
                    )

    if failures:
        print("Firegex verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Verified {len(attacks)} attack rules; no matches across {len(checkers)} checker representatives")
    return 0


if __name__ == "__main__":
    sys.exit(main())
