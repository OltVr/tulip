#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
import uuid

import database
from triage import ATTACK_MARKERS, _firegex_rule, triage_groups


ATTACK_SAMPLES = {
    "path traversal": b"GET /download?name=..%2f..%2fetc/passwd HTTP/1.1\r\n\r\n",
    "SQL injection shape": b"POST /login HTTP/1.1\r\n\r\nuser=x' OR 1=1--",
    "command execution shape": b"GET /admin?cmd=id HTTP/1.1\r\n\r\n",
    "attack-tool marker": b"GET /backdoor?username=0123456789abcdef0123456789abcdef HTTP/1.1\r\n\r\n",
    "overflow-sized repeated bytes": b"1\nuser\npass\n" + b"A" * 64 + b"\n",
    "script injection shape": b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n",
    "template injection shape": b"GET /hello?name={{config.__class__}} HTTP/1.1\r\n\r\n",
    "XXE shape": b'POST /xml HTTP/1.1\r\n\r\n<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
    "unsafe deserialization shape": b"POST /load HTTP/1.1\r\n\r\n\xac\xed\x00\x05payload",
    "NoSQL injection shape": b'POST /login HTTP/1.1\r\n\r\n{"user":{"$ne":null}}',
    "prototype pollution shape": b'POST /merge HTTP/1.1\r\n\r\n{"__proto__":{"admin":true}}',
    "SSRF shape": b"GET /fetch?url=http://169.254.169.254/latest/meta-data HTTP/1.1\r\n\r\n",
    "CRLF injection shape": b"GET /jump?to=x%0d%0aLocation:%20https://evil.invalid HTTP/1.1\r\n\r\n",
    "HTTP request smuggling shape": b"POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "sensitive file probe": b"GET /.git/config HTTP/1.1\r\n\r\n",
}

BENIGN_SAMPLES = (
    b"GET /health?nonce=0123456789abcdef HTTP/1.1\r\nHost: service\r\n\r\n",
    b"GET /profile/alice HTTP/1.1\r\nHost: service\r\n\r\n",
    b'POST /render HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"message":"hello {{name}}"}',
    b"POST /upload HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata",
    b"2\nchecker_user\nnormal-note-value\n",
)


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

    marker_lookup = {reason: marker for marker, reason in ATTACK_MARKERS}
    for reason, sample in ATTACK_SAMPLES.items():
        marker = marker_lookup.get(reason)
        if marker is None or not marker.search(sample):
            failures.append(f"detector did not match synthetic {reason} sample")
            continue
        rule = _firegex_rule({"_client_data": sample}, [reason])
        flags = 0 if rule["case_sensitive"] else re.IGNORECASE
        if not re.compile(rule["pattern"].encode(), flags).search(sample):
            failures.append(f"Firegex rule did not match synthetic {reason} sample")

    for sample_number, sample in enumerate(BENIGN_SAMPLES, start=1):
        for marker, reason in ATTACK_MARKERS:
            if marker.search(sample):
                failures.append(f"{reason} detector matched benign sample {sample_number}")

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

    print(
        f"Verified {len(ATTACK_SAMPLES)} attack families and {len(attacks)} generated rules; "
        f"no matches across {len(BENIGN_SAMPLES)} benign samples and {len(checkers)} checker representatives"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
