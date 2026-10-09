from __future__ import annotations

from textwrap import indent


def render_ecsc_exploit(
    *,
    service: str,
    port: int,
    protocol: str,
    candidates: list[str],
    attack_info_tokens: list[str] | None,
    imports: str,
    exploit_body: str,
) -> str:
    """Wrap captured traffic in a small ECSC 2026 and AttackFarm runner."""
    dependency = "pwntools" if protocol == "tcp" else "requests"
    return f'''#!/usr/bin/env python3
"""Rose-generated {protocol.upper()} replay.

Install: pip install ecsc2026ad {dependency}
Run without arguments during ECSC, or use --host for one target/AttackFarm.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

from ecsc2026ad import EcscApiSync

{imports.strip()}

SERVICE = {service!r}
PORT = {port}
DEFAULT_FLAG_REGEX = r"ECSC\{{[A-Za-z0-9_-]{{32}}\}}"

# Rose found these changing values in the captured request.
CANDIDATE_TOKENS = {candidates!r}
# Likely checker-provided attack-info values are replaced automatically.
# Review this list before farming; add or remove captured values if necessary.
ATTACK_INFO_TOKENS = {attack_info_tokens or []!r}


def materialize(value, flag_id):
    if not flag_id:
        return value
    if isinstance(value, bytes):
        for captured in ATTACK_INFO_TOKENS:
            value = value.replace(captured.encode(), flag_id.encode())
    elif isinstance(value, str):
        for captured in ATTACK_INFO_TOKENS:
            value = value.replace(captured, flag_id)
    elif isinstance(value, list):
        value = [materialize(item, flag_id) for item in value]
    elif isinstance(value, dict):
        value = {{key: materialize(item, flag_id) for key, item in value.items()}}
    return value


def exploit(host, port, flag_id, timeout):
{indent(exploit_body.strip(), "    ")}


def resolve_targets(args):
    if args.host:
        return [(args.host, args.flag_id)], None

    with EcscApiSync(args.api) as ecsc:
        info = ecsc.attack_info()
        if not info.has_service(args.service):
            available = ", ".join(sorted(info.services))
            raise RuntimeError(f"unknown service {{args.service!r}}; available: {{available}}")

        targets = []
        for team in info.teams:
            if team.id == 1:  # NOP earns no attack points.
                continue
            flag_ids = (
                info.flag_ids(args.service, team)
                if args.round is None
                else info.flag_ids(args.service, team, args.round)
            )
            targets.extend((team.ip, flag_id) for flag_id in flag_ids)
        return list(dict.fromkeys(targets)), info.flag_regex


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.getenv("TARGET_HOST") or os.getenv("XFARM_HOST") or os.getenv("TARGET_IP"))
    parser.add_argument("--flag-id", default=os.getenv("TARGET_FLAG_ID"))
    parser.add_argument("--service", default=os.getenv("ECSC_SERVICE", SERVICE))
    parser.add_argument("--round", type=int, default=None, help="one round; default is every valid round")
    parser.add_argument("--api", default=os.getenv("ECSC_API", ""), help="scoreboard URL; normally unnecessary")
    parser.add_argument("--port", type=int, default=int(os.getenv("TARGET_PORT", PORT)))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("ATTACK_TIMEOUT", "5")))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    return args


def main():
    args = parse_args()
    try:
        targets, game_flag_regex = resolve_targets(args)
    except Exception as error:
        print(f"target lookup failed: {{error}}", file=sys.stderr)
        return 2

    pattern_text = os.getenv("FLAG_REGEX") or game_flag_regex or DEFAULT_FLAG_REGEX
    pattern_text = pattern_text.removeprefix("^").removesuffix("$")
    flag_pattern = re.compile(pattern_text.encode())
    found = set()

    for host, flag_id in targets:
        try:
            output = exploit(host, args.port, flag_id, args.timeout)
            if isinstance(output, str):
                output = output.encode()
            flags = list(dict.fromkeys(flag_pattern.findall(output)))
            for flag in flags:
                if flag not in found:
                    found.add(flag)
                    print(flag.decode())
            print(f"[{{host}} flag_id={{flag_id!r}}] {{len(flags)}} flags", file=sys.stderr)
        except Exception as error:
            print(f"[{{host}} flag_id={{flag_id!r}}] {{error}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
