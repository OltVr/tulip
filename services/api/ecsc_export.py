from __future__ import annotations

from textwrap import indent


def render_ecsc_exploit(
    *,
    service: str,
    port: int,
    protocol: str,
    candidates: list[str],
    imports: str,
    exploit_body: str,
) -> str:
    """Wrap a captured request sequence in an ECSC 2026-compatible runner."""
    return f'''#!/usr/bin/env python3
"""Rose-generated {protocol.upper()} replay for ECSC 2026 A/D.

Install: pip install ecsc2026ad {"pwntools" if protocol == "tcp" else "requests"}
The default run attacks every team for every currently valid attack-info value.
Use --host for a single-target replay without the ECSC package.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Any

{imports.strip()}

DEFAULT_SERVICE = {service!r}
DEFAULT_PORT = {port}
DEFAULT_FLAG_REGEX = r"ECSC\{{[A-Za-z0-9_-]{{32}}\}}"

# Values Rose noticed in the captured request. Keep this list for reference.
CANDIDATE_TOKENS = {candidates!r}
# Copy only values that represent checker-provided attack info into this list.
# Every occurrence will be replaced by target.flag_id at replay time.
ATTACK_INFO_TOKENS: list[str] = []


@dataclass(frozen=True)
class AttackTarget:
    host: str
    port: int
    service: str
    team_id: int | None = None
    team_name: str | None = None
    flag_id: str | None = None
    flag_id_path: list[str | int] | None = None
    attack_round: int | None = None
    flag_store: str | int | None = None
    raw_flag_ids: Any = None
    requested_round: int | None = None
    current_round: int | None = None
    current_round_start: float | None = None
    current_round_until: float | None = None
    flag_regex: str | None = None
    extra: Any = None
    timeout: float = 5.0


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.lower() in {{"1", "true", "yes", "on"}}


def materialize(value: Any, target: AttackTarget) -> Any:
    """Replace selected captured values with this target's attack-info value."""
    if target.flag_id is None:
        return value
    if isinstance(value, bytes):
        result = value
        for captured in ATTACK_INFO_TOKENS:
            result = result.replace(captured.encode(), target.flag_id.encode())
        return result
    if isinstance(value, str):
        result = value
        for captured in ATTACK_INFO_TOKENS:
            result = result.replace(captured, target.flag_id)
        return result
    if isinstance(value, list):
        return [materialize(item, target) for item in value]
    if isinstance(value, tuple):
        return tuple(materialize(item, target) for item in value)
    if isinstance(value, dict):
        return {{materialize(key, target): materialize(item, target) for key, item in value.items()}}
    return value


def flag_id_contexts(value: Any, path: tuple[str | int, ...] = ()) -> list[tuple[str, list[str | int]]]:
    """Keep the round/store path that AttackInfo.flag_ids() intentionally flattens."""
    if value is None:
        return []
    if isinstance(value, str):
        return [(value, list(path))]
    if isinstance(value, list):
        return [item for index, child in enumerate(value) for item in flag_id_contexts(child, path + (index,))]
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in flag_id_contexts(child, path + (key,))]
    return [(str(value), list(path))]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.getenv("TARGET_HOST") or os.getenv("XFARM_HOST") or os.getenv("TARGET_IP"), help="single target; skips attack.json")
    parser.add_argument("--port", type=int, default=int(os.getenv("TARGET_PORT", str(DEFAULT_PORT))))
    parser.add_argument("--service", default=os.getenv("ECSC_SERVICE", DEFAULT_SERVICE), help="exact attack.json service name")
    parser.add_argument("--team", default=os.getenv("ECSC_TEAM"), help="one team by ID, IP, or name")
    parser.add_argument("--round", type=int, default=int(os.environ["ECSC_ROUND"]) if os.getenv("ECSC_ROUND") else None, help="round number; -1 is newest; default is every published valid round")
    parser.add_argument("--api", default=os.getenv("ECSC_API", ""), help="scoreboard host/base URL; package default is ECSC 2026")
    parser.add_argument("--flag-id", default=os.getenv("TARGET_FLAG_ID"), help="attack-info value for --host mode")
    parser.add_argument("--timeout", type=float, default=float(os.getenv("ATTACK_TIMEOUT", "5")))
    parser.add_argument("--workers", type=int, default=int(os.getenv("ATTACK_WORKERS", "8")))
    parser.add_argument("--extra-json", default=os.getenv("TARGET_EXTRA", "[]"), help="JSON exposed as target.extra")
    parser.add_argument("--exclude-team", action="append", default=[value for value in os.getenv("ECSC_EXCLUDE_TEAMS", "").split(",") if value])
    parser.add_argument("--include-nop", action="store_true", default=env_bool("ECSC_INCLUDE_NOP"))
    parser.add_argument("--allow-blind", action="store_true", default=env_bool("ECSC_ALLOW_BLIND"), help="attack teams with no published flag IDs")
    parser.add_argument("--dry-run", action="store_true", help="print resolved target contexts as JSON")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if args.workers <= 0:
        parser.error("workers must be positive")
    try:
        args.extra = json.loads(args.extra_json)
    except json.JSONDecodeError as error:
        parser.error(f"invalid --extra-json: {{error}}")
    return args


def resolve_targets(args: argparse.Namespace) -> list[AttackTarget]:
    if args.host:
        return [AttackTarget(args.host, args.port, args.service, flag_id=args.flag_id, requested_round=args.round, extra=args.extra, timeout=args.timeout)]

    try:
        from ecsc2026ad import EcscApiSync
    except ImportError as error:
        raise RuntimeError("install the ECSC client with: pip install ecsc2026ad") from error

    with EcscApiSync(args.api) as ecsc:
        info = ecsc.attack_info()
        try:
            attack_json = json.loads(info.raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            attack_json = {{}}
        if not info.has_service(args.service):
            available = ", ".join(sorted(info.services))
            raise RuntimeError(f"unknown service {{args.service!r}}; attack.json contains: {{available}}")
        if args.team:
            selected = info.team(args.team)
            if selected is None:
                raise RuntimeError(f"team {{args.team!r}} is not present in attack.json")
            teams = [selected]
        else:
            teams = info.teams

        targets: list[AttackTarget] = []
        excluded = {{value.lower() for value in args.exclude_team}}
        for team in teams:
            if team.id == 1 and not args.include_nop:
                continue
            if any(value in excluded for value in (str(team.id).lower(), team.ip.lower(), (team.name or "").lower())):
                continue
            raw = info.flag_ids_raw(args.service, team, args.round)
            contexts = flag_id_contexts(raw)
            contexts = list(dict.fromkeys((flag_id, tuple(path)) for flag_id, path in contexts))
            if not contexts and args.allow_blind:
                contexts = [(None, ())]
            for flag_id, flag_id_path in contexts:
                attack_round = (
                    int(flag_id_path[0])
                    if flag_id_path and str(flag_id_path[0]).lstrip("-").isdigit()
                    else None
                )
                targets.append(AttackTarget(
                    host=team.ip,
                    port=args.port,
                    service=args.service,
                    team_id=team.id,
                    team_name=team.name,
                    flag_id=flag_id,
                    flag_id_path=list(flag_id_path),
                    attack_round=attack_round,
                    flag_store=flag_id_path[1] if len(flag_id_path) > 1 else None,
                    raw_flag_ids=raw,
                    requested_round=args.round,
                    current_round=info.current_round,
                    current_round_start=attack_json.get("current_round_start"),
                    current_round_until=attack_json.get("current_round_until"),
                    flag_regex=info.flag_regex,
                    extra=args.extra,
                    timeout=args.timeout,
                ))
        return targets


def exploit(target: AttackTarget) -> bytes:
{indent(exploit_body.strip(), "    ")}


def run_target(target: AttackTarget, flag_pattern: re.Pattern[bytes]) -> tuple[AttackTarget, list[bytes], int]:
    output = exploit(target)
    if isinstance(output, str):
        output = output.encode()
    flags = list(dict.fromkeys(flag_pattern.findall(output)))
    return target, flags, len(output)


def main() -> int:
    args = parse_args()
    try:
        targets = resolve_targets(args)
    except Exception as error:
        print(f"target resolution failed: {{error}}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(json.dumps([asdict(target) for target in targets], indent=2, default=str))
        return 0
    if not targets:
        print("no targets resolved; check --service/--round or use --allow-blind", file=sys.stderr)
        return 0

    attack_info_regex = next((target.flag_regex for target in targets if target.flag_regex), None)
    flag_pattern = re.compile((os.getenv("FLAG_REGEX") or attack_info_regex or DEFAULT_FLAG_REGEX).encode())
    found: set[bytes] = set()
    with ThreadPoolExecutor(max_workers=min(args.workers, len(targets))) as executor:
        futures = {{executor.submit(run_target, target, flag_pattern): target for target in targets}}
        for future in as_completed(futures):
            target = futures[future]
            try:
                _, flags, size = future.result()
            except Exception as error:
                print(f"[{{target.host}} team={{target.team_id}} flag_id={{target.flag_id!r}}] {{error}}", file=sys.stderr)
                continue
            for flag in flags:
                if flag not in found:
                    found.add(flag)
                    print(flag.decode())
            print(f"[{{target.host}} team={{target.team_id}} flag_id={{target.flag_id!r}}] {{size}} bytes, {{len(flags)}} flags", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
