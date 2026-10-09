from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import dateutil.parser
from psycopg.rows import dict_row

import configurations
from data2req import convert_flow_to_http_requests
from flow2pwn import flow2pwn


HTTP_REQUEST = re.compile(
    rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/\d(?:\.\d)?",
    re.IGNORECASE,
)
HTTP_RESPONSE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})")

NORMALIZERS = (
    (re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27,}", re.IGNORECASE), "<UUID>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE), "<HEX>"),
    (re.compile(r"\b\d{4,}\b"), "<NUM>"),
    (re.compile(r"\b[A-Za-z0-9_-]{32,}\b"), "<TOKEN>"),
)

ATTACK_MARKERS = (
    (re.compile(rb"(?:\.\./|%2e%2e|/etc/passwd)", re.IGNORECASE), "path traversal"),
    (re.compile(rb"(?:union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1)", re.IGNORECASE), "SQL injection shape"),
    (re.compile(rb"(?:/bin/(?:ba)?sh|cmd=|powershell|system\s*\()", re.IGNORECASE), "command execution shape"),
    (re.compile(rb"(?:/backdoor|\batk_[A-Za-z0-9_-]*)", re.IGNORECASE), "attack-tool marker"),
    (re.compile(rb"A{48,}|\x90{16,}"), "overflow-sized repeated bytes"),
    (re.compile(rb"<script\b|javascript:", re.IGNORECASE), "script injection shape"),
)

FIREGEX_PATTERNS = {
    "path traversal": r"(?:\.\./|%2e%2e(?:%2f|/)|/etc/passwd)",
    "SQL injection shape": r"(?:union[\x20\t]+(?:all[\x20\t]+)?select|(?:'|%27)[\x20\t]*or[\x20\t]+(?:'?[0-9]+'?)[\x20\t]*=[\x20\t]*(?:'?[0-9]+'?))",
    "command execution shape": r"(?:[?&](?:cmd|exec|command)=|/bin/(?:ba)?sh|powershell(?:\.exe)?|system[\x20\t]*\()",
    "overflow-sized repeated bytes": r"(?:A{48,}|\x90{16,})",
    "script injection shape": r"(?:<script(?:[\x20\t]|>)|javascript:)",
}


def _normalise(value: str) -> str:
    result = value
    for pattern, replacement in NORMALIZERS:
        result = pattern.sub(replacement, result)
    return result[:500]


def _first_line(data: bytes) -> str:
    return data.splitlines()[0].decode("utf-8", errors="replace")[:300] if data else ""


def _summarise_flow(row: dict[str, Any]) -> dict[str, Any]:
    client_items = row.pop("client_items") or []
    server_items = row.pop("server_items") or []
    client_data = b"".join(client_items)
    server_data = b"".join(server_items)

    method = None
    path = None
    status = None
    request_preview = _first_line(client_data)
    response_preview = _first_line(server_data)

    request_match = HTTP_REQUEST.match(client_data)
    if request_match:
        method = request_match.group(1).decode("ascii", errors="replace").upper()
        path = request_match.group(2).decode("utf-8", errors="replace")

    response_match = HTTP_RESPONSE.match(server_data)
    if response_match:
        status = int(response_match.group(1))

    signature_text = "|".join(
        [
            str(row["ip_dst"]),
            str(row["port_dst"]),
            _normalise(request_preview),
            _normalise(response_preview),
        ]
    )
    fingerprint = hashlib.sha256(signature_text.encode()).hexdigest()[:16]

    attack_reasons = []
    for marker, reason in ATTACK_MARKERS:
        if marker.search(client_data):
            attack_reasons.append(reason)

    return {
        **row,
        "_client_data": client_data,
        "fingerprint": fingerprint,
        "method": method,
        "path": path,
        "status": status,
        "request_preview": request_preview,
        "response_preview": response_preview,
        "request_bytes": len(client_data),
        "response_bytes": len(server_data),
        "attack_reasons": attack_reasons,
    }


def _firegex_rule(flow: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    patterns = [FIREGEX_PATTERNS[reason] for reason in reasons if reason in FIREGEX_PATTERNS]
    client_data = flow["_client_data"]

    if "attack-tool marker" in reasons:
        if re.search(rb"(?:^|\n)atk_[A-Za-z0-9_-]{4,64}(?:\n|$)", client_data):
            patterns.append(r"(?:^|\x0a)atk_[A-Za-z0-9_-]{4,64}(?:\x0a|$)")
        if re.search(rb"/(?:backdoor)(?:\?|\s)", client_data, re.IGNORECASE):
            patterns.append(r"(?:GET|POST|PUT|PATCH)[\x20\t]+/backdoor(?:\?|[\x20\t])")

    # Preserve order while avoiding duplicate alternatives.
    patterns = list(dict.fromkeys(patterns))
    pattern = patterns[0] if len(patterns) == 1 else "(?:" + "|".join(patterns) + ")"
    specificity = "high" if any("backdoor" in value or "atk_" in value for value in patterns) else "medium"
    return {
        "pattern": pattern,
        "mode": "S",
        "case_sensitive": False,
        "engine": "PCRE2 / Firegex nfregex",
        "specificity": specificity,
        "warning": "Replay checker traffic against this rule before enabling it in production.",
    }


def triage_groups(connection, limit: int = 1000) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 2000))
    query = """
        WITH recent AS (
            SELECT f.id, f.time, f.port_src, f.port_dst, f.ip_src, f.ip_dst,
                f.duration, f.tags, f.flags, f.flagids, f.packets_count,
                f.packets_size, p.name AS pcap_name
            FROM flow AS f
            LEFT JOIN pcap AS p ON p.id = f.pcap_id
            ORDER BY f.id DESC
            LIMIT %(limit)s
        )
        SELECT recent.*, items.client_items, items.server_items
        FROM recent
        LEFT JOIN LATERAL (
            SELECT
                array_agg(fi.data ORDER BY fi.id)
                    FILTER (WHERE fi.direction = 'c' AND fi.kind = 'raw') AS client_items,
                array_agg(fi.data ORDER BY fi.id)
                    FILTER (WHERE fi.direction = 's' AND fi.kind = 'raw') AS server_items
            FROM flow_item AS fi
            WHERE fi.flow_id = recent.id
        ) AS items ON true
        ORDER BY recent.id DESC
    """

    with connection.cursor(row_factory=dict_row) as cursor:
        flows = [_summarise_flow(dict(row)) for row in cursor.execute(query, {"limit": limit})]

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        grouped[flow["fingerprint"]].append(flow)

    service_lookup = {
        (service["ip"], service["port"]): service["name"]
        for service in configurations.get_services()
    }
    tick_length_ms = int(configurations.tick_length)

    results = []
    for fingerprint, members in grouped.items():
        representative = members[0]
        timestamps = [member["time"] for member in members]
        ticks = {
            int(timestamp.timestamp() * 1000) // tick_length_ms for timestamp in timestamps
        }
        attack_reasons = sorted(
            {reason for member in members for reason in member["attack_reasons"]}
        )

        if attack_reasons:
            classification = "attack"
            confidence = min(99, 78 + len(attack_reasons) * 7)
            reasons = attack_reasons
        elif len(members) >= 3 and len(ticks) >= 2:
            classification = "checker"
            confidence = min(98, 70 + len(ticks) * 4 + min(len(members), 10))
            reasons = [
                f"stable normalized shape repeated {len(members)} times",
                f"observed across {len(ticks)} time buckets",
            ]
        else:
            classification = "unknown"
            confidence = 45 if len(members) == 1 else 58
            reasons = ["new or low-frequency normalized shape"]

        target = (str(representative["ip_dst"]), representative["port_dst"])
        includes_live_sample = any(member["pcap_name"].startswith("live://") for member in members)
        results.append(
            {
                "fingerprint": fingerprint,
                "classification": classification,
                "confidence": confidence,
                "reasons": reasons,
                "count": len(members),
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "representative_flow_id": representative["id"],
                "service": service_lookup.get(target, f"{target[0]}:{target[1]}"),
                "ip_dst": target[0],
                "port_dst": target[1],
                "method": representative["method"],
                "path": representative["path"],
                "status": representative["status"],
                "request_preview": representative["request_preview"],
                "response_preview": representative["response_preview"],
                "request_bytes": max(member["request_bytes"] for member in members),
                "response_bytes": max(member["response_bytes"] for member in members),
                "source": "live sample · redacted" if includes_live_sample else "synthetic demo",
                "firegex": _firegex_rule(representative, attack_reasons) if classification == "attack" else None,
            }
        )

    priority = {"attack": 0, "unknown": 1, "checker": 2}
    return sorted(results, key=lambda group: (priority[group["classification"]], -group["last_seen"].timestamp()))


def ingestion_health(connection) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    with connection.cursor(row_factory=dict_row) as cursor:
        row = cursor.execute(
            """
            SELECT max(time) AS last_flow_time,
                count(*) FILTER (WHERE id > fid_pack_low(%(minute_ago)s)) AS flows_last_minute
            FROM flow
            """,
            {"minute_ago": now - timedelta(minutes=1)},
        ).fetchone()

    last_flow_time = row["last_flow_time"] if row else None
    age_seconds = max(0, (now - last_flow_time).total_seconds()) if last_flow_time else None
    tick_length_ms = int(configurations.tick_length)
    start = dateutil.parser.parse(configurations.start_date)
    current_tick = int((now - start).total_seconds() * 1000 // tick_length_ms) + 1
    captured_tick = (
        int((last_flow_time - start).total_seconds() * 1000 // tick_length_ms) + 1
        if last_flow_time
        else None
    )
    stale_after = max(30, tick_length_ms / 1000 * 2)

    return {
        "status": "empty" if last_flow_time is None else ("stale" if age_seconds > stale_after else "healthy"),
        "last_flow_time": last_flow_time,
        "age_seconds": age_seconds,
        "flows_last_minute": row["flows_last_minute"] if row else 0,
        "current_tick": current_tick,
        "captured_tick": captured_tick,
        "capture_delay_ticks": current_tick - captured_tick if captured_tick is not None else None,
    }


def _service_name(flow) -> str:
    target = (str(flow.ip_dst), flow.port_dst)
    service_lookup = {
        (service["ip"], service["port"]): service["name"]
        for service in configurations.get_services()
    }
    return service_lookup.get(target, f"service-{flow.port_dst}")


def _candidate_values(client_data: bytes) -> list[dict[str, Any]]:
    candidates = []
    seen = set()
    for pattern, kind in (
        (re.compile(rb"[0-9a-fA-F]{16,}"), "hex/token"),
        (re.compile(rb"[A-Za-z0-9_-]{32,}"), "token"),
        (re.compile(rb"\b\d{4,}\b"), "number"),
    ):
        for match in pattern.finditer(client_data):
            value = match.group().decode("utf-8", errors="ignore")
            if value and value not in seen and len(set(value)) > 3:
                seen.add(value)
                candidates.append(
                    {
                        "value": value[:160],
                        "kind": kind,
                        "recommended_attack_info": bool(
                            re.search(
                                rb"(?:flag[_-]?id|username|user|token|note[_-]?id|entry[_-]?id)[^\r\n]{0,24}"
                                + re.escape(match.group()),
                                client_data,
                                re.IGNORECASE,
                            )
                        ),
                    }
                )
            if len(candidates) >= 20:
                break
        if len(candidates) >= 20:
            break
    return candidates


def attackfarm_export(flow) -> dict[str, Any]:
    is_http = "http" in flow.tags or any(HTTP_REQUEST.match(item.data) for item in flow.kind_items())
    client_data = b"".join(item.data for item in flow.kind_items() if item.direction == "c")
    candidates = _candidate_values(client_data)
    candidate_tokens = [candidate["value"] for candidate in candidates]
    service_name = _service_name(flow)
    code = (
        convert_flow_to_http_requests(
            flow,
            service_name=service_name,
            candidates=candidate_tokens,
        )
        if is_http
        else flow2pwn(
            flow,
            service_name=service_name,
            candidates=candidate_tokens,
        )
    )
    safe_service_name = re.sub(r"[^A-Za-z0-9_-]+", "_", service_name).strip("_") or "service"

    return {
        "filename": f"rose_{safe_service_name}_{'http' if is_http else 'tcp'}.py",
        "protocol": "http" if is_http else "tcp",
        "port": flow.port_dst,
        "service": service_name,
        "runtime": "ecsc2026ad + requests" if is_http else "ecsc2026ad + pwntools",
        "code": code,
        "candidates": candidates,
        "variables": [
            {"name": "ECSC_API / --api", "purpose": "attack.json endpoint override"},
            {"name": "ECSC_SERVICE / --service", "purpose": "exact service key"},
            {"name": "ECSC_TEAM / --team", "purpose": "one team ID, IP, or name"},
            {"name": "ECSC_ROUND / --round", "purpose": "round number; -1 means newest"},
            {"name": "TARGET_HOST / --host", "purpose": "single-target mode without attack.json"},
            {"name": "TARGET_FLAG_ID / --flag-id", "purpose": "single-target dynamic flag ID"},
            {"name": "TARGET_EXTRA / --extra-json", "purpose": "arbitrary JSON available as target.extra"},
            {"name": "ATTACK_WORKERS / --workers", "purpose": "bounded parallelism"},
            {"name": "ATTACK_TIMEOUT / --timeout", "purpose": "per-request timeout"},
            {"name": "FLAG_REGEX", "purpose": "override flag extraction regex"},
        ],
        "context_fields": [
            {"name": "target.host / port / service", "purpose": "resolved victim endpoint"},
            {"name": "target.team_id / team_name", "purpose": "victim identity from attack.json"},
            {"name": "target.flag_id", "purpose": "current flattened attack-info value"},
            {"name": "target.flag_id_path", "purpose": "raw round/store path for that value"},
            {"name": "target.attack_round / flag_store", "purpose": "ECSC round and flag-store hints"},
            {"name": "target.raw_flag_ids", "purpose": "unmodified nested IDs for the team"},
            {"name": "target.requested_round", "purpose": "selected round or None for all valid rounds"},
            {"name": "target.current_round", "purpose": "current game round"},
            {"name": "target.current_round_start / current_round_until", "purpose": "round timing from raw attack.json"},
            {"name": "target.flag_regex", "purpose": "competition-provided flag pattern"},
            {"name": "target.extra / timeout", "purpose": "custom JSON and per-target timeout"},
        ],
    }
