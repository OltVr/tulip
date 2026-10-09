#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg


DATABASE_URL = os.environ["TIMESCALE"]
PCAP_NAME = "demo://defender-triage"
LIVE_PCAP_NAME = "live://2.31.24.56/redacted-2026-10-04"


def connect():
    for attempt in range(60):
        try:
            return psycopg.connect(DATABASE_URL)
        except psycopg.OperationalError:
            if attempt == 59:
                raise
            time.sleep(1)


def token(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:32]


def fid(cursor, timestamp: datetime):
    return cursor.execute("SELECT fid_create(%s)", (timestamp,)).fetchone()[0]


def insert_flow(cursor, pcap_id, *, timestamp, port, client, server, http=True):
    flow_id = fid(cursor, timestamp)
    tags = ["tcp"] + (["http"] if http else [])
    duration = timedelta(milliseconds=120 if http else 420)
    cursor.execute(
        """
        INSERT INTO flow (
            id, port_src, port_dst, ip_src, ip_dst, duration, tags, flags,
            flagids, pcap_id, fingerprints, packets_count, packets_size,
            flags_in, flags_out
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s::jsonb, '[]'::jsonb,
            '[]'::jsonb, %s, '{}', %s, %s, 0, 0
        )
        """,
        (
            flow_id,
            30000 + port % 1000,
            port,
            "10.60.41.254",
            "10.60.41.2",
            duration,
            json.dumps(tags),
            pcap_id,
            4,
            len(client) + len(server),
        ),
    )

    items = (("c", client, timestamp), ("s", server, timestamp + duration))
    for direction, data, item_time in items:
        cursor.execute(
            """
            INSERT INTO flow_item (id, flow_id, kind, direction, data)
            VALUES (%s, %s, 'raw', %s, %s)
            """,
            (fid(cursor, item_time), flow_id, direction, data),
        )

    searchable = (client + b"\n" + server).decode("utf-8", errors="ignore")
    cursor.execute(
        "INSERT INTO flow_index (flow_id, text) VALUES (%s, %s)",
        (flow_id, searchable),
    )


def main():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with connect() as connection, connection.cursor() as cursor:
        old_pcaps = cursor.execute(
            "SELECT id FROM pcap WHERE name = ANY(%s)", ([PCAP_NAME, LIVE_PCAP_NAME],)
        ).fetchall()
        for (old_id,) in old_pcaps:
            cursor.execute(
                "DELETE FROM flow_index WHERE flow_id IN (SELECT id FROM flow WHERE pcap_id = %s)",
                (old_id,),
            )
            cursor.execute(
                "DELETE FROM flow_item WHERE flow_id IN (SELECT id FROM flow WHERE pcap_id = %s)",
                (old_id,),
            )
            cursor.execute("DELETE FROM flow WHERE pcap_id = %s", (old_id,))
            cursor.execute("DELETE FROM pcap WHERE id = %s", (old_id,))

        pcap_id = uuid.uuid4()
        cursor.execute(
            "INSERT INTO pcap (id, name, position) VALUES (%s, %s, 0)",
            (pcap_id, PCAP_NAME),
        )
        live_pcap_id = uuid.uuid4()
        cursor.execute(
            "INSERT INTO pcap (id, name, position) VALUES (%s, %s, 0)",
            (live_pcap_id, LIVE_PCAP_NAME),
        )

        for tick in range(6):
            base = now - timedelta(minutes=6 - tick)
            nonce = token(f"nonce-{tick}")
            profile = token(f"profile-{tick}")

            insert_flow(
                cursor,
                pcap_id,
                timestamp=base,
                port=9000,
                client=f"GET /health?nonce={nonce} HTTP/1.1\r\nHost: fireworx\r\n\r\n".encode(),
                server=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
            )
            insert_flow(
                cursor,
                pcap_id,
                timestamp=base + timedelta(seconds=4),
                port=9200,
                client=f"GET /profile/{profile} HTTP/1.1\r\nHost: fastvuln\r\n\r\n".encode(),
                server=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"role\":\"user\"}",
            )
            insert_flow(
                cursor,
                pcap_id,
                timestamp=base + timedelta(seconds=8),
                port=9300,
                client=b"GET /status HTTP/1.1\r\nHost: stldoctor\r\n\r\n",
                server=b"HTTP/1.1 200 OK\r\n\r\nhealthy",
            )
            insert_flow(
                cursor,
                pcap_id,
                timestamp=base + timedelta(seconds=12),
                port=9100,
                client=f"2\nchecker_{nonce[:12]}\n{nonce}\n".encode(),
                server=b"Welcome to Bambi-Notes!\nLogin successful\n> ",
                http=False,
            )

        insert_flow(
            cursor,
            pcap_id,
            timestamp=now - timedelta(seconds=38),
            port=9200,
            client=b"GET /admin?cmd=cat+/flag HTTP/1.1\r\nHost: fastvuln\r\n\r\n",
            server=b"HTTP/1.1 403 Forbidden\r\n\r\nblocked",
        )
        insert_flow(
            cursor,
            pcap_id,
            timestamp=now - timedelta(seconds=31),
            port=9100,
            client=b"1\natk_deadbeefcafe\npassword\n1\n5\n" + b"A" * 96 + b"\n",
            server=b"Welcome to Bambi-Notes!\nWhich slot?\nNote [5]\n> ",
            http=False,
        )
        insert_flow(
            cursor,
            pcap_id,
            timestamp=now - timedelta(seconds=24),
            port=9000,
            client=b"POST /login HTTP/1.1\r\nHost: fireworx\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=' OR 1=1 --&password=x",
            server=b"HTTP/1.1 401 Unauthorized\r\n\r\nnope",
        )
        insert_flow(
            cursor,
            pcap_id,
            timestamp=now - timedelta(seconds=15),
            port=9300,
            client=b"HEAD /experimental HTTP/1.1\r\nHost: stldoctor\r\n\r\n",
            server=b"HTTP/1.1 404 Not Found\r\n\r\n",
        )

        # Redacted request shapes sampled read-only from the authorized live Tulip.
        # Dynamic usernames/passwords are regenerated; no flags or credentials are retained.
        for sample in range(6):
            username = token(f"live-backdoor-{sample}")
            insert_flow(
                cursor,
                live_pcap_id,
                timestamp=now - timedelta(seconds=12 + sample * 3),
                port=9200,
                client=(
                    f"GET /backdoor?username={username} HTTP/1.1\r\n"
                    "Host: 10.60.41.2:9200\r\n"
                    "Accept: */*\r\n"
                    "X-Ctfroute-Proxied: true\r\n\r\n"
                ).encode(),
                server=b"",
            )

        for sample in range(3):
            username = f"atk_{token(f'live-atk-{sample}')[:12]}"
            password = token(f"live-password-{sample}")
            overflow = b"A" * 64 + token(f"live-suffix-{sample}")[:16].encode()
            insert_flow(
                cursor,
                live_pcap_id,
                timestamp=now - timedelta(seconds=34 + sample * 4),
                port=9100,
                client=(
                    b"1\n"
                    + username.encode()
                    + b"\n"
                    + password.encode()
                    + b"\n1\n5\n"
                    + overflow
                    + b"\n"
                ),
                server=(
                    b"Welcome to Bambi-Notes!\nUsername: > Password: > "
                    b"Registration successful!\nWhich slot to save the note into? > Note [5] > "
                ),
                http=False,
            )

    print("Seeded 37 Rose demo flows (28 synthetic, 9 redacted live samples)")


if __name__ == "__main__":
    main()
