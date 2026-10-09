# Rose defender demo

This profile starts only TimescaleDB, the API, and the Rose frontend. It binds
the UI to localhost and inserts 28 synthetic flows plus 9 redacted request
shapes sampled from the authorized live competition viewer. No live flags,
passwords, or authentication material are retained.

```sh
docker compose --env-file .env.demo \
  -f docker-compose.yml -f docker-compose.demo.yml \
  up -d --build timescale api frontend

docker compose --env-file .env.demo \
  -f docker-compose.yml -f docker-compose.demo.yml \
  run --rm demo-seed
```

Open <http://127.0.0.1:3300>. Rerunning `demo-seed` replaces only the
`demo://defender-triage` capture, leaving imported PCAP data untouched.

## ECSC replay exports

Open **Traffic intelligence** and choose **Export exploit** on a flow. Rose
generates a standalone Python 3.10+ replay with two execution modes:

- ECSC mode uses `ecsc2026ad` to read `/api/attack.json`, skips NOP by
  default, preserves raw per-round/flag-store IDs, and attacks every published
  valid ID. HTTP exports use `requests`; TCP exports use `pwntools`.
- Single-target mode uses `--host`, `TARGET_HOST`, `XFARM_HOST`, or
  `TARGET_IP`, so the same file runs under ExploitFarm. Flags are the only
  values written to stdout; target diagnostics go to stderr.

Install the generated script's dependencies with one of:

```sh
pip install ecsc2026ad requests
pip install ecsc2026ad pwntools
```

The export panel lists every supported override. The most useful are
`ECSC_API`, `ECSC_SERVICE`, `ECSC_TEAM`, `ECSC_ROUND` (`-1` selects the newest
published round), `TARGET_FLAG_ID`, `TARGET_EXTRA`, `ATTACK_WORKERS`,
`ATTACK_TIMEOUT`, and `FLAG_REGEX`. Run with `--dry-run` to inspect resolved
target contexts without sending traffic. Each context exposes the team ID and
name, selected flag ID, its raw path, attack round, flag store, nested raw IDs,
current-round timing, competition flag regex, and custom `target.extra` data.

Captured values are listed in `CANDIDATE_TOKENS`. Copy only values known to be
checker-provided attack info into `ATTACK_INFO_TOKENS`; Rose replaces those
values recursively in paths, headers, bodies, and TCP payloads with the
current `target.flag_id`.

Verify the generated Firegex rules against the local checker representatives:

```sh
docker compose --env-file .env.demo \
  -f docker-compose.yml -f docker-compose.demo.yml \
  exec api python verify_firegex.py
```

Stop the demo without deleting its database volume:

```sh
docker compose --env-file .env.demo \
  -f docker-compose.yml -f docker-compose.demo.yml \
  down
```
