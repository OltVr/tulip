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
  default, and follows the official `info.teams` plus `info.flag_ids()` loop to
  attack every published valid ID. HTTP exports use `requests`; TCP exports use
  `pwntools`.
- Single-target mode uses `--host`, `TARGET_HOST`, `XFARM_HOST`, or
  `TARGET_IP`, so the same file runs under ExploitFarm. Flags are the only
  values written to stdout; target diagnostics go to stderr.

Install the generated script's dependencies with one of:

```sh
pip install ecsc2026ad requests
pip install ecsc2026ad pwntools
```

The export panel lists every supported override. Normally no ECSC arguments are
needed because `ecsc2026ad` already points at the competition scoreboard. Use
`ECSC_API` only for a different API, `--round` to select one round instead of
all still-valid rounds, and `TARGET_HOST`, `TARGET_FLAG_ID`, `TARGET_PORT`, or
`ATTACK_TIMEOUT` for a single-target/AttackFarm run.

Captured values are listed in `CANDIDATE_TOKENS`. Rose pre-populates
`ATTACK_INFO_TOKENS` when the captured value is next to a likely attack-info
field such as `username`, `token`, or `note_id`. Review that short list before
farming; every listed value is replaced in paths, headers, bodies, and TCP
payloads with the current `flag_id`.

## Attack triage and Firegex

Rose inspects the request path, query, headers, and body for path traversal,
SQL/NoSQL injection, command injection, exploit-tool markers, overflows and NOP
sleds, XSS, template/JNDI injection, XXE, unsafe deserialization, prototype
pollution, SSRF, CRLF injection, HTTP request smuggling, and sensitive-file
probes. The generated Firegex PCRE2 rule is intentionally scoped to the
evidence in that flow instead of becoming a blanket service-wide deny rule.

Treat every proposed rule as a starting point: compare it with recent checker
traffic, test it in Firegex, and only then enable blocking. The verifier below
checks all detector families, the rules generated from the retained live-shaped
samples, benign requests, and local checker representatives.

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
