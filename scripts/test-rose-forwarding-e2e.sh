#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
ROSE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly ROSE_DIR
readonly SETUP_SCRIPT="$ROSE_DIR/setup-tulip-ecsc.sh"

keep=0
case "${1:-}" in
    "") ;;
    --keep) keep=1 ;;
    -h|--help)
        cat <<'EOF'
Run a disposable two-container integration test for Rose PCAP forwarding.

Usage: scripts/test-rose-forwarding-e2e.sh [--keep]

The test bootstraps an offsite host and a vulnbox, generates real PCAPs,
checks the restricted SSH receiver, and verifies queue retention and recovery
during an SSH outage. Docker is required. --keep preserves test resources.
EOF
        exit 0
        ;;
    *)
        printf 'error: unknown option: %s\n' "$1" >&2
        exit 2
        ;;
esac

command -v docker >/dev/null 2>&1 || {
    printf 'error: Docker is required\n' >&2
    exit 1
}
docker info >/dev/null 2>&1 || {
    printf 'error: Docker is not running\n' >&2
    exit 1
}
[[ -x "$SETUP_SCRIPT" ]] || {
    printf 'error: setup script is missing or not executable: %s\n' "$SETUP_SCRIPT" >&2
    exit 1
}

test_root="$(mktemp -d "${TMPDIR:-/tmp}/rose-e2e.XXXXXX")"
suffix="$(basename "$test_root" | tr -cd 'A-Za-z0-9')"
network="rose-e2e-net-$suffix"
offsite="rose-e2e-offsite-$suffix"
vulnbox="rose-e2e-vulnbox-$suffix"
rose_fixture="$test_root/rose"
shared="$test_root/shared"

case "$network $offsite $vulnbox" in
    rose-e2e-*) ;;
    *)
        printf 'error: refusing unsafe test resource names\n' >&2
        exit 1
        ;;
esac

cleanup() {
    local status=$?
    if ((keep)); then
        printf '[test] kept resources after exit %d:\n' "$status"
        printf '       temp: %s\n       containers: %s %s\n       network: %s\n' \
            "$test_root" "$offsite" "$vulnbox" "$network"
        return
    fi
    docker rm -f -- "$offsite" "$vulnbox" >/dev/null 2>&1 || true
    docker network rm -- "$network" >/dev/null 2>&1 || true
    case "$test_root" in
        "${TMPDIR:-/tmp}"/rose-e2e.*) rm -rf -- "$test_root" ;;
        *) printf 'warning: refusing to remove unexpected path: %s\n' "$test_root" >&2 ;;
    esac
}
trap cleanup EXIT

step() { printf '\n[test] %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

container_exec() {
    local container="$1"
    shift
    docker exec "$container" "$@"
}

assert_container_file() {
    local container="$1" path="$2"
    container_exec "$container" test -s "$path" \
        || fail "$container did not contain a non-empty $path"
}

assert_container_pcap() {
    local container="$1" path="$2"
    container_exec "$container" python3 -c '
import pathlib
import sys

header = pathlib.Path(sys.argv[1]).read_bytes()[:24]
magic = header[:4]
valid_magic = {
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("4d3cb2a1"),
}
raise SystemExit(0 if len(header) == 24 and magic in valid_magic else 1)
' "$path" || fail "$container contained an unreadable PCAP at $path"
}

mkdir -p -- "$rose_fixture/services/timescale" "$shared"
cp -- "$ROSE_DIR/docker-compose.yml" "$rose_fixture/docker-compose.yml"
cp -- "$ROSE_DIR/services/timescale/Dockerfile" "$rose_fixture/services/timescale/Dockerfile"

step "creating isolated offsite and vulnbox hosts"
docker network create "$network" >/dev/null
docker run -d --name "$offsite" --hostname offsite --network "$network" \
    -v "$ROSE_DIR:/work:ro" \
    -v "$rose_fixture:/opt/rose" \
    -v "$shared:/shared" \
    docker:cli sleep infinity >/dev/null
docker run -d --name "$vulnbox" --hostname vulnbox --network "$network" \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$ROSE_DIR:/work:ro" \
    -v "$rose_fixture:/opt/rose" \
    -v "$shared:/shared" \
    ubuntu:24.04 sleep infinity >/dev/null
container_exec "$offsite" apk add --no-cache bash >/dev/null

step "bootstrapping the offsite Rose configuration"
container_exec "$offsite" /work/setup-tulip-ecsc.sh offsite \
    --team-id 41 \
    --vulnbox-ip 10.60.41.2 \
    --tulip-dir /opt/rose \
    --ui-vpn-ip 127.0.0.1 \
    --force

step "bootstrapping the vulnbox forwarder"
container_exec "$vulnbox" bash -lc \
    'apt-get update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y systemd iputils-ping >/dev/null'
container_exec "$vulnbox" /work/setup-tulip-ecsc.sh vulnbox \
    --public-key-file /opt/rose/.ecsc/ssh/id_ed25519.pub \
    --vulnbox-ip 10.60.41.2 \
    --game-interface lo \
    --capture-filter icmp \
    --offsite-host offsite \
    --offsite-dir /opt/rose/.ecsc/traffic \
    --force
container_exec "$vulnbox" cp /root/.ssh/rose-pcap-push.pub /shared/rose-pcap-push.pub

step "installing the restricted offsite receiver"
container_exec "$offsite" /work/setup-tulip-ecsc.sh offsite \
    --team-id 41 \
    --vulnbox-ip 10.60.41.2 \
    --tulip-dir /opt/rose \
    --ui-vpn-ip 127.0.0.1 \
    --push-public-key-file /shared/rose-pcap-push.pub \
    --force
container_exec "$offsite" sh -c 'ssh-keygen -A >/dev/null && mkdir -p /run/sshd && /usr/sbin/sshd'
container_exec "$vulnbox" bash -lc \
    'ssh-keyscan -T 5 offsite > /root/.ssh/rose-offsite-known-hosts 2>/dev/null && chmod 0600 /root/.ssh/rose-offsite-known-hosts'

step "checking receiver command restrictions"
health="$(container_exec "$vulnbox" ssh \
    -i /root/.ssh/rose-pcap-push \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/root/.ssh/rose-offsite-known-hosts \
    root@offsite health)"
[[ "$health" == rose-receiver-ok ]] || fail "receiver health check returned: $health"
if container_exec "$vulnbox" ssh \
    -i /root/.ssh/rose-pcap-push \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/root/.ssh/rose-offsite-known-hosts \
    root@offsite uname >/dev/null 2>&1; then
    fail "restricted receiver accepted an arbitrary command"
fi

step "generating real loopback PCAP traffic"
# This script is intentionally evaluated inside the vulnbox container.
# shellcheck disable=SC2016
container_exec "$vulnbox" bash -lc '
set -Eeuo pipefail
capture_one() {
    local output="$1" capture_pid
    tcpdump -i lo -nn -c 1 -w "$output" icmp >/tmp/rose-tcpdump.log 2>&1 &
    capture_pid=$!
    sleep 0.5
    ping -c 1 127.0.0.1 >/dev/null
    wait "$capture_pid"
}
capture_one /var/spool/rose-pcap/active/first.pcap
sleep 1
capture_one /var/spool/rose-pcap/active/current.pcap
'
container_exec "$vulnbox" /usr/local/sbin/rose-pcap-stage
assert_container_file "$vulnbox" /var/spool/rose-pcap/ready/first.pcap
assert_container_file "$vulnbox" /var/spool/rose-pcap/active/current.pcap

step "delivering a staged capture through restricted rsync"
container_exec "$vulnbox" /usr/local/sbin/rose-pcap-push
if container_exec "$vulnbox" test -e /var/spool/rose-pcap/ready/first.pcap; then
    fail "acknowledged capture remained in the local queue"
fi
assert_container_file "$offsite" /opt/rose/.ecsc/traffic/first.pcap
assert_container_pcap "$offsite" /opt/rose/.ecsc/traffic/first.pcap

step "simulating an offsite SSH outage"
container_exec "$vulnbox" cp \
    /var/spool/rose-pcap/active/current.pcap \
    /var/spool/rose-pcap/ready/during-outage.pcap
# The PID file must be read inside the offsite container.
# shellcheck disable=SC2016
container_exec "$offsite" sh -c 'kill "$(cat /var/run/sshd.pid)"'
if container_exec "$vulnbox" /usr/local/sbin/rose-pcap-push >/dev/null 2>&1; then
    fail "forwarder unexpectedly succeeded while SSH was unavailable"
fi
assert_container_file "$vulnbox" /var/spool/rose-pcap/ready/during-outage.pcap
if container_exec "$offsite" test -e /opt/rose/.ecsc/traffic/during-outage.pcap; then
    fail "outage capture appeared offsite before connectivity was restored"
fi

step "restoring SSH and draining the retained queue"
container_exec "$offsite" /usr/sbin/sshd
health="$(container_exec "$vulnbox" ssh \
    -i /root/.ssh/rose-pcap-push \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/root/.ssh/rose-offsite-known-hosts \
    root@offsite health)"
[[ "$health" == rose-receiver-ok ]] || fail "receiver did not recover"
container_exec "$vulnbox" /usr/local/sbin/rose-pcap-push
if container_exec "$vulnbox" test -e /var/spool/rose-pcap/ready/during-outage.pcap; then
    fail "retained capture was not removed after acknowledged recovery delivery"
fi
assert_container_file "$offsite" /opt/rose/.ecsc/traffic/during-outage.pcap
assert_container_pcap "$offsite" /opt/rose/.ecsc/traffic/during-outage.pcap

step "checking durable-mode configuration"
grep -q '^PCAP_OVER_IP=$' "$rose_fixture/.env.ecsc" \
    || fail "durable configuration did not disable PCAP-over-IP"
if grep -q '^  pcap-broker:' "$rose_fixture/docker-compose.ecsc.yml"; then
    fail "durable configuration still contains pcap-broker"
fi
grep -q 'PCAP_OVER_IP: ""' "$rose_fixture/docker-compose.ecsc.yml" \
    || fail "assembler durable ingest override is missing"

printf '\nPASS: Rose retained PCAPs during outage and delivered them after recovery.\n'
