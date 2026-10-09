# Rose offsite and vulnbox deployment runbook

This guide installs Rose as two cooperating roles:

- **Offsite server:** runs the Rose Docker Compose stack, receives PCAP files,
  and serves the web interface.
- **Vulnbox:** captures traffic on the game interface, rotates it into a durable
  local queue, and pushes closed PCAP files to the offsite server.

The complete path has been tested in isolated Linux containers with real PCAP
traffic, restricted SSH delivery, a simulated SSH outage, retained local data,
and successful delivery after recovery.

## 1. Understand the data path

```text
game interface
    -> tcpdump on vulnbox
    -> /var/spool/rose-pcap/active
    -> /var/spool/rose-pcap/ready
    -> restricted SSH + rsync
    -> <Rose checkout>/.ecsc/traffic on offsite
    -> Rose assembler, database, API, and UI
```

The capture rotates every 15 seconds. Staging runs every 3 seconds, delivery is
retried every 5 seconds, and the health watchdog runs every 30 seconds. A queued
file is removed from the vulnbox only after rsync acknowledges its delivery.

## 2. Requirements and values to collect

Both machines must be Linux. Run the setup as root or through `sudo`.

The installer supports systems using `apt`, `dnf`, or `apk`. It installs missing
dependencies, including Docker Engine and Docker Compose v2 on the offsite host,
and `tcpdump`, OpenSSH, Python, rsync, and supporting tools on the vulnbox. The
vulnbox must use systemd.

Before starting, record these values:

| Value | Example | Meaning |
| --- | --- | --- |
| `TEAM_ID` | `41` | Competition team number |
| `VULNBOX_IP` | `10.60.41.2` | Vulnbox address reachable from offsite |
| `GAME_INTERFACE` | `kmob0` | Interface carrying competition traffic |
| `OFFSITE_HOST` | `2.31.24.56` | Offsite SSH address reachable from vulnbox |
| `ROSE_DIR` | `/opt/rose` | Rose checkout on the offsite server |
| `UI_VPN_IP` | `2.28.234.166` | Optional trusted VPN address for the UI |

Find the game interface on the vulnbox before configuring capture:

```bash
ip -br link
ip -6 route get fd66:777::1
ip -6 -br address
```

The interface shown after `dev` in the game route is normally the correct one.
Confirm this against the competition network documentation.

## 3. Put Rose on the offsite server

Place the current Rose checkout on the offsite machine. The setup script and
the rest of the repository must stay together.

For a fork that already contains the Rose changes:

```bash
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/OltVr/tulip.git rose
cd /opt/rose
sudo chmod 0755 setup-tulip-ecsc.sh
```

If the current changes have not been pushed to GitHub yet, copy this working
checkout to the server instead of cloning an older revision. Verify the expected
files before continuing:

```bash
cd /opt/rose
test -x setup-tulip-ecsc.sh
test -f docker-compose.yml
test -f services/timescale/Dockerfile
```

## 4. Choose how to expose the UI

Use one of these modes consistently in every offsite command.

### Trusted VPN binding

This binds the UI directly to an offsite VPN address. It does not add Caddy
authentication, so use it only on a trusted team network.

```bash
--ui-vpn-ip 2.28.234.166 --ui-port 3000
```

### Public domain with HTTPS and authentication

Point the domain at the offsite server first and allow inbound TCP 80 and 443.
If `--auth-password` is omitted, the installer generates a strong password,
prints it once, and stores it in `.ecsc/public-auth-password` with mode `0600`.

```bash
--domain rose.example.org --auth-user team
```

`--public-ip` is available as a fallback, but the generated IP configuration is
plain HTTP. A domain with HTTPS or a trusted VPN binding is preferred.

## 5. Bootstrap the offsite server

Do not pass `--start` yet. This first run installs dependencies, prepares Rose,
and creates the public key that the offsite server will use to query the
vulnbox's restricted service endpoint.

```bash
cd /opt/rose
sudo ./setup-tulip-ecsc.sh offsite \
  --team-id 41 \
  --vulnbox-ip 10.60.41.2 \
  --tulip-dir /opt/rose \
  --ui-vpn-ip 2.28.234.166 \
  --ui-port 3000 \
  --force
```

For a domain deployment, replace the two `--ui-*` arguments with the domain and
authentication arguments from the previous section.

The public key to transfer to the vulnbox is:

```text
/opt/rose/.ecsc/ssh/id_ed25519.pub
```

Only copy the `.pub` file. Never copy `/opt/rose/.ecsc/ssh/id_ed25519` to the
vulnbox.

Transfer the public key through your approved management channel and store it
on the vulnbox as `/tmp/rose-offsite-capture.pub`.

## 6. Bootstrap the vulnbox

On the vulnbox, confirm the transferred public key exists:

```bash
sudo test -s /tmp/rose-offsite-capture.pub
```

Copy `setup-tulip-ecsc.sh` from the same Rose revision to the vulnbox, then run:

```bash
cd /path/to/rose-or-setup-script
sudo ./setup-tulip-ecsc.sh vulnbox \
  --public-key-file /tmp/rose-offsite-capture.pub \
  --vulnbox-ip 10.60.41.2 \
  --game-interface kmob0 \
  --force
```

This installs the restricted capture/service-discovery endpoint and creates the
vulnbox's dedicated forwarding key:

```text
/root/.ssh/rose-pcap-push.pub
```

Copy that public key back to the offsite server as
`/tmp/rose-vulnbox-push.pub`. Copy only the `.pub` file; the private key must
remain on the vulnbox.

## 7. Enable the offsite receiver and start Rose

Back on the offsite server, confirm the vulnbox public key arrived:

```bash
sudo test -s /tmp/rose-vulnbox-push.pub
```

Rerun offsite setup with that key and `--start`:

```bash
cd /opt/rose
sudo ./setup-tulip-ecsc.sh offsite \
  --team-id 41 \
  --vulnbox-ip 10.60.41.2 \
  --tulip-dir /opt/rose \
  --ui-vpn-ip 2.28.234.166 \
  --ui-port 3000 \
  --push-public-key-file /tmp/rose-vulnbox-push.pub \
  --start \
  --force
```

This run:

- installs `/usr/local/sbin/rose-pcap-receive`;
- adds the forwarding key with a forced command to root's `authorized_keys`;
- verifies restricted SSH access from offsite to the vulnbox;
- validates the merged Compose configuration;
- builds and starts Rose in durable ingest mode.

The forwarding public key is also retained at
`/opt/rose/.ecsc/ssh/vulnbox-push.pub`, so later offsite reruns remain in durable
mode without repeating `--push-public-key-file`.

## 8. Start capture and forwarding on the vulnbox

Run the final vulnbox command only after the offsite receiver is installed:

```bash
cd /path/to/rose-or-setup-script
sudo ./setup-tulip-ecsc.sh vulnbox \
  --public-key-file /tmp/rose-offsite-capture.pub \
  --vulnbox-ip 10.60.41.2 \
  --game-interface kmob0 \
  --offsite-host 2.31.24.56 \
  --offsite-port 22 \
  --offsite-user root \
  --offsite-dir /opt/rose/.ecsc/traffic \
  --start \
  --force
```

The first successful start pins the offsite SSH host key in
`/root/.ssh/rose-offsite-known-hosts`. The script deliberately does not replace
an existing pinned key automatically.

The following systemd units should now be enabled and active:

```text
rose-pcap-capture.service
rose-pcap-stage.timer
rose-pcap-push.timer
rose-pcap-health.timer
```

## 9. Verify both roles

### Offsite checks

```bash
cd /opt/rose
sudo ./setup-tulip-ecsc.sh doctor \
  --role offsite \
  --tulip-dir /opt/rose
```

Inspect the running stack and recent logs:

```bash
cd /opt/rose
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  ps
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  logs --tail=100 assembler api frontend service-sync
find /opt/rose/.ecsc/traffic -maxdepth 1 -type f -name '*.pcap' \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %p\n' | tail -20
```

The doctor expects `timescale`, `api`, `frontend`, `assembler`, and
`service-sync` to be running.

### Vulnbox checks

```bash
sudo ./setup-tulip-ecsc.sh doctor --role vulnbox
sudo systemctl status \
  rose-pcap-capture.service \
  rose-pcap-stage.timer \
  rose-pcap-push.timer \
  rose-pcap-health.timer
sudo systemctl list-timers 'rose-pcap-*'
sudo journalctl \
  -u rose-pcap-capture.service \
  -u rose-pcap-push.service \
  -u rose-pcap-health.service \
  --since=-10m
sudo find /var/spool/rose-pcap -maxdepth 2 -type f -name '*.pcap' \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %p\n'
```

One current file normally remains under `active`. Closed files may appear
briefly under `ready` before the next delivery run.

### Test the restricted receiver from the vulnbox

This command must print exactly `rose-receiver-ok`:

```bash
sudo ssh \
  -p 22 \
  -i /root/.ssh/rose-pcap-push \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/root/.ssh/rose-offsite-known-hosts \
  root@2.31.24.56 health
```

## 10. Competition operation

Use the Rose UI at the address selected in section 4. During the competition:

1. Run both doctor commands before scoring starts.
2. Confirm new PCAP modification times appear offsite.
3. Watch the vulnbox `ready` directory. A continually growing queue indicates a
   delivery problem, not permission to delete the files.
4. Watch free space with `df -h /var/spool/rose-pcap`.
5. Keep every private key on its original host and out of team chat or tickets.

An offsite outage should not lose closed captures. Leave the vulnbox queue
intact, restore connectivity, then run:

```bash
sudo systemctl start rose-pcap-push.service
sudo journalctl -u rose-pcap-push.service -n 50 --no-pager
```

The queued file count should then decrease.

## 11. Troubleshooting

### `doctor` reports Docker or Compose missing

On the offsite server:

```bash
sudo systemctl enable --now docker
docker --version
docker compose version
sudo docker info
```

The required command is `docker compose`, not the deprecated standalone
`docker-compose`. Rerun offsite setup as root if dependencies were missing.

### Docker Compose configuration is invalid

Render the merged configuration to expose the exact error:

```bash
cd /opt/rose
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  config
```

Confirm `.env.ecsc` and `docker-compose.ecsc.yml` exist and were generated by
the same checkout. Rerun the offsite command with the intended options and
`--force` if a generated file is stale.

### `cannot read the SSH host key from the vulnbox`

From offsite, verify routing and SSH:

```bash
ip route get 10.60.41.2
ssh-keyscan -T 5 10.60.41.2
```

On the vulnbox, verify SSH is running and port 22 is listening:

```bash
sudo systemctl status ssh 2>/dev/null || sudo systemctl status sshd
sudo ss -ltnp | grep ':22 '
```

Check the game VPN, address, firewall, and competition routing. Do not use
`StrictHostKeyChecking=no` as a workaround.

### Offsite cannot query vulnbox services

From `/opt/rose` on the offsite server:

```bash
ssh \
  -i .ecsc/ssh/id_ed25519 \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=.ecsc/ssh/known_hosts \
  root@10.60.41.2 services | python3 -m json.tool
```

If authentication fails, verify that the key ending in
`ecsc-tulip-capture` exists in `/root/.ssh/authorized_keys` on the vulnbox, then
rerun vulnbox bootstrap with the correct offsite public key.

### `restricted offsite receiver check failed`

On offsite, verify the receiver and authorized key:

```bash
sudo test -x /usr/local/sbin/rose-pcap-receive
sudo grep 'rose-pcap-push$' /root/.ssh/authorized_keys
sudo systemctl status ssh 2>/dev/null || sudo systemctl status sshd
```

On the vulnbox, run the receiver health command from section 9. Confirm that
`--offsite-dir` on the vulnbox exactly matches the Rose traffic directory used
when the offsite receiver was generated.

### SSH reports a changed offsite host key

Do not delete the pinned key until the new host fingerprint is verified through
a trusted channel.

Show the fingerprint on the offsite server:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Show the currently pinned fingerprint on the vulnbox:

```bash
sudo ssh-keygen -lf /root/.ssh/rose-offsite-known-hosts
```

If the change is expected and verified, preserve the old pin and rerun the
final vulnbox setup command:

```bash
sudo mv /root/.ssh/rose-offsite-known-hosts \
  /root/.ssh/rose-offsite-known-hosts.before-rotation
```

The next `--start` run will scan and pin the new key.

### The PCAP queue grows and does not drain

Check the queue, last successful delivery, timer, network, and receiver:

```bash
sudo find /var/spool/rose-pcap/ready -maxdepth 1 -type f -name '*.pcap' \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %p\n'
sudo test -s /var/lib/rose-forwarder/last-success-epoch && \
  sudo cat /var/lib/rose-forwarder/last-success-epoch
sudo systemctl status rose-pcap-push.timer
sudo journalctl -u rose-pcap-push.service -n 100 --no-pager
sudo systemctl start rose-pcap-push.service
```

Do not delete queued captures. Resolve SSH, routing, receiver, or disk errors and
let the timer retry them.

### No packets are captured

Verify the selected interface has traffic:

```bash
sudo ip -s link show dev kmob0
sudo timeout 10 tcpdump -ni kmob0 'tcp and not port 22 and not port 4242 and not port 4444'
sudo journalctl -u rose-pcap-capture.service -n 100 --no-pager
```

If the game interface is wrong, rerun vulnbox setup with the correct
`--game-interface`. To use a custom BPF filter, pass `--capture-filter` on every
vulnbox setup rerun.

### Capture or forwarding units are inactive

```bash
sudo systemctl daemon-reload
sudo systemctl restart \
  rose-pcap-capture.service \
  rose-pcap-stage.timer \
  rose-pcap-push.timer \
  rose-pcap-health.timer
sudo systemctl --failed
```

The watchdog also restarts inactive Rose capture and timer units every 30
seconds. If systemd is not PID 1, move the setup to the actual Linux vulnbox;
the production forwarder is not supported in a non-systemd application
container.

### The vulnbox spool is low on disk space

```bash
df -h /var/spool/rose-pcap
sudo du -sh /var/spool/rose-pcap/active /var/spool/rose-pcap/ready
```

Restore offsite delivery first so acknowledged files drain normally. If space
is critically low, stop capture before maintenance and preserve queued PCAPs on
approved storage rather than deleting evidence:

```bash
sudo systemctl stop rose-pcap-capture.service
```

Restart capture after space and delivery are healthy.

### PCAP files arrive offsite but Rose shows no flows

Check file timestamps and assembler logs:

```bash
find /opt/rose/.ecsc/traffic -maxdepth 1 -type f -name '*.pcap' \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %p\n' | tail -20
cd /opt/rose
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  logs --tail=200 assembler timescale api
```

Confirm `.env.ecsc` contains an empty `PCAP_OVER_IP=` entry. Durable mode reads
the mounted traffic directory and must not also use the retired live stream.

### Rose UI is unavailable

```bash
cd /opt/rose
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  ps
sudo ss -ltnp | grep -E ':3000 |:443 |:80 '
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  logs --tail=200 frontend api
# Public domain/IP mode only:
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  logs --tail=200 caddy
```

The `caddy` service exists only in public domain/IP mode. In VPN mode, check the
configured VPN address and UI port instead.

### Timescale build mentions Clang 15

The installer migrates the known `clang15/llvm15` package names to
`clang19/llvm19` and preserves the original as:

```text
services/timescale/Dockerfile.before-clang19
```

Verify the active file and rebuild:

```bash
grep -nE 'clang|llvm' /opt/rose/services/timescale/Dockerfile
cd /opt/rose
sudo docker compose --env-file .env.ecsc \
  -f docker-compose.yml \
  -f docker-compose.ecsc.yml \
  build --no-cache timescale
```

### Setup refuses to replace a generated file

The installer protects changed generated files. Inspect the named file first.
If the difference is expected, rerun the same setup command with `--force`.
Do not use `--force` as a substitute for understanding unexpected key, address,
or destination changes.

## 12. Safe disposable test

Before deployment, or after changing the forwarding code, run this from the
Rose repository on a workstation with Docker:

```bash
./scripts/test-rose-forwarding-e2e.sh
```

The test creates disposable offsite and vulnbox containers, captures real ICMP
traffic, verifies command restrictions, delivers a PCAP, stops SSH, confirms the
next PCAP stays queued, restores SSH, and confirms the queue drains. It does not
contact the competition host or modify the running Rose stack.

Successful output ends with:

```text
PASS: Rose retained PCAPs during outage and delivered them after recovery.
```

Use `--keep` only when you need to inspect the temporary containers manually.
Without it, the test cleans up its network, containers, and temporary files.

## 13. Generated files reference

### Offsite

| Path | Purpose |
| --- | --- |
| `/opt/rose/.env.ecsc` | Competition and ingest configuration |
| `/opt/rose/docker-compose.ecsc.yml` | Generated Compose override |
| `/opt/rose/.ecsc/traffic` | Received PCAP directory |
| `/opt/rose/.ecsc/ssh/id_ed25519` | Private key used to query the vulnbox |
| `/opt/rose/.ecsc/ssh/vulnbox-push.pub` | Stored forwarding public key |
| `/usr/local/sbin/rose-pcap-receive` | Forced-command PCAP receiver |

### Vulnbox

| Path | Purpose |
| --- | --- |
| `/etc/ecsc-tulip/config` | Capture and service-discovery configuration |
| `/etc/ecsc-tulip/forwarder` | Durable forwarding configuration |
| `/root/.ssh/rose-pcap-push` | Private forwarding key; never copy offsite |
| `/root/.ssh/rose-offsite-known-hosts` | Pinned offsite host key |
| `/var/spool/rose-pcap/active` | Current capture files |
| `/var/spool/rose-pcap/ready` | Closed files awaiting acknowledgement |
| `/var/lib/rose-forwarder/last-success-epoch` | Last successful transfer timestamp |
