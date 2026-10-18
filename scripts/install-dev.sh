#!/usr/bin/env bash
# Install the broker before it ships in a base OS image.
# Run with: sudo scripts/install-dev.sh
# The image version installs the same unit with ExecStart pointing at
# /usr/libexec/vaultbroker-launch; here /usr is read-only, so the dev unit
# runs /usr/local/libexec/vaultbroker directly.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run with sudo" >&2
    exit 1
fi

repo=$(cd "$(dirname "$0")/.." && pwd)

if ! getent group vaultbroker > /dev/null; then
    groupadd --system vaultbroker
fi
if ! id vaultbroker > /dev/null 2>&1; then
    useradd --system --gid vaultbroker --home-dir /var/lib/vaultbroker \
        --shell /usr/sbin/nologin vaultbroker
fi
agent_user=${AGENT_USER:-${SUDO_USER:-}}
if [[ -z "$agent_user" ]]; then
    echo "set AGENT_USER to the agent's unix user" >&2
    exit 1
fi
usermod --append --groups vaultbroker "$agent_user"

install -d -o vaultbroker -g vaultbroker -m 0700 /var/lib/vaultbroker
install -d -o root -g vaultbroker -m 0750 /etc/vaultbroker
install -d -o root -g root -m 0755 /usr/local/libexec

if [[ -x "$repo/vaultbroker" ]]; then
    install -o root -g root -m 0755 "$repo/vaultbroker" /usr/local/libexec/vaultbroker
else
    echo "binary $repo/vaultbroker not built yet; service installed without it"
fi

if [[ -x "$repo/bw" ]]; then
    install -o root -g root -m 0755 "$repo/bw" /usr/local/bin/bw
fi

if [[ ! -f /etc/vaultbroker/config.json ]]; then
    helper_token=$(openssl rand -hex 32)
    sed -e "s|replace-with-random-token|$helper_token|" \
        -e 's|"bw_path": "/usr/bin/bw"|"bw_path": "/usr/local/bin/bw"|' \
        "$repo/config.example.json" > /etc/vaultbroker/config.json
    chown vaultbroker:vaultbroker /etc/vaultbroker/config.json
    chmod 0600 /etc/vaultbroker/config.json
    echo "wrote /etc/vaultbroker/config.json (random helper token generated)"
fi

sed 's|ExecStart=/usr/libexec/vaultbroker-launch|ExecStart=/usr/local/libexec/vaultbroker|' \
    "$repo/systemd/vaultbroker.service" > /etc/systemd/system/vaultbroker.service
chmod 0644 /etc/systemd/system/vaultbroker.service

systemctl daemon-reload
echo "installed. Next: systemctl enable --now vaultbroker"
echo "Note: /etc/vaultbroker/config.json is vaultbroker-owned 0600. After editing"
echo "it (sudoedit rewrites it as root), run: chown vaultbroker:vaultbroker /etc/vaultbroker/config.json"
echo "The agent user ($agent_user) picks up the vaultbroker group at next login."
