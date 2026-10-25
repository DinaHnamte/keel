#!/bin/sh
# Install the Keel agent on this server without the desktop app.
#
#   curl -fsSL <url>/install.sh | sudo sh
#
# Downloads the agent for this processor, checks it against its published
# checksum, installs it as a system service running as the `keel` user and
# prints a one-time pairing code to paste into the Keel app.
#
# Safe to run again: it upgrades the agent in place, keeps the server's
# identity and prints a new pairing code.
#
# Environment:
#   KEEL_DOWNLOAD_BASE  where to download keel-agent-<arch> and its .sha256
#   KEEL_HOST           host name or IP desktops use (default: hostname -f)

set -eu

DOWNLOAD_BASE="${KEEL_DOWNLOAD_BASE:-https://github.com/OWNER/keel/releases/latest/download}"
AGENT_BIN=/usr/local/bin/keel-agent
AGENT_BIN_NEW=/usr/local/bin/keel-agent.new
UNIT_PATH=/etc/systemd/system/keel-agent.service

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    fail "This script needs to run as root. Run it again with sudo, for example: curl -fsSL <url>/install.sh | sudo sh"
fi

command -v systemctl >/dev/null 2>&1 \
    || fail "This server doesn't use systemd, which the Keel agent needs. Supported systems are Ubuntu 22.04 and 24.04 and Debian 12 and 13."

case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "The Keel agent isn't available for $(uname -m) processors. It runs on x86_64 and aarch64 servers." ;;
esac

host="${KEEL_HOST:-}"
if [ -z "$host" ]; then
    host="$(hostname -f 2>/dev/null || true)"
fi
if [ -z "$host" ]; then
    host="$(uname -n)"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

download() {
    # $1 URL, $2 output file
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail "Neither curl nor wget is installed. Install one of them and run this script again."
    fi
}

name="keel-agent-$arch"
echo "Downloading the Keel agent for $arch..."
download "$DOWNLOAD_BASE/$name" "$tmp/$name" \
    || fail "Couldn't download the agent from $DOWNLOAD_BASE/$name. Check the server's internet connection and try again. Nothing was installed."
download "$DOWNLOAD_BASE/$name.sha256" "$tmp/$name.sha256" \
    || fail "Couldn't download the agent's checksum from $DOWNLOAD_BASE/$name.sha256. Check the server's internet connection and try again. Nothing was installed."

# The .sha256 file may hold just the hash or "hash  file name"; check against
# the hash alone so the name inside it doesn't matter.
want="$(cut -d ' ' -f 1 <"$tmp/$name.sha256" | head -n 1)"
if command -v sha256sum >/dev/null 2>&1; then
    check() { (cd "$tmp" && printf '%s  %s\n' "$want" "$name" | sha256sum -c - >/dev/null 2>&1); }
elif command -v shasum >/dev/null 2>&1; then
    check() { (cd "$tmp" && printf '%s  %s\n' "$want" "$name" | shasum -a 256 -c - >/dev/null 2>&1); }
else
    fail "Neither sha256sum nor shasum is installed, so the download can't be checked. Nothing was installed."
fi
if [ -z "$want" ] || ! check; then
    fail "The download didn't match its checksum. Nothing was installed."
fi

echo "Installing the agent..."
# Write beside the target, then rename over it, so a running agent never
# sees a partial file.
cp "$tmp/$name" "$AGENT_BIN_NEW"
chmod 755 "$AGENT_BIN_NEW"
mv -f "$AGENT_BIN_NEW" "$AGENT_BIN"

if ! id keel >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /var/lib/keel --shell /usr/sbin/nologin keel
fi
install -d -m 0700 -o keel -g keel /var/lib/keel
install -d -m 0755 /etc/keel

# Must stay identical to crates/keel-agent/dist/keel-agent.service (CI checks).
cat >"$UNIT_PATH" <<'UNIT'
[Unit]
Description=Keel agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=keel
ExecStart=/usr/local/bin/keel-agent run
Restart=always
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/keel
PrivateTmp=yes
ProtectHome=yes
MemoryMax=64M

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

# Keeps the existing identity and issues a fresh one-time pairing token.
init_out="$(runuser -u keel -- "$AGENT_BIN" init --host "$host")" \
    || fail "The agent couldn't set itself up. Check the messages above, then run this script again."
fingerprint="$(printf '%s\n' "$init_out" | sed -n 's/^fingerprint=//p')"
code="$(printf '%s\n' "$init_out" | sed -n 's/^pairing_code=//p')"
if [ -z "$fingerprint" ] || [ -z "$code" ]; then
    fail "The agent's setup output wasn't understood. Download the latest install script and try again."
fi

echo "Starting the agent..."
systemctl enable keel-agent >/dev/null 2>&1 \
    || fail "The agent's service couldn't be enabled. Check the agent logs with: journalctl -u keel-agent"
systemctl restart keel-agent \
    || fail "The agent's service wouldn't start. Check the agent logs with: journalctl -u keel-agent"

echo
echo "The Keel agent is installed and running on $host (port 7443)."
echo "Server fingerprint: $fingerprint"
echo
echo "Paste this pairing code into the Keel app:"
printf '%s\n' "$code"
