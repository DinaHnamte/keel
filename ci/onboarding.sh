#!/bin/sh
# Run the real-server onboarding tests against one distro.
#
#   ci/onboarding.sh <base image> <agent binary> <agent .sig>
#
# Builds ci/systemd-sshd for the base image, starts it with systemd as PID 1
# and sshd on port 2222, then runs the ignored tests in
# crates/keel-client/tests/onboarding.rs twice: as root, and as a
# passwordless-sudo user. The last of those tests restarts keel-agent and
# checks the client is back within 15 seconds (the reboot stand-in).
# Then tests scripts/install.sh on the same server: a clean install prints a
# pairing code, a second run prints a new code with the same fingerprint, and
# a wrong checksum stops it with nothing installed.
# The binary must be signed with the key the test build embeds (the dev key
# for debug builds).
set -eu

image="$1"
bin="$(realpath "$2")"
sig="$(realpath "$3")"
tag="keel-test/$(printf '%s' "$image" | tr ':/' '--')"
name="keel-onboarding-$$"
work="$(mktemp -d)"
http_pid=""

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "--- keel-agent journal ($image)"
        docker exec "$name" journalctl -u keel-agent --no-pager -n 100 2>/dev/null || true
    fi
    if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || true; fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT INT TERM

here="$(dirname "$0")"
docker build -q --build-arg "IMAGE=$image" -t "$tag" "$here/systemd-sshd" >/dev/null
docker run -d --name "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -p 127.0.0.1:2222:2222 -p 127.0.0.1:7443:7443 "$tag" >/dev/null

# A throwaway key, made inside the container so the host needs no OpenSSH.
docker exec "$name" sh -c 'ssh-keygen -q -t ed25519 -N "" -f /tmp/id_ed25519 &&
    install -m 600 /tmp/id_ed25519.pub /root/.ssh/authorized_keys &&
    install -m 600 -o deploy -g deploy /tmp/id_ed25519.pub /home/deploy/.ssh/authorized_keys'
docker exec "$name" cat /tmp/id_ed25519 >"$work/id_ed25519"
docker exec "$name" rm -f /tmp/id_ed25519 /tmp/id_ed25519.pub

# Wait for systemd and sshd.
i=0
until docker exec "$name" sh -c 'ss -Htln | grep -q ":2222 "' 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "sshd didn't start in the $image container" >&2
        docker exec "$name" systemctl --failed --no-pager || true
        exit 1
    fi
    sleep 1
done

export KEEL_TEST_SSH_HOST=127.0.0.1 KEEL_TEST_SSH_PORT=2222
export KEEL_TEST_SSH_KEY_FILE="$work/id_ed25519"
export KEEL_TEST_AGENT_BIN="$bin" KEEL_TEST_AGENT_SIG="$sig"
for user in root deploy; do
    echo "--- onboarding tests on $image as $user"
    KEEL_TEST_SSH_USER="$user" cargo test -p keel-client --test onboarding -- \
        --ignored --test-threads=1 --nocapture
done

echo "--- install.sh on $image"
# Serve the agent the way a release does, from the host.
mkdir -p "$work/www/good" "$work/www/bad"
cp "$bin" "$work/www/good/keel-agent-x86_64"
(cd "$work/www/good" && sha256sum keel-agent-x86_64 >keel-agent-x86_64.sha256)
cp "$bin" "$work/www/bad/keel-agent-x86_64"
printf '%064d  keel-agent-x86_64\n' 0 >"$work/www/bad/keel-agent-x86_64.sha256"
python3 -m http.server 8765 --bind 0.0.0.0 --directory "$work/www" >/dev/null 2>&1 &
http_pid=$!
gateway="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
docker cp "$here/../scripts/install.sh" "$name:/tmp/install.sh"
docker exec "$name" sh -c 'systemctl disable --now keel-agent; userdel keel;
    rm -rf /usr/local/bin/keel-agent /etc/systemd/system/keel-agent.service /var/lib/keel /etc/keel;
    systemctl daemon-reload' >/dev/null 2>&1

install_sh() {
    docker exec -e "KEEL_DOWNLOAD_BASE=http://$gateway:8765/$1" "$name" sh /tmp/install.sh
}
field() { sed -n "s/^$1//p"; }
code_of() { sed -n '/^Paste this pairing code into the Keel app:$/{n;p;}'; }

i=0
until curl -fs "http://127.0.0.1:8765/good/keel-agent-x86_64.sha256" >/dev/null; do
    i=$((i + 1)); [ "$i" -gt 20 ] && { echo "local HTTP server didn't start" >&2; exit 1; }
    sleep 0.5
done

first="$(install_sh good)"
printf '%s\n' "$first"
code1="$(printf '%s\n' "$first" | code_of)"
fp1="$(printf '%s\n' "$first" | field 'Server fingerprint: ')"
case "$code1" in keel1:*) ;; *) echo "FAIL: no keel1: pairing code" >&2; exit 1 ;; esac
[ "$(printf '%s\n' "$first" | grep -c 'keel1:')" -eq 1 ] || { echo "FAIL: code printed more than once" >&2; exit 1; }
docker exec "$name" systemctl is-active --quiet keel-agent || { echo "FAIL: agent not running" >&2; exit 1; }
docker exec "$name" sh -c 'test "$(stat -c %a:%U /var/lib/keel)" = 700:keel' || { echo "FAIL: /var/lib/keel mode" >&2; exit 1; }
docker exec "$name" cat /etc/systemd/system/keel-agent.service | diff - "$here/../crates/keel-agent/dist/keel-agent.service"

second="$(install_sh good)"
code2="$(printf '%s\n' "$second" | code_of)"
fp2="$(printf '%s\n' "$second" | field 'Server fingerprint: ')"
if [ -z "$code2" ] || [ "$code2" = "$code1" ]; then
    echo "FAIL: re-run didn't print a new code" >&2; exit 1
fi
[ "$fp1" = "$fp2" ] || { echo "FAIL: fingerprint changed on re-run ($fp1 vs $fp2)" >&2; exit 1; }

before="$(docker exec "$name" sha256sum /usr/local/bin/keel-agent)"
if out="$(install_sh bad 2>&1)"; then
    echo "FAIL: a wrong checksum didn't stop the install" >&2; exit 1
fi
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -qx "The download didn't match its checksum. Nothing was installed." \
    || { echo "FAIL: wrong checksum message" >&2; exit 1; }
[ "$(docker exec "$name" sha256sum /usr/local/bin/keel-agent)" = "$before" ] \
    || { echo "FAIL: the binary changed after a bad download" >&2; exit 1; }
echo "install.sh checks passed on $image"
