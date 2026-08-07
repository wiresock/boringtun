#!/usr/bin/env bash
#
# AmneziaWG interoperability proof against an INDEPENDENT implementation.
#
# scripts/awg-interop-poc.sh wants the kernel module, which WSL2 cannot provide
# (no headers for the running kernel). This uses amneziawg-go instead -- the
# reference userspace AmneziaWG implementation, a different codebase from ours
# in a different language -- as the client. It answers the same question the
# kernel-module harness answers and this project's unit tests cannot: does a
# real AmneziaWG implementation agree with our wire format?
#
# What it does NOT cover: the kernel datapath, and `awg`/`awg-quick` config
# parsing. Both ends here are userspace and both are driven over the UAPI
# directly.
#
# Requires: root, iproute2, python3 with `cryptography`, ping, and a built
#           amneziawg-go:
#
#   go install github.com/amnezia-vpn/amneziawg-go@latest
#   # or: git clone ... && go build -o amneziawg-go .
#
# SAFETY: everything lives in throwaway network namespaces prefixed `agi-`. The
# host's own interfaces, routes and WireGuard devices are never touched, and
# cleanup runs on every exit path.
#
# Usage: awg-go-interop.sh <boringtun-cli> <amneziawg-go>
set -uo pipefail

BT=${1:?path to boringtun-cli}
GO=${2:?path to amneziawg-go}

NS_SRV=agi-srv; NS_CLI=agi-cli
IF_SRV=agi0;    IF_CLI=agic
PORT=51820
SRV_TUN=10.77.0.1; CLI_TUN=10.77.0.2
SRV_LINK=10.55.0.1; CLI_LINK=10.55.0.2

# Single values, not ranges: amneziawg-go parses h1..h4 as plain uints. Our fork
# accepts a bare value as a degenerate range, which is exactly the compatibility
# claim being tested here.
readonly JC=4 JMIN=50 JMAX=1000
readonly S1=120 S2=130 S3=110 S4=80
readonly H1=169887817 H2=390382747 H3=1033691040 H4=1526332224

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '\033[1m==> %s\033[0m\n' "$1"; }

teardown() {
  for ns in "$NS_SRV" "$NS_CLI"; do
    p=$(ip netns pids "$ns" 2>/dev/null); [ -n "$p" ] && kill $p 2>/dev/null
  done
  sleep 0.4
  ip netns del "$NS_SRV" 2>/dev/null; ip netns del "$NS_CLI" 2>/dev/null
  ip link del agi-vs 2>/dev/null
  rm -f "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock" \
        "/var/run/wireguard/${IF_CLI}.sock" "/var/run/amneziawg/${IF_CLI}.sock"
  return 0
}
trap teardown EXIT

# `amneziawg-go` publishes its UAPI socket in /var/run/amneziawg only -- the
# directory the AmneziaWG fork of wireguard-tools searches. boringtun publishes
# in both, for the reason its `api.rs` documents. So try the AmneziaWG path
# first and fall back, rather than assuming either.
uapi() { # <ns> <iface>; request on stdin
  ip netns exec "$1" python3 -c '
import socket, sys, os
iface = sys.argv[1]
path = next(
    (p for p in ("/var/run/amneziawg/%s.sock" % iface, "/var/run/wireguard/%s.sock" % iface)
     if os.path.exists(p)),
    None,
)
if path is None:
    sys.exit("no UAPI socket for " + iface)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
s.sendall(sys.stdin.read().encode())
d = b""
while True:
    b = s.recv(4096)
    if not b: break
    d += b
    if d.endswith(b"\n\n"): break
sys.stdout.write(d.decode())
' "$2"
}

pubkey() { python3 -c '
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
k = X25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[1]))
print(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
' "$1"; }

wait_sock() { # <iface>
  local w=0
  while [ ! -e "/var/run/amneziawg/$1.sock" ] && [ ! -e "/var/run/wireguard/$1.sock" ]; do
    sleep 0.2; w=$((w+1)); [ "$w" -ge 60 ] && return 1
  done
  return 0
}

# $1 = server obfuscated (1/0), $2 = client obfuscated (1/0), $3.. = boringtun flags.
#
# Two flags, not one, because the negative control has to be *born* mismatched.
# Configuring both ends alike and then reconfiguring one leaves the handshake
# that already succeeded recorded in `last_handshake_time_sec`, and the control
# then reads that stale timestamp and reports a pass. It did exactly that.
start_pair() {
  local srv_obf=$1 cli_obf=$2; shift 2
  teardown
  ip netns add "$NS_SRV"; ip netns add "$NS_CLI"
  ip link add agi-vs type veth peer name agi-vc
  ip link set agi-vs netns "$NS_SRV"; ip link set agi-vc netns "$NS_CLI"
  ip netns exec "$NS_SRV" sh -c "ip link set lo up; ip addr add $SRV_LINK/30 dev agi-vs; ip link set agi-vs up"
  ip netns exec "$NS_CLI" sh -c "ip link set lo up; ip addr add $CLI_LINK/30 dev agi-vc; ip link set agi-vc up"

  SRV_KEY=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  CLI_KEY=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  SRV_PUB=$(pubkey "$SRV_KEY"); CLI_PUB=$(pubkey "$CLI_KEY")

  ip netns exec "$NS_SRV" env WG_LOG_FILE=/tmp/agi-srv.log WG_LOG_LEVEL=debug \
    "$BT" --disable-drop-privileges "$@" "$IF_SRV" >/dev/null 2>&1
  # `-f`, not its default daemonise. Forking under WSL loses the process
  # before the UAPI socket appears -- the same failure boringtun's own
  # daemonised logs have here. Foreground plus `&` keeps it in the
  # namespace and observable.
  ip netns exec "$NS_CLI" env LOG_LEVEL=verbose \
    "$GO" -f "$IF_CLI" >/tmp/agi-cli.log 2>&1 &

  wait_sock "$IF_SRV" || { echo "server socket never appeared"; return 1; }
  wait_sock "$IF_CLI" || { echo "amneziawg-go socket never appeared"; return 1; }

  local AWG
  AWG=$'jc='"$JC"$'\njmin='"$JMIN"$'\njmax='"$JMAX"$'\ns1='"$S1"$'\ns2='"$S2"$'\ns3='"$S3"$'\ns4='"$S4"$'\nh1='"$H1"$'\nh2='"$H2"$'\nh3='"$H3"$'\nh4='"$H4"$'\n'
  local SRV_OBF='' CLI_OBF=''
  [ "$srv_obf" = 1 ] && SRV_OBF=$AWG
  [ "$cli_obf" = 1 ] && CLI_OBF=$AWG

  uapi "$NS_SRV" "$IF_SRV" >/tmp/agi-srv-set.txt <<EOF
set=1
private_key=$SRV_KEY
listen_port=$PORT
${SRV_OBF}public_key=$CLI_PUB
allowed_ip=$CLI_TUN/32

EOF
  uapi "$NS_CLI" "$IF_CLI" >/tmp/agi-cli-set.txt <<EOF
set=1
private_key=$CLI_KEY
listen_port=51821
${CLI_OBF}public_key=$SRV_PUB
endpoint=$SRV_LINK:$PORT
persistent_keepalive_interval=5
allowed_ip=$SRV_TUN/32

EOF
  grep -q 'errno=0' /tmp/agi-srv-set.txt || { echo "server set=1 failed: $(cat /tmp/agi-srv-set.txt)"; return 1; }
  grep -q 'errno=0' /tmp/agi-cli-set.txt || { echo "amneziawg-go set=1 failed: $(cat /tmp/agi-cli-set.txt)"; return 1; }

  ip netns exec "$NS_SRV" sh -c "ip addr add $SRV_TUN/24 dev $IF_SRV; ip link set $IF_SRV up mtu 1420" 2>/dev/null
  ip netns exec "$NS_CLI" sh -c "ip addr add $CLI_TUN/32 dev $IF_CLI; ip link set $IF_CLI up mtu 1420; ip route add $SRV_TUN/32 dev $IF_CLI" 2>/dev/null
  return 0
}

handshaked() { # -> 0 if the server recorded a handshake
  local hs
  for _ in $(seq 1 24); do
    hs=$(uapi "$NS_SRV" "$IF_SRV" <<< $'get=1\n\n' | grep '^last_handshake_time_sec=' | head -1 | cut -d= -f2)
    case "${hs:-}" in ""|*[!0-9]*) hs=0 ;; esac
    [ "$hs" -gt 0 ] && return 0
    sleep 0.5
  done
  return 1
}

echo "boringtun : $BT"
echo "peer      : $GO ($("$GO" --version 2>/dev/null | head -1 || echo 'amneziawg-go'))"
echo

info "1. An independent AmneziaWG implementation handshakes with our server"
if ! start_pair 1 1; then
  bad "setup failed -- not an interop result"
else
  if handshaked; then
    ok "amneziawg-go completed a handshake against boringtun"
  else
    bad "no handshake -- wire format disagreement"
    echo "    srv: $(tail -3 /tmp/agi-srv.log 2>/dev/null | tr '\n' ' ')"
    echo "    cli: $(tail -3 /tmp/agi-cli.log 2>/dev/null | tr '\n' ' ')"
  fi

  info "2. and passes bidirectional traffic through the tunnel"
  if ip netns exec "$NS_CLI" ping -c3 -w 20 -q "$SRV_TUN" >/dev/null 2>&1; then
    ok "ping through the tunnel, both directions"
  else
    bad "handshake but no data -- the transport path disagrees"
  fi
fi

info "3. NEGATIVE CONTROL: a vanilla server must NOT serve an AmneziaWG client"
# Without this, checks 1 and 2 would pass even if both ends silently spoke
# plain WireGuard, which would prove nothing about the obfuscation.
if ! start_pair 0 1; then
  bad "vanilla setup failed"
else
  if handshaked; then
    bad "an obfuscated client reached a VANILLA server -- checks 1-2 prove nothing"
  else
    ok "vanilla server correctly cannot serve an obfuscated client"
  fi
fi

info "4. The ordering guarantee, against a third-party peer"
# Under ip=dns our own S1 junk is a valid DNS query by construction. A server
# that asked "is this a probe?" before "is this one of my peers?" would SERVFAIL
# this client's handshake. Unit tests pin the order; this is the confirmation
# with an implementation that is not ours.
if ! start_pair 1 1 --imitate-protocol dns; then
  bad "setup failed with --imitate-protocol dns"
else
  if handshaked && ip netns exec "$NS_CLI" ping -c3 -w 20 -q "$SRV_TUN" >/dev/null 2>&1; then
    ok "amneziawg-go still handshakes and passes traffic while the port answers DNS probes"
  else
    bad "the probe responder broke interop with a third-party client"
    echo "    srv: $(tail -5 /tmp/agi-srv.log 2>/dev/null | tr '\n' ' ')"
  fi
fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mSUMMARY: all %d checks passed\033[0m\n' "$PASS"; exit 0
else
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"; exit 1
fi
