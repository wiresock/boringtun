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
#   go install github.com/amnezia-vpn/amneziawg-go/v3@latest   # needs Go >= 1.25
#   # or: git clone ... && go build -o amneziawg-go .
#
# The `/v3` suffix is required, not cosmetic: upstream's go.mod declares
# `module github.com/amnezia-vpn/amneziawg-go/v3`, so the unsuffixed path cannot
# reach the current line -- it resolves to v1.0.4, a tag deleted from GitHub but
# cached forever in the module proxy. And `--version` will not tell you: the
# version constant reads 0.0.20250522 on both the v0 and v3 lines, so the banner
# this script prints looks identical either way. Check `go version -m` on the
# binary if a result here surprises you.
#
# SAFETY: everything lives in throwaway network namespaces prefixed `agi-`. The
# host's own interfaces, routes and WireGuard devices are never touched, and
# cleanup runs on every exit path.
#
# Usage: awg-go-interop.sh <boringtun-cli> <amneziawg-go>
set -uo pipefail

BT=${1:?path to boringtun-cli}
GO=${2:?path to amneziawg-go}

PORT=51820
SRV_TUN=10.77.0.1; CLI_TUN=10.77.0.2
SRV_LINK=10.55.0.1; CLI_LINK=10.55.0.2

# Bare values, not ranges -- and that is a degenerate range, not a plain uint.
# amneziawg-go parses h1..h4 through `UintRange.FromString` (device/uapi.go),
# which splits on `-` and collapses a single part to [N,N]; only s1..s4 take a
# plain `ParseUint`. So the bare form our fork accepts is the same one-element
# range every real AmneziaWG config carries, which is the compatibility claim
# under test. Keep the four distinct: amneziawg-go refuses the whole `set=`
# transaction with "headers must not overlap" if any two intersect.
readonly JC=4 JMIN=50 JMAX=1000
readonly S1=120 S2=130 S3=110 S4=80
readonly H1=169887817 H2=390382747 H3=1033691040 H4=1526332224

# One definition. This was written out inline in both `start_pair` and
# `start_bt_pair`, and the two copies had already drifted apart in formatting --
# which is how a difference in the *values* would arrive next.
AWG_BLOCK=$'jc='"$JC"$'\njmin='"$JMIN"$'\njmax='"$JMAX"$'\ns1='"$S1"$'\ns2='"$S2"$'\ns3='"$S3"$'\ns4='"$S4"$'\nh1='"$H1"$'\nh2='"$H2"$'\nh3='"$H3"$'\nh4='"$H4"$'\n'
readonly AWG_BLOCK

genkey() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Every artifact goes here, not to a predictable /tmp path. This runs as root:
# a local user who pre-creates $SRV_LOG as a symlink would have root
# truncate whatever it points at. `mktemp -d` plus `umask 077` is what
# awg-interop-poc.sh does, for exactly this reason.
umask 077
WORKDIR=$(mktemp -d /tmp/awg-go-interop.XXXXXX) || {
  echo "could not create a temporary directory" >&2
  exit 2
}
readonly WORKDIR

# Every kernel-visible name this run creates carries the `mktemp` token.
#
# Fixed names were the reason cleanup needed an ownership flag at all: a
# namespace called `agi-srv` might be somebody else's, and `ip netns pids | kill`
# on somebody else's namespace is exactly the host damage the safety notice
# above promises not to do. Preflight could only check for a collision, never
# prevent one opening between the check and the create. A suffix the kernel has
# just proved unique retires that question -- and lets two runs proceed at once,
# which fixed names could not. The longest interface name below is 13
# characters, inside the kernel's limit of 15.
RUN=${WORKDIR##*.}
NS_SRV="agi-srv-$RUN";  NS_CLI="agi-cli-$RUN"
IF_SRV="agi0-$RUN";     IF_CLI="agic-$RUN"
VETH_SRV="agi-vs-$RUN"; VETH_CLI="agi-vc-$RUN"
readonly RUN NS_SRV NS_CLI IF_SRV IF_CLI VETH_SRV VETH_CLI

SRV_LOG="$WORKDIR/srv.log"
CLI_LOG="$WORKDIR/cli.log"
BTCLI_LOG="$WORKDIR/btcli.log"
SRV_SET="$WORKDIR/srv-set.txt"
CLI_SET="$WORKDIR/cli-set.txt"

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '\033[1m==> %s\033[0m\n' "$1"; }

# What this run has actually created, appended to only after the creating
# command reports success. A single "setup has started" flag could not say this:
# it was set by the first successful create and then claimed everything, so a
# later `ip netns add` that failed *because the name was already taken* still
# left teardown believing the namespace was ours. It also never cleared, so from
# the second check onward the claim outlived the resources entirely.
#
# Emptied by `teardown`, so each rebuild has to acquire ownership again.
OWNED_NS=()
OWNED_LINKS=()
OWNED_SOCKS=()

# The UAPI sockets are created by the daemons, not by us, and they live outside
# the namespaces -- /var/run is not network namespaced -- so they have to be
# removed by name. The name is claimed when the daemon is launched rather than
# when the socket appears: a daemon that starts and then hangs still has to be
# cleaned up after, and `wait_sock` giving up does not mean nothing was created.
own_socks() { # <iface>
  OWNED_SOCKS+=("/var/run/wireguard/$1.sock" "/var/run/amneziawg/$1.sock")
}

# `${a[@]+"${a[@]}"}` and not `"${a[@]}"`: under `set -u` an empty array is an
# unbound variable to bash 4.3 and older, and this script is run on whatever the
# host has.
teardown() {
  local ns link sock p killed=0
  for ns in ${OWNED_NS[@]+"${OWNED_NS[@]}"}; do
    p=$(ip netns pids "$ns" 2>/dev/null)
    [ -n "$p" ] && { kill $p 2>/dev/null; killed=1; }
  done
  [ "$killed" -eq 1 ] && sleep 0.4
  for ns in ${OWNED_NS[@]+"${OWNED_NS[@]}"}; do
    ip netns del "$ns" 2>/dev/null
  done
  # Usually already gone with the namespaces they were moved into; this covers
  # a failure between creating the veth pair and moving it.
  for link in ${OWNED_LINKS[@]+"${OWNED_LINKS[@]}"}; do
    ip link del "$link" 2>/dev/null
  done
  for sock in ${OWNED_SOCKS[@]+"${OWNED_SOCKS[@]}"}; do
    rm -f "$sock"
  done
  OWNED_NS=()
  OWNED_LINKS=()
  OWNED_SOCKS=()
  return 0
}
# `$WORKDIR` came from `mktemp -d`, so this only ever removes a directory this
# run created. Failures are printed rather than swallowed: leaving a root-owned
# directory behind in /tmp is worth a line of output.
cleanup_workdir() {
  [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR" ] || return 0
  rm -rf "$WORKDIR" || echo "could not remove $WORKDIR" >&2
  return 0
}
trap 'teardown; cleanup_workdir' EXIT

die() { printf '\033[31mpreflight: %s\033[0m\n' "$1" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || die "must run as root (creates network namespaces)"
[ -x "$BT" ]         || die "boringtun-cli not found or not executable: $BT"
[ -x "$GO" ]         || die "amneziawg-go not found or not executable: $GO"

# The names carry this run's `mktemp` token, so a hit here means the token was
# not unique after all. Kept as an assertion on that premise, not as the safety
# mechanism it used to be -- ownership tracking is what makes teardown safe now.
for ns in "$NS_SRV" "$NS_CLI"; do
  ip netns list 2>/dev/null | grep -qw "$ns" && die "namespace $ns already exists; refusing to touch it"
done
for l in "$VETH_SRV" "$VETH_CLI"; do
  ip link show "$l" >/dev/null 2>&1 && die "interface $l already exists; refusing to touch it"
done
for sock in "${IF_SRV}" "${IF_CLI}"; do
  for d in /var/run/amneziawg /var/run/wireguard; do
    [ -e "$d/$sock.sock" ] && die "$d/$sock.sock already exists; refusing to touch it"
  done
done

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

# Build the two namespaces and the veth between them, checking every step.
#
# Unchecked setup is how a negative control passes for the wrong reason: if the
# veth or an address never came up, check 3 sees no handshake and reports
# "vanilla server correctly cannot serve an obfuscated client" for a topology
# that could not have carried one either way. That is the exact vacuous pass
# check 3 exists to prevent, so the link is also *proven* to work below rather
# than assumed.
build_underlay() {
  # Each name is claimed only by the command that created it, immediately after
  # that command reports success. Anything below this that fails leaves the
  # names it did not create unclaimed, so teardown cannot reach them.
  ip netns add "$NS_SRV" || return 1
  OWNED_NS+=("$NS_SRV")
  ip netns add "$NS_CLI" || return 1
  OWNED_NS+=("$NS_CLI")
  ip link add "$VETH_SRV" type veth peer name "$VETH_CLI" || return 1
  OWNED_LINKS+=("$VETH_SRV" "$VETH_CLI")
  ip link set "$VETH_SRV" netns "$NS_SRV" || return 1
  ip link set "$VETH_CLI" netns "$NS_CLI" || return 1
  ip netns exec "$NS_SRV" ip link set lo up || return 1
  ip netns exec "$NS_CLI" ip link set lo up || return 1
  ip netns exec "$NS_SRV" ip addr add "$SRV_LINK/30" dev "$VETH_SRV" || return 1
  ip netns exec "$NS_CLI" ip addr add "$CLI_LINK/30" dev "$VETH_CLI" || return 1
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" up || return 1
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" up || return 1

  # Positive control on the underlay itself, before any daemon exists. If this
  # fails, nothing below is a statement about WireGuard.
  ip netns exec "$NS_CLI" ping -c1 -w 5 -q "$SRV_LINK" >/dev/null 2>&1 || {
    echo "underlay ping $CLI_LINK -> $SRV_LINK failed; the link is broken, not the tunnel"
    return 1
  }
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
  build_underlay || return 1

  SRV_KEY=$(genkey); CLI_KEY=$(genkey)
  SRV_PUB=$(pubkey "$SRV_KEY"); CLI_PUB=$(pubkey "$CLI_KEY")

  own_socks "$IF_SRV"
  ip netns exec "$NS_SRV" env WG_LOG_FILE="$SRV_LOG" WG_LOG_LEVEL=debug \
    "$BT" --disable-drop-privileges "$@" "$IF_SRV" >/dev/null 2>&1
  # `-f`, not its default daemonise. Forking under WSL loses the process
  # before the UAPI socket appears -- the same failure boringtun's own
  # daemonised logs have here. Foreground plus `&` keeps it in the
  # namespace and observable.
  own_socks "$IF_CLI"
  ip netns exec "$NS_CLI" env LOG_LEVEL=verbose \
    "$GO" -f "$IF_CLI" >"$CLI_LOG" 2>&1 &

  wait_sock "$IF_SRV" || { echo "server socket never appeared"; return 1; }
  wait_sock "$IF_CLI" || { echo "amneziawg-go socket never appeared"; return 1; }

  local SRV_OBF='' CLI_OBF=''
  [ "$srv_obf" = 1 ] && SRV_OBF=$AWG_BLOCK
  [ "$cli_obf" = 1 ] && CLI_OBF=$AWG_BLOCK

  uapi "$NS_SRV" "$IF_SRV" >"$SRV_SET" <<EOF
set=1
private_key=$SRV_KEY
listen_port=$PORT
${SRV_OBF}public_key=$CLI_PUB
allowed_ip=$CLI_TUN/32

EOF
  uapi "$NS_CLI" "$IF_CLI" >"$CLI_SET" <<EOF
set=1
private_key=$CLI_KEY
listen_port=51821
${CLI_OBF}public_key=$SRV_PUB
endpoint=$SRV_LINK:$PORT
persistent_keepalive_interval=5
allowed_ip=$SRV_TUN/32

EOF
  grep -q '^errno=0$' "$SRV_SET" || { echo "server set=1 failed: $(cat "$SRV_SET")"; return 1; }
  grep -q '^errno=0$' "$CLI_SET" || { echo "amneziawg-go set=1 failed: $(cat "$CLI_SET")"; return 1; }

  ip netns exec "$NS_SRV" sh -c "ip addr add $SRV_TUN/24 dev $IF_SRV && ip link set $IF_SRV up mtu 1420" || return 1
  ip netns exec "$NS_CLI" sh -c "ip addr add $CLI_TUN/32 dev $IF_CLI && ip link set $IF_CLI up mtu 1420 && ip route add $SRV_TUN/32 dev $IF_CLI" || return 1
  return 0
}

# Both ends boringtun, both with the same imitation setting. Used only by check
# 5, where the client has to produce a DNS-shaped S1 prefix and amneziawg-go
# cannot.
start_bt_pair() {
  teardown
  build_underlay || return 1

  SRV_KEY=$(genkey); CLI_KEY=$(genkey)
  SRV_PUB=$(pubkey "$SRV_KEY"); CLI_PUB=$(pubkey "$CLI_KEY")

  own_socks "$IF_SRV"
  ip netns exec "$NS_SRV" env WG_LOG_FILE="$SRV_LOG" WG_LOG_LEVEL=debug \
    "$BT" --disable-drop-privileges "$@" "$IF_SRV" >/dev/null 2>&1
  own_socks "$IF_CLI"
  ip netns exec "$NS_CLI" env WG_LOG_FILE="$BTCLI_LOG" WG_LOG_LEVEL=debug \
    "$BT" --disable-drop-privileges "$@" "$IF_CLI" >/dev/null 2>&1

  wait_sock "$IF_SRV" || { echo "server socket never appeared"; return 1; }
  wait_sock "$IF_CLI" || { echo "boringtun client socket never appeared"; return 1; }

  local AWG=$AWG_BLOCK

  # Both responses are inspected, as `start_pair` does. `validate` refuses some
  # S combinations outright, so a bad set of sizes here would otherwise surface
  # as check 5 reporting a classification-order failure for a config the device
  # never accepted.
  uapi "$NS_SRV" "$IF_SRV" >"$SRV_SET" <<EOF
set=1
private_key=$SRV_KEY
listen_port=$PORT
${AWG}public_key=$CLI_PUB
allowed_ip=$CLI_TUN/32

EOF
  uapi "$NS_CLI" "$IF_CLI" >"$CLI_SET" <<EOF
set=1
private_key=$CLI_KEY
listen_port=51821
${AWG}public_key=$SRV_PUB
endpoint=$SRV_LINK:$PORT
persistent_keepalive_interval=5
allowed_ip=$SRV_TUN/32

EOF
  grep -q '^errno=0$' "$SRV_SET" || { echo "server set=1 failed: $(cat "$SRV_SET")"; return 1; }
  grep -q '^errno=0$' "$CLI_SET" || { echo "boringtun client set=1 failed: $(cat "$CLI_SET")"; return 1; }

  # `&&` not `;`, and the status propagated: a half-configured interface would
  # otherwise reach check 5 and be reported as a classification-order failure.
  ip netns exec "$NS_SRV" sh -c "ip addr add $SRV_TUN/24 dev $IF_SRV && ip link set $IF_SRV up mtu 1420" || return 1
  ip netns exec "$NS_CLI" sh -c "ip addr add $CLI_TUN/32 dev $IF_CLI && ip link set $IF_CLI up mtu 1420 && ip route add $SRV_TUN/32 dev $IF_CLI" || return 1
  # Best-effort on purpose: this only nudges the client into handshaking, and
  # the handshake itself is what check 5 asserts.
  ip netns exec "$NS_CLI" ping -c2 -w 8 -q "$SRV_TUN" >/dev/null 2>&1 || true
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
    echo "    srv: $(tail -3 "$SRV_LOG" 2>/dev/null | tr '\n' ' ')"
    echo "    cli: $(tail -3 "$CLI_LOG" 2>/dev/null | tr '\n' ' ')"
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

info "4. The probe responder does not break interop"
# NOT an ordering test, though an earlier version of this script claimed it was.
#
# The ordering rule matters because a datagram can be *simultaneously* a valid
# AmneziaWG initiation and a valid DNS query, so a server that classified probes
# first would answer its own peers. But that collision needs a client whose S1
# filler is DNS-shaped, and that shaping is this fork's own extension:
# amneziawg-go fills its prefix with `rand.Read` (device/send.go), so its
# initiations are random bytes and `detect` returns None for them.
#
# Measured, not assumed: with `classify` mutated to ask "is this a probe?"
# first, this check still passed. A third-party client therefore cannot test the
# ordering at all -- it can only show that turning the responder on does not
# break a peer that does not collide with it, which is what it now claims.
if ! start_pair 1 1 --imitate-protocol dns; then
  bad "setup failed with --imitate-protocol dns"
else
  if handshaked && ip netns exec "$NS_CLI" ping -c3 -w 20 -q "$SRV_TUN" >/dev/null 2>&1; then
    ok "amneziawg-go still handshakes and passes traffic while the port answers DNS probes"
  else
    bad "enabling the probe responder broke interop with a third-party client"
    echo "    srv: $(tail -5 "$SRV_LOG" 2>/dev/null | tr '\n' ' ')"
  fi
fi

info "5. The ordering guarantee, with a client that actually collides"
# The client here is boringtun, not amneziawg-go, because only our own filler
# produces an S1 prefix that is a well-formed DNS query -- which is the whole
# premise of the rule. Both ends being ours is a real weakness of this check and
# the reason it is numbered separately rather than folded into 4; the
# deterministic version is the unit test
# `a_conforming_initiation_is_tunnel_traffic_even_though_it_is_a_valid_dns_query`.
# What this adds is a real socket and a real ingress path.
#
# Verified load-bearing: reordering `classify` fails this check.
if ! start_bt_pair --imitate-protocol dns; then
  bad "boringtun client setup failed -- not an ordering result"
else
  if handshaked; then
    ok "a DNS-shaped initiation is treated as tunnel traffic, not answered as a probe"
  else
    bad "a client whose S1 junk is a valid DNS query did not handshake -- classification order"
    echo "    srv: $(tail -5 "$SRV_LOG" 2>/dev/null | tr '\n' ' ')"
  fi
fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mSUMMARY: all %d checks passed\033[0m\n' "$PASS"; exit 0
else
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"; exit 1
fi
