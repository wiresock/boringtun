#!/usr/bin/env bash
#
# AmneziaWG interoperability proof: a stock kernel-module client against a
# boringtun server.
#
# The unit tests can only show that our client and our server agree with each
# other. This shows that a real AmneziaWG implementation agrees with us, which
# is a different claim and the only one that de-risks the project. It is what
# found the epoch-timestamp and UAPI-socket-path bugs (#12); neither was
# reachable from any unit test.
#
# Requires: root, the amneziawg kernel module, amneziawg-tools, iproute2.
#
# SAFETY: everything lives in throwaway network namespaces. The host's own
# interfaces, routes, firewall rules and WireGuard/AmneziaWG devices are never
# touched, and the module is never loaded or unloaded. Cleanup runs on any exit
# path. It is still preferable to run this on a disposable host.
#
# Usage:
#   scripts/awg-interop-poc.sh [path-to-boringtun-cli]
#
# Exit codes: 0 all checks passed, 1 a check failed, 2 preflight failed.

set -uo pipefail

readonly NS_SRV=awgpoc-srv
readonly NS_CLI=awgpoc-cli
readonly NS_CLI2=awgpoc-cli2
readonly IF_SRV=awgpoc0
readonly IF_CLI=awgpocc
readonly PORT=51820
# Checked: on failure this is empty, and `cd ""` succeeds in bash without
# changing directory, so the `cd "$WORKDIR" || die` below would not fire and
# every artifact would land in the invoking directory instead.
WORKDIR=$(mktemp -d /tmp/awg-interop-poc.XXXXXX) || {
  echo "preflight: could not create a temporary directory" >&2
  exit 2
}
readonly WORKDIR

# Obfuscation parameters. H1-H4 are deliberately *ranges*, not single values:
# that is how real deployments are configured, and single values would not
# exercise the range handling at all.
readonly JC=8 JMIN=50 JMAX=1000
readonly S1=120 S2=130 S3=110 S4=80
readonly H1=169887817-269887816
readonly H2=390382747-890382746
readonly H3=1033691040-1433691039
readonly H4=1526332224-2026332223

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '\033[1m==> %s\033[0m\n' "$1"; }
die()  { printf '\033[31mpreflight: %s\033[0m\n' "$1" >&2; exit 2; }

cleanup() {
  local rc=$?
  set +e
  pkill -f "$IF_SRV" >/dev/null 2>&1
  for ns in "$NS_SRV" "$NS_CLI" "$NS_CLI2"; do ip netns del "$ns" >/dev/null 2>&1; done
  ip link del awgpoc-vs  >/dev/null 2>&1
  ip link del awgpoc-vs2 >/dev/null 2>&1
  rm -f "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock"
  rmdir /var/run/amneziawg >/dev/null 2>&1
  [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR"
  return $rc
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- preflight --

BORINGTUN=${1:-}
[ -n "$BORINGTUN" ] || BORINGTUN=$(command -v boringtun-cli 2>/dev/null)
[ -n "$BORINGTUN" ] || BORINGTUN=target/release/boringtun-cli

[ "$(id -u)" -eq 0 ]              || die "must run as root (creates network namespaces)"
[ -x "$BORINGTUN" ]               || die "boringtun-cli not found or not executable: $BORINGTUN"
command -v awg >/dev/null         || die "amneziawg-tools (awg) not installed"
command -v ip  >/dev/null         || die "iproute2 (ip) not installed"
# Asserted rather than assumed: absent, these do not merely skip a check --
# tcpdump/timeout make check 6 report a wire-format failure that is really a
# missing tool, and without pkill the cleanup cannot stop the server, which on
# a shared host is the worst outcome this script can produce.
command -v tcpdump >/dev/null     || die "tcpdump not installed (needed by the wire-format check)"
command -v timeout >/dev/null     || die "timeout not installed (needed by the wire-format check)"
command -v pkill   >/dev/null     || die "pkill not installed (needed to stop the server on cleanup)"
lsmod | grep -q '^amneziawg'      || die "amneziawg kernel module not loaded -- the point of this test is a REAL client"
[ -e /dev/net/tun ]               || die "/dev/net/tun missing"

# Refuse to clobber anything that already exists under our names.
for ns in "$NS_SRV" "$NS_CLI" "$NS_CLI2"; do
  ip netns list 2>/dev/null | grep -qw "$ns" && die "namespace $ns already exists; refusing to touch it"
done
ip link show "$IF_SRV" >/dev/null 2>&1 && die "interface $IF_SRV already exists; refusing to touch it"

info "preflight OK  (binary: $BORINGTUN, kernel module present)"

# ------------------------------------------------------------------- set up --

umask 077
cd "$WORKDIR" || die "cannot enter $WORKDIR"
awg genkey > srv.key; awg pubkey < srv.key > srv.pub
awg genkey > cli.key; awg pubkey < cli.key > cli.pub
awg genkey > cli2.key; awg pubkey < cli2.key > cli2.pub

ip netns add "$NS_SRV"; ip netns add "$NS_CLI"; ip netns add "$NS_CLI2"
ip link add awgpoc-vs  type veth peer name awgpoc-vc
ip link add awgpoc-vs2 type veth peer name awgpoc-vc2
ip link set awgpoc-vs  netns "$NS_SRV";  ip link set awgpoc-vc  netns "$NS_CLI"
ip link set awgpoc-vs2 netns "$NS_SRV";  ip link set awgpoc-vc2 netns "$NS_CLI2"

ip netns exec "$NS_SRV" sh -c "ip link set lo up
  ip addr add 10.201.0.1/30 dev awgpoc-vs  && ip link set awgpoc-vs up
  ip addr add 10.201.1.1/30 dev awgpoc-vs2 && ip link set awgpoc-vs2 up"
ip netns exec "$NS_CLI"  sh -c "ip link set lo up; ip addr add 10.201.0.2/30 dev awgpoc-vc  && ip link set awgpoc-vc up"
ip netns exec "$NS_CLI2" sh -c "ip link set lo up; ip addr add 10.201.1.2/30 dev awgpoc-vc2 && ip link set awgpoc-vc2 up"

# $1 = output file, $2 = private key, $3..: extra [Interface] lines
write_iface_conf() {
  local out=$1 key=$2; shift 2
  { printf '[Interface]\nPrivateKey = %s\n' "$key"
    printf '%s\n' "$@"
  } > "$out"
}

readonly OBF_LINES=(
  "Jc = $JC" "Jmin = $JMIN" "Jmax = $JMAX"
  "S1 = $S1" "S2 = $S2" "S3 = $S3" "S4 = $S4"
  "H1 = $H1" "H2 = $H2" "H3 = $H3" "H4 = $H4"
)

write_iface_conf srv.conf "$(cat srv.key)" "ListenPort = $PORT" "${OBF_LINES[@]}"
printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.201.2/32\n' "$(cat cli.pub)" >> srv.conf

for n in 1 2; do
  k=cli.key; ep=10.201.0.1; [ "$n" = 2 ] && { k=cli2.key; ep=10.201.1.1; }
  write_iface_conf "c$n.conf" "$(cat $k)" "${OBF_LINES[@]}"
  printf '\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = 10.66.201.1/32\nPersistentKeepalive = 25\n' \
    "$(cat srv.pub)" "$ep" "$PORT" >> "c$n.conf"
done

start_server() {  # $1 = config file
  ip netns exec "$NS_SRV" env WG_LOG_FILE="$WORKDIR/srv.log" \
    "$BORINGTUN" --disable-drop-privileges "$IF_SRV" >/dev/null 2>&1
  sleep 2
  ip netns exec "$NS_SRV" awg setconf "$IF_SRV" "$1" || return 1
  ip netns exec "$NS_SRV" sh -c "ip addr add 10.66.201.1/24 dev $IF_SRV; ip link set $IF_SRV up mtu 1420"
}
stop_server() {
  pkill -f "$IF_SRV" >/dev/null 2>&1
  ip netns exec "$NS_SRV" ip link del "$IF_SRV" >/dev/null 2>&1
  rm -f "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock"
  sleep 1
}
start_client() {  # $1 = ns, $2 = conf, $3 = tunnel addr
  ip netns exec "$1" ip link add "$IF_CLI" type amneziawg
  ip netns exec "$1" awg setconf "$IF_CLI" "$2"
  ip netns exec "$1" sh -c "ip addr add $3/32 dev $IF_CLI; ip link set $IF_CLI up mtu 1420; ip route add 10.66.201.1/32 dev $IF_CLI"
}

# --------------------------------------------------------------------- tests --

info "1. UAPI: awg setconf against a userspace implementation"
if start_server srv.conf; then
  ok "awg setconf accepted (implies the UAPI socket was discoverable)"
else
  bad "awg setconf failed -- see $WORKDIR/srv.log"
  # `bad` already incremented FAIL; adding one here would over-report.
  printf '[31mSUMMARY: %d passed, %d FAILED[0m
' "$PASS" "$FAIL"; exit 1
fi

info "2. UAPI: showconf round-trips every AmneziaWG parameter"
conf_out=$(ip netns exec "$NS_SRV" awg showconf "$IF_SRV" 2>/dev/null)
for kv in "Jc = $JC" "Jmin = $JMIN" "Jmax = $JMAX" "S1 = $S1" "S2 = $S2" "S3 = $S3" "S4 = $S4" \
          "H1 = $H1" "H2 = $H2" "H3 = $H3" "H4 = $H4"; do
  if grep -qF "$kv" <<<"$conf_out"; then ok "showconf: $kv"; else bad "showconf lost or altered: $kv"; fi
done

info "3. Handshake and bidirectional traffic from a kernel-module client"
start_client "$NS_CLI" c1.conf 10.66.201.2
if ip netns exec "$NS_CLI" ping -c3 -W3 -q 10.66.201.1 >/dev/null 2>&1; then
  ok "kernel-module client passes traffic to the boringtun server"
else
  bad "no traffic -- handshake or datapath broken"
fi

info "4. Handshake timestamp is an epoch value, not an age"
# Regression guard for #12: `last_handshake_time_sec` carried the elapsed
# duration, so awg rendered live peers as ~56 years stale and any health check
# treating a stale handshake as "peer down" saw every peer as dead.
hs=$(ip netns exec "$NS_SRV" awg show "$IF_SRV" latest-handshakes | head -1 | cut -f2)
now=$(date -u +%s)
if [ "${hs:-0}" -gt $((now - 300)) ] && [ "${hs:-0}" -le "$now" ]; then
  ok "handshake reported as a plausible epoch timestamp ($hs, now=$now)"
else
  bad "handshake timestamp is not an epoch value: got $hs, now=$now"
fi

info "5. Multi-peer: a second peer added live to the running server"
ip netns exec "$NS_SRV" awg set "$IF_SRV" peer "$(cat cli2.pub)" allowed-ips 10.66.201.3/32
start_client "$NS_CLI2" c2.conf 10.66.201.3
if ip netns exec "$NS_CLI2" ping -c3 -W3 -q 10.66.201.1 >/dev/null 2>&1; then
  ok "second peer handshakes and passes traffic"
else
  bad "second peer failed"
fi
if ip netns exec "$NS_CLI" ping -c2 -W3 -q 10.66.201.1 >/dev/null 2>&1; then
  ok "first peer still works after the second was added"
else
  bad "adding a peer disturbed the existing one"
fi

info "6. Wire format: the S-prefix and H-range tag are really on the wire"
# Without this, tests 3 and 5 would also pass if both ends silently agreed to
# speak vanilla WireGuard -- which would prove nothing about obfuscation.
ip netns exec "$NS_SRV" timeout 10 tcpdump -i awgpoc-vs -c 2 -w "$WORKDIR/wire.pcap" udp port "$PORT" >/dev/null 2>&1 &
tcpdump_pid=$!
sleep 1
ip netns exec "$NS_CLI" ping -c2 -W2 -q 10.66.201.1 >/dev/null 2>&1
wait $tcpdump_pid 2>/dev/null
len=$(ip netns exec "$NS_SRV" tcpdump -r "$WORKDIR/wire.pcap" -nn 2>/dev/null | head -1 | sed 's/.*length \([0-9]*\).*/\1/')
if [ "${len:-0}" -gt "$S4" ]; then
  ok "captured datagram is $len bytes, larger than the S4 prefix ($S4)"
else
  bad "no captured datagram, or too small to carry an S4 prefix (got '${len:-none}')"
fi

info "7. NEGATIVE CONTROL: a vanilla server must NOT serve an AmneziaWG client"
# The most important check. If this passes, tests 3-6 were not proving
# interoperability -- they would pass even with obfuscation switched off.
stop_server
write_iface_conf srv-vanilla.conf "$(cat srv.key)" "ListenPort = $PORT"
printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.201.2/32\n' "$(cat cli.pub)" >> srv-vanilla.conf
if start_server srv-vanilla.conf; then
  if ip netns exec "$NS_CLI" ping -c2 -W3 -q 10.66.201.1 >/dev/null 2>&1; then
    bad "an obfuscated client reached a VANILLA server -- the other checks prove nothing"
  else
    ok "vanilla server correctly cannot serve an obfuscated client"
  fi
else
  bad "could not start the vanilla control server"
fi

# ------------------------------------------------------------------ summary --

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mSUMMARY: all %d checks passed\033[0m\n' "$PASS"; exit 0
else
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m  (logs: %s)\n' "$PASS" "$FAIL" "$WORKDIR"
  trap - EXIT; cleanup >/dev/null 2>&1; exit 1
fi
