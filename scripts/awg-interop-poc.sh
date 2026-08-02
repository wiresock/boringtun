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
# Requires: root, the amneziawg kernel module, amneziawg-tools (awg), iproute2
#           (ip), tcpdump, timeout, ping, and awk/cut/date/grep/head/lsmod.
#           Preflight enforces every one of them and names the missing tool,
#           because a missing dependency otherwise surfaces as a bogus test
#           failure rather than as a setup problem.
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

# Whether the amneziawg runtime directory predates this run. Cleanup removes it
# only if we created it: it may be host-managed, and cleanup also runs when
# preflight refuses to start, so removing it unconditionally would be a host
# change the safety notice rules out.
# Set to 1 immediately before the first resource is created. Cleanup runs on
# every exit path including a preflight refusal, and at that point this run
# owns nothing -- tearing down links and sockets it did not create would be
# the very clobbering preflight exists to prevent.
SETUP_STARTED=0
# Set on any failing path. The failure messages point at $WORKDIR, so deleting
# it on the way out would advertise a log file that never exists -- the harness
# would be least debuggable exactly when it has something to report.
KEEP_WORKDIR=0

AWG_RUNDIR=/var/run/amneziawg
if [ -d "$AWG_RUNDIR" ]; then readonly AWG_RUNDIR_PREEXISTING=1; else readonly AWG_RUNDIR_PREEXISTING=0; fi

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '\033[1m==> %s\033[0m\n' "$1"; }
die()  { printf '\033[31mpreflight: %s\033[0m\n' "$1" >&2; exit 2; }

# Values parsed out of `awg` and `tcpdump` output are not guaranteed numeric:
# an error message or unexpected token reaching a `[ -gt ]` or `$(( ))` makes
# the shell print "integer expression expected", burying the real result in
# noise. Validate first, so a malformed value is reported as the check failing
# with the offending text quoted.
is_uint() { case "${1:-}" in ""|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
is_hex8() { case "${1:-}" in *[!0-9a-fA-F]*) return 1 ;; *) [ "${#1}" -eq 8 ] ;; esac; }

# Kill only what is inside our own namespace, via `ip netns pids`. Matching on
# the command line instead (`pkill -f "$IF_SRV"`) would also reap unrelated
# host processes that merely mention the interface name -- unacceptable in a
# script whose selling point is that it is safe to run on a shared host.
kill_server() {
  local pids
  pids=$(ip netns pids "$NS_SRV" 2>/dev/null)
  [ -n "$pids" ] && kill $pids >/dev/null 2>&1
  return 0
}

cleanup() {
  local rc=$?
  set +e
  # Only tear down what this run actually created.
  if [ "$SETUP_STARTED" -eq 1 ]; then
    kill_server
    for ns in "$NS_SRV" "$NS_CLI" "$NS_CLI2"; do ip netns del "$ns" >/dev/null 2>&1; done
    ip link del awgpoc-vs  >/dev/null 2>&1
    ip link del awgpoc-vs2 >/dev/null 2>&1
    rm -f "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock"
    # Remove the runtime directory only when this run created it, and only if empty.
    [ "$AWG_RUNDIR_PREEXISTING" -eq 0 ] && rmdir "$AWG_RUNDIR" >/dev/null 2>&1
  fi
  # The temp dir is unambiguously ours (unique mktemp name), but keep it when
  # a check failed so the logs it points at are still there.
  if [ "$KEEP_WORKDIR" -eq 1 ]; then
    printf 'logs preserved in %s\n' "$WORKDIR" >&2
  else
    [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR"
  fi
  return $rc
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- preflight --

BORINGTUN=${1:-}
[ -n "$BORINGTUN" ] || BORINGTUN=$(command -v boringtun-cli 2>/dev/null)
[ -n "$BORINGTUN" ] || BORINGTUN=target/release/boringtun-cli

# Make it absolute before anything changes directory. The script cd's into
# $WORKDIR, after which a relative path -- including the documented
# target/release fallback -- no longer resolves: the server fails to start and
# check 1 blames "awg setconf", having already reported preflight OK.
case "$BORINGTUN" in
  /*) ;;
  *) BORINGTUN="$(cd "$(dirname "$BORINGTUN")" 2>/dev/null && pwd)/$(basename "$BORINGTUN")" ;;
esac

[ "$(id -u)" -eq 0 ]              || die "must run as root (creates network namespaces)"
[ -x "$BORINGTUN" ]               || die "boringtun-cli not found or not executable: $BORINGTUN"
command -v awg >/dev/null         || die "amneziawg-tools (awg) not installed"
command -v ip  >/dev/null         || die "iproute2 (ip) not installed"
# Asserted rather than assumed: absent, these do not merely skip a check.
# Without tcpdump or timeout, check 6 reports a wire-format failure that is
# really a missing tool, and a misleading failure is worse than none in a
# script whose purpose is to be believed.
command -v tcpdump >/dev/null     || die "tcpdump not installed (needed by the wire-format check)"
command -v timeout >/dev/null     || die "timeout not installed (needed by the wire-format check)"
# Everything else the checks shell out to. Ordinary userland, but assert it
# anyway: absence produces a wrong diagnosis rather than an obvious one --
# without awk, check 6 reports "no H4 tag" as if the wire format were broken;
# without ping, checks 3 and 5 report a dead datapath; and without grep or
# lsmod the module check below reports the module as not loaded. ping is the
# realistic one: minimal images frequently ship without iputils.
for tool in awk cut date grep head lsmod ping; do
  command -v "$tool" >/dev/null || die "$tool not installed (used by preflight or the checks)"
done

lsmod | grep -q '^amneziawg'      || die "amneziawg kernel module not loaded -- the point of this test is a REAL client"
[ -e /dev/net/tun ]               || die "/dev/net/tun missing"

# Refuse to clobber anything that already exists under our names.
for ns in "$NS_SRV" "$NS_CLI" "$NS_CLI2"; do
  ip netns list 2>/dev/null | grep -qw "$ns" && die "namespace $ns already exists; refusing to touch it"
done
ip link show "$IF_SRV" >/dev/null 2>&1 && die "interface $IF_SRV already exists; refusing to touch it"
for veth in awgpoc-vs awgpoc-vc awgpoc-vs2 awgpoc-vc2; do
  ip link show "$veth" >/dev/null 2>&1 && die "interface $veth already exists; refusing to touch it"
done
for sock in "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock"; do
  [ -e "$sock" ] && die "$sock already exists; refusing to touch it"
done

info "preflight OK  (binary: $BORINGTUN, kernel module present)"

# ------------------------------------------------------------------- set up --

umask 077
cd "$WORKDIR" || die "cannot enter $WORKDIR"
awg genkey > srv.key; awg pubkey < srv.key > srv.pub
awg genkey > cli.key; awg pubkey < cli.key > cli.pub
awg genkey > cli2.key; awg pubkey < cli2.key > cli2.pub

SETUP_STARTED=1   # from here on, cleanup owns what it tears down

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
  # Poll for the socket `awg` actually opens, not the one boringtun binds
  # first: it binds /var/run/wireguard/<if>.sock and only then symlinks it
  # into /var/run/amneziawg/ (device/api.rs), so waiting on the former leaves
  # a window where the poll succeeds and setconf still cannot find the device.
  # A fixed sleep would be worse again -- a false negative on a loaded host.
  local waited=0
  while [ ! -e "/var/run/amneziawg/${IF_SRV}.sock" ]; do
    sleep 0.2
    waited=$((waited + 1))
    [ "$waited" -ge 50 ] && return 1   # 10s
  done
  ip netns exec "$NS_SRV" awg setconf "$IF_SRV" "$1" || return 1
  ip netns exec "$NS_SRV" sh -c "ip addr add 10.66.201.1/24 dev $IF_SRV && ip link set $IF_SRV up mtu 1420"
}
stop_server() {
  kill_server
  ip netns exec "$NS_SRV" ip link del "$IF_SRV" >/dev/null 2>&1
  rm -f "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock"
  sleep 1
}
# Returns non-zero on a setup failure, so a caller can distinguish "the client
# could not be configured" from "the client was configured and no traffic
# flowed". Reporting the former as the latter points debugging at the wrong
# half of the system.
start_client() {  # $1 = ns, $2 = conf, $3 = tunnel addr
  ip netns exec "$1" ip link add "$IF_CLI" type amneziawg || return 1
  ip netns exec "$1" awg setconf "$IF_CLI" "$2" || return 1
  ip netns exec "$1" sh -c "ip addr add $3/32 dev $IF_CLI && ip link set $IF_CLI up mtu 1420 && ip route add 10.66.201.1/32 dev $IF_CLI" || return 1
}

# --------------------------------------------------------------------- tests --

info "1. UAPI: awg setconf against a userspace implementation"
if start_server srv.conf; then
  ok "awg setconf accepted (implies the UAPI socket was discoverable)"
else
  bad "awg setconf failed -- see $WORKDIR/srv.log"
  KEEP_WORKDIR=1
  # `bad` already incremented FAIL; adding one here would over-report.
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"
  exit 1
fi

info "2. UAPI: showconf round-trips every AmneziaWG parameter"
# Capture stderr and test the exit status: if showconf itself fails, every one
# of the eleven key assertions would otherwise report "lost or altered" and
# bury the single real cause under eleven false ones.
if conf_out=$(ip netns exec "$NS_SRV" awg showconf "$IF_SRV" 2>&1); then
  for kv in "Jc = $JC" "Jmin = $JMIN" "Jmax = $JMAX" "S1 = $S1" "S2 = $S2" "S3 = $S3" "S4 = $S4" \
            "H1 = $H1" "H2 = $H2" "H3 = $H3" "H4 = $H4"; do
    if grep -qF "$kv" <<<"$conf_out"; then ok "showconf: $kv"; else bad "showconf lost or altered: $kv"; fi
  done
else
  bad "awg showconf failed, so no parameter could be checked: $conf_out"
fi

info "3. Handshake and bidirectional traffic from a kernel-module client"
if ! start_client "$NS_CLI" c1.conf 10.66.201.2; then
  bad "client setup failed (ip link add / awg setconf) -- not a datapath result"
elif ip netns exec "$NS_CLI" ping -c3 -W3 -q 10.66.201.1 >/dev/null 2>&1; then
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
if is_uint "$hs" && [ "$hs" -gt $((now - 300)) ] && [ "$hs" -le "$now" ]; then
  ok "handshake reported as a plausible epoch timestamp ($hs, now=$now)"
else
  bad "handshake timestamp is not a plausible epoch value: got '${hs:-<empty>}', now=$now"
fi

info "5. Multi-peer: a second peer added live to the running server"
if ! ip netns exec "$NS_SRV" awg set "$IF_SRV" peer "$(cat cli2.pub)" allowed-ips 10.66.201.3/32; then
  bad "server rejected the second peer (awg set) -- not a client or datapath result"
elif ! start_client "$NS_CLI2" c2.conf 10.66.201.3; then
  bad "second client setup failed (ip link add / awg setconf) -- not a datapath result"
elif ip netns exec "$NS_CLI2" ping -c3 -W3 -q 10.66.201.1 >/dev/null 2>&1; then
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
# Decode each captured frame and test the four bytes at the S4 offset against
# the configured H4 range. A length check alone would not do what this claims:
# a vanilla transport packet is also larger than S4, so it would pass even with
# obfuscation switched off. IPv4(20) + UDP(8) = 28 bytes precede the payload.
h4_lo=${H4%-*}; h4_hi=${H4#*-}
tag_off=$(( (28 + S4) * 2 ))
tag_found=0; frames=0
while read -r hex; do
  frames=$((frames + 1))
  [ "${#hex}" -ge $((tag_off + 8)) ] || continue
  b0=${hex:$tag_off:2};       b1=${hex:$((tag_off+2)):2}
  b2=${hex:$((tag_off+4)):2}; b3=${hex:$((tag_off+6)):2}
  is_hex8 "$b3$b2$b1$b0" || continue
  tag=$(( 0x$b3$b2$b1$b0 ))   # little-endian on the wire
  if [ "$tag" -ge "$h4_lo" ] && [ "$tag" -le "$h4_hi" ]; then
    ok "H4 tag $tag at offset $S4 is inside the configured range $H4"
    tag_found=1
    break
  fi
done <<EOF
$(ip netns exec "$NS_SRV" tcpdump -r "$WORKDIR/wire.pcap" -nn -x 2>/dev/null | awk '
  /^[[:space:]]*0x[0-9a-fA-F]+:/ { for (i = 2; i <= NF; i++) h = h $i; next }
  { if (h != "") print h; h = "" }
  END { if (h != "") print h }')
EOF
if [ "$frames" -eq 0 ]; then
  # Either nothing was captured, or the output could not be parsed. Both are
  # real possibilities and neither says anything about the wire format, so
  # name both rather than pointing debugging at the decoder.
  bad "no frames decoded: either no traffic was captured or the tcpdump output was not understood"
elif [ "$tag_found" -ne 1 ]; then
  bad "no captured frame carried an H4 tag at offset $S4 (frames examined: $frames)"
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
  # $WORKDIR is retained by cleanup when KEEP_WORKDIR is set, and cleanup
  # prints where it is -- so this no longer names a path that is about to go.
  KEEP_WORKDIR=1
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"
  exit 1
fi
