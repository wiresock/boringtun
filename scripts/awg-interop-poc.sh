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
#           (ip), tcpdump, timeout, ping, and these coreutils:
#           awk, cut, date, dd, grep, head, lsmod, od, tr.
#           Preflight enforces every one of them and names the missing tool,
#           because a missing dependency otherwise surfaces as a bogus test
#           failure rather than as a setup problem.
#
# A sibling, scripts/awg-go-interop.sh, makes the same cross-implementation
# claim against amneziawg-go instead of the kernel module. It needs no kernel
# headers, so it runs where this cannot -- but it exercises two userspace
# implementations, not the kernel datapath, so it complements this rather than
# replacing it.
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

readonly PORT=51820
# Checked: on failure this is empty, and `cd ""` succeeds in bash without
# changing directory, so the `cd "$WORKDIR" || die` below would not fire and
# every artifact would land in the invoking directory instead.
WORKDIR=$(mktemp -d /tmp/awg-interop-poc.XXXXXX) || {
  echo "preflight: could not create a temporary directory" >&2
  exit 2
}
readonly WORKDIR

# Every kernel-visible name carries a token from the `mktemp` directory, so no
# two runs -- and no unrelated workload -- can collide on one. That is what lets
# `cleanup` reason about ownership at all: with fixed names, a namespace called
# `awgpoc-srv` might be somebody else's, and preflight can only look for a
# collision, never prevent one opening between the check and the create.
#
# The whole token, all six characters: 62^6 rather than 62^4. The kernel allows
# 15 characters for an interface name, so the veths carry a shortened `awgp-`
# prefix to afford it -- the namespaces have no such limit and keep `awgpoc-`.
# Preflight asserts the resulting lengths rather than trusting this arithmetic
# to survive a rename.
#
# Entropy is not what makes cleanup safe -- the ownership lists below are. A
# collision here costs a run, because the loser's `ip netns add` fails and it
# exits having claimed nothing; it does not cost the winner its namespaces.
RUN=${WORKDIR##*.}
readonly RUN
readonly NS_SRV="awgpoc-srv-$RUN"
readonly NS_CLI="awgpoc-cli-$RUN"
readonly NS_CLI2="awgpoc-cli2-$RUN"
readonly IF_SRV="awgpoc0-$RUN"
readonly IF_CLI="awgpocc-$RUN"
readonly VETH_S1="awgp-vs-$RUN"
readonly VETH_C1="awgp-vc-$RUN"
readonly VETH_S2="awgp-vs2-$RUN"
readonly VETH_C2="awgp-vc2-$RUN"

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
# What this run has actually created, appended to only after the creating
# command reports success. A single "setup has started" flag could not say
# this: it was set before the first create and then claimed everything, so an
# `ip netns add` that failed *because the name was already taken* still left
# cleanup believing that namespace was ours. It also never cleared, so once set
# the claim outlived the resources.
#
# Emptied by `cleanup`, so nothing is claimed twice.
OWNED_NS=()
OWNED_LINKS=()
OWNED_SOCKS=()
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

# Same rule, over every namespace this run owns rather than just the server's.
kill_owned() {
  local ns pids
  for ns in ${OWNED_NS[@]+"${OWNED_NS[@]}"}; do
    pids=$(ip netns pids "$ns" 2>/dev/null)
    [ -n "$pids" ] && kill $pids >/dev/null 2>&1
  done
  return 0
}

cleanup() {
  local rc=$?
  set +e
  # Only tear down what this run actually created. Every loop below is over a
  # name some command of ours reported success for; a preflight refusal, or a
  # failure part-way through setup, leaves the rest unclaimed and untouched.
  local ns link sock
  kill_owned
  for ns in ${OWNED_NS[@]+"${OWNED_NS[@]}"}; do
    ip netns del "$ns" >/dev/null 2>&1
  done
  # Usually gone with the namespace they were moved into; this covers a failure
  # between creating a veth pair and moving it.
  for link in ${OWNED_LINKS[@]+"${OWNED_LINKS[@]}"}; do
    ip link del "$link" >/dev/null 2>&1
  done
  for sock in ${OWNED_SOCKS[@]+"${OWNED_SOCKS[@]}"}; do
    rm -f "$sock"
  done
  # Remove the runtime directory only when this run created it, and only if
  # empty. Unlike the names above this one is shared and host-managed, so the
  # pre-existing check is what stands in for ownership.
  if [ ${#OWNED_NS[@]} -gt 0 ] && [ "$AWG_RUNDIR_PREEXISTING" -eq 0 ]; then
    rmdir "$AWG_RUNDIR" >/dev/null 2>&1
  fi
  OWNED_NS=()
  OWNED_LINKS=()
  OWNED_SOCKS=()
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
  /*)
    # Already absolute.
    ;;
  */*)
    # A path with a directory component: resolve it via that directory, and
    # fail loudly if the directory does not exist. Letting the substitution
    # collapse would leave "/<basename>", which at best names a path the
    # caller never typed and at worst a different executable sitting in /.
    _dir=$(cd "$(dirname "$BORINGTUN")" 2>/dev/null && pwd)
    [ -n "$_dir" ] || die "cannot resolve $BORINGTUN: no such directory"
    BORINGTUN="$_dir/$(basename "$BORINGTUN")"
    ;;
  *)
    # A bare command name. dirname would make this "./<name>" and look only
    # in the current directory, so an installed boringtun-cli would be
    # reported as missing. Resolve it the way the shell would.
    _resolved=$(command -v "$BORINGTUN" 2>/dev/null)
    [ -n "$_resolved" ] || die "$BORINGTUN not found on PATH"
    BORINGTUN=$_resolved
    ;;
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
for tool in awk cut date dd grep head lsmod od ping tr; do
  command -v "$tool" >/dev/null || die "$tool not installed (used by preflight or the checks)"
done

# The probe checks send UDP through bash's /dev/udp, which is a compile-time
# option (--enable-net-redirections). Without it every probe fails to send, and
# a check that asserts *silence* would score that as a pass. Assert it here
# rather than let the harness quietly test nothing.
bash -c 'exec 3<>/dev/udp/127.0.0.1/9' 2>/dev/null \
  || die "this bash has no /dev/udp support (needed by the probe-reply checks)"

lsmod | grep -q '^amneziawg'      || die "amneziawg kernel module not loaded -- the point of this test is a REAL client"
[ -e /dev/net/tun ]               || die "/dev/net/tun missing"

# Refuse to clobber anything that already exists under our names.
for ns in "$NS_SRV" "$NS_CLI" "$NS_CLI2"; do
  ip netns list 2>/dev/null | grep -qw "$ns" && die "namespace $ns already exists; refusing to touch it"
done
ip link show "$IF_SRV" >/dev/null 2>&1 && die "interface $IF_SRV already exists; refusing to touch it"
for veth in "$VETH_S1" "$VETH_C1" "$VETH_S2" "$VETH_C2"; do
  ip link show "$veth" >/dev/null 2>&1 && die "interface $veth already exists; refusing to touch it"
done
# The names above are generated, so their length is a property of this script
# rather than of the environment. `ip link add` would otherwise fail well into
# setup with a message that says nothing about a rename being the cause.
for ifname in "$IF_SRV" "$IF_CLI" "$VETH_S1" "$VETH_C1" "$VETH_S2" "$VETH_C2"; do
  [ "${#ifname}" -le 15 ] || die "generated interface name '$ifname' is ${#ifname} characters; the kernel allows 15"
done
for sock in "/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock"; do
  [ -e "$sock" ] && die "$sock already exists; refusing to touch it"
done

info "preflight OK  (binary: $BORINGTUN, kernel module present)"

# ------------------------------------------------------------------- set up --

# Abort on the first failure for the whole setup phase. Without it a failed
# `ip netns add` or `awg genkey` leaves a half-built topology, and every check
# below then reports an interop failure that is really setup breakage.
# Disabled again before the checks, which inspect non-zero exits themselves.
set -e
umask 077
cd "$WORKDIR" || die "cannot enter $WORKDIR"
awg genkey > srv.key; awg pubkey < srv.key > srv.pub
awg genkey > cli.key; awg pubkey < cli.key > cli.pub
awg genkey > cli2.key; awg pubkey < cli2.key > cli2.pub

# Each name is claimed by the command that created it, on the line after that
# command reported success. `set -e` is in force here, so a failed create exits
# before its claim is recorded and cleanup never reaches for it.
ip netns add "$NS_SRV";  OWNED_NS+=("$NS_SRV")
ip netns add "$NS_CLI";  OWNED_NS+=("$NS_CLI")
ip netns add "$NS_CLI2"; OWNED_NS+=("$NS_CLI2")
ip link add "$VETH_S1" type veth peer name "$VETH_C1"; OWNED_LINKS+=("$VETH_S1" "$VETH_C1")
ip link add "$VETH_S2" type veth peer name "$VETH_C2"; OWNED_LINKS+=("$VETH_S2" "$VETH_C2")
ip link set "$VETH_S1" netns "$NS_SRV";  ip link set "$VETH_C1" netns "$NS_CLI"
ip link set "$VETH_S2" netns "$NS_SRV";  ip link set "$VETH_C2" netns "$NS_CLI2"

ip netns exec "$NS_SRV" sh -c "ip link set lo up
  ip addr add 10.201.0.1/30 dev $VETH_S1 && ip link set $VETH_S1 up
  ip addr add 10.201.1.1/30 dev $VETH_S2 && ip link set $VETH_S2 up"
ip netns exec "$NS_CLI"  sh -c "ip link set lo up; ip addr add 10.201.0.2/30 dev $VETH_C1 && ip link set $VETH_C1 up"
ip netns exec "$NS_CLI2" sh -c "ip link set lo up; ip addr add 10.201.1.2/30 dev $VETH_C2 && ip link set $VETH_C2 up"

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
  k=cli.key; ep=10.201.0.1
  if [ "$n" = 2 ]; then k=cli2.key; ep=10.201.1.1; fi
  write_iface_conf "c$n.conf" "$(cat $k)" "${OBF_LINES[@]}"
  printf '\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = 10.66.201.1/32\nPersistentKeepalive = 25\n' \
    "$(cat srv.pub)" "$ep" "$PORT" >> "c$n.conf"
done

# Extra boringtun-cli flags for the next start_server. Protocol imitation has
# no UAPI key -- `awg showconf` drops keys it does not know -- so it can only be
# set on the command line, which means the probe checks have to restart the
# daemon rather than reconfigure it.
SRV_EXTRA_ARGS=()
start_server() {  # $1 = config file; SRV_EXTRA_ARGS = extra daemon flags
  # `${a[@]+"${a[@]}"}` rather than `"${a[@]}"`: under `set -u` an empty array
  # expansion is an unbound-variable error on bash before 4.4.
  # Claimed before the launch, not after the socket appears: a daemon that
  # starts and then hangs still leaves these behind, and `$IF_SRV` carries this
  # run's token so no other run can own the paths.
  OWNED_SOCKS+=("/var/run/wireguard/${IF_SRV}.sock" "/var/run/amneziawg/${IF_SRV}.sock")
  ip netns exec "$NS_SRV" env WG_LOG_FILE="$WORKDIR/srv.log" \
    "$BORINGTUN" --disable-drop-privileges \
    ${SRV_EXTRA_ARGS[@]+"${SRV_EXTRA_ARGS[@]}"} "$IF_SRV" >/dev/null 2>&1
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
  # Optional: exercise the window between binding the UDP socket and having a
  # private key. `DeviceHandle::new` binds before any `private_key=` can
  # arrive, so a datagram here reaches a keyless device. It used to hit
  # `expect("Key not set")` in the ingress handler and kill an ingress worker
  # for the life of the process.
  #
  # Thread count is the observable, not "does the tunnel still work": the
  # daemon runs several ingress workers, so losing one leaves the others
  # serving traffic and every downstream check still passes.
  if [ "${PRE_KEY_PROBE:-0}" = "1" ]; then
    PRE_KEY_PORT=$(ip netns exec "$NS_SRV" awg show "$IF_SRV" listen-port 2>/dev/null)
    PRE_KEY_PID=$(ip netns pids "$NS_SRV" 2>/dev/null | head -1)
    if is_uint "$PRE_KEY_PORT" && [ "$PRE_KEY_PORT" -gt 0 ] && [ -d "/proc/$PRE_KEY_PID/task" ]; then
      PRE_KEY_THREADS_BEFORE=$(ls "/proc/$PRE_KEY_PID/task" | wc -l)
      # utime+stime in clock ticks, fields 14 and 15 of /proc/<pid>/stat.
      # Read from after the last ')' so a comm containing spaces or parens
      # cannot shift the field offsets, and strip the leading blank explicitly.
      # POSIX makes a single-blank separator mean "split on runs of blanks,
      # ignoring leading ones" -- verified against gawk and mawk -- so the sub()
      # is redundant, but it states the intent without relying on that rule.
      PRE_KEY_CPU_BEFORE=$(awk -F')' '{s=$NF; sub(/^[[:blank:]]+/,"",s); split(s,f," "); print f[12]+f[13]}' "/proc/$PRE_KEY_PID/stat")
      # Anything at all: with no key configured the daemon cannot classify it,
      # which is the point.
      # bash's /dev/udp rather than socat or nc: no new preflight dependency,
      # and the harness already requires bash.
      ip netns exec "$NS_SRV" timeout 2 bash -c         "printf 'x' > /dev/udp/127.0.0.1/$PRE_KEY_PORT" >/dev/null 2>&1
      sleep 1
      PRE_KEY_THREADS_AFTER=$(ls "/proc/$PRE_KEY_PID/task" | wc -l)
      PRE_KEY_CPU_AFTER=$(awk -F')' '{s=$NF; sub(/^[[:blank:]]+/,"",s); split(s,f," "); print f[12]+f[13]}' "/proc/$PRE_KEY_PID/stat")
    else
      PRE_KEY_THREADS_BEFORE=skip
      PRE_KEY_THREADS_AFTER=skip
    fi
  fi

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

# A DNS query for example.com/A/IN with transaction id 0xabcd and RD set: the
# 12-byte header, then the QNAME as length-prefixed labels, then QTYPE/QCLASS.
# `\x07example` is unambiguous -- bash's printf takes at most two hex digits
# after \x -- and the whole thing is 29 bytes.
readonly DNS_PROBE='\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'

# Send one datagram and print the reply as lowercase hex. Three other outcomes
# are distinguishable from a reply and from each other: empty means the datagram
# was sent and nothing came back, `SENDFAIL` means the probe ran but could not
# send, and `HARNESSFAIL(rc=N)` means the probe never ran at all.
#
# Distinguishing those two is the whole point. The checks below assert
# *silence*, so a probe that never left the namespace -- a bash without
# /dev/udp support, a broken route, a missing netns -- would otherwise score as
# a PASS, and the harness would report that the responder is correctly inert
# while having tested nothing.
#
# bash's /dev/udp rather than a new dependency on socat or dig, and a single
# `dd` read rather than `head -c`: one read() on a datagram socket returns
# exactly one datagram, whereas `head -c N` blocks for an EOF that a UDP socket
# never delivers, so `timeout` would kill it before it printed.
#
# `printf '%b'` rather than `printf "$P_FMT"`: the payload is data, and passing
# it as the *format* means a future probe containing a `%` produces garbage or
# an error -- which, again, the silence checks would score as a PASS.
udp_probe() { # <ns> <dst-ip> <dst-port> <printf-escapes-for-payload>
  local out rc
  out=$(ip netns exec "$1" env P_IP="$2" P_PORT="$3" P_FMT="$4" timeout 3 bash -c '
    exec 3<>/dev/udp/$P_IP/$P_PORT || { echo SENDFAIL; exit 0; }
    printf "%b" "$P_FMT" >&3 || { echo SENDFAIL; exit 0; }
    dd bs=512 count=1 <&3 2>/dev/null | od -An -tx1 | tr -d " \n"
  ' 2>/dev/null)
  rc=$?

  # The inner script handles its own failures and always exits 0, so a non-zero
  # status here is the *harness* failing before the probe ever ran: a missing
  # namespace, no `timeout` or `bash` on PATH, `ip netns exec` refused. Those
  # produce no output either, so without this they would arrive at the callers
  # as an empty string and be scored as silence -- which is exactly the
  # confusion `SENDFAIL` was added to remove, just one level further out.
  #
  # 124 is the exception: that is `timeout` killing a `dd` that is still waiting
  # for a reply, which is the ordinary no-answer case and the thing the silence
  # checks are actually asserting.
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    echo "HARNESSFAIL(rc=$rc)"
    return 0
  fi
  printf '%s' "$out"
}

# Assert that a probe was delivered and drew no reply, keeping "could not send"
# distinct from "sent, no answer".
expect_silence() { # <label> <reply-from-udp_probe>
  case "$2" in
    SENDFAIL)      bad "$1: the probe could not be sent -- harness failure, not a result" ;;
    HARNESSFAIL*)  bad "$1: the probe never ran ($2) -- harness failure, not a result" ;;
    "")            ok  "$1" ;;
    *)             bad "$1: answered with $2" ;;
  esac
}

# Checks from here on inspect exit statuses themselves.
set +e

# --------------------------------------------------------------------- tests --

info "1. UAPI: awg setconf against a userspace implementation"
if PRE_KEY_PROBE=1 start_server srv.conf; then
  ok "awg setconf accepted (implies the UAPI socket was discoverable)"
else
  bad "awg setconf failed -- see $WORKDIR/srv.log"
  KEEP_WORKDIR=1
  # `bad` already incremented FAIL; adding one here would over-report.
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"
  exit 1
fi

info "1b. A datagram arriving before the private key must not kill a worker"
case "$PRE_KEY_THREADS_BEFORE" in
  skip|"") bad "could not probe the pre-key window (port='${PRE_KEY_PORT:-}', pid='${PRE_KEY_PID:-}')" ;;
  *)
    if [ "$PRE_KEY_THREADS_BEFORE" = "$PRE_KEY_THREADS_AFTER" ]; then
      ok "thread count unchanged across a pre-key datagram ($PRE_KEY_THREADS_AFTER)"
    else
      bad "worker died on a pre-key datagram: $PRE_KEY_THREADS_BEFORE -> $PRE_KEY_THREADS_AFTER threads"
    fi
    # Surviving is not enough: a handler that returns without consuming the
    # datagram leaves the socket readable, epoll re-arms it on guard drop and
    # re-dispatches immediately, and the worker spins. Over a 1 s idle window a
    # healthy daemon burns ~0 ticks; a spinning one burns ~100 per busy core.
    # Guard the arithmetic: an unreadable /proc entry yields an empty string,
    # and `$(( ))` would print a shell error rather than a check result. Every
    # other numeric read in this script goes through `is_uint` for the same
    # reason.
    if ! is_uint "$PRE_KEY_CPU_BEFORE" || ! is_uint "$PRE_KEY_CPU_AFTER"; then
      bad "could not read CPU time (before='${PRE_KEY_CPU_BEFORE:-}', after='${PRE_KEY_CPU_AFTER:-}')"
    else
      cpu_delta=$(( PRE_KEY_CPU_AFTER - PRE_KEY_CPU_BEFORE ))
      if [ "$cpu_delta" -le 20 ]; then
        ok "no busy-loop after a pre-key datagram (${cpu_delta} ticks over 1s)"
      else
        bad "daemon is spinning after a pre-key datagram: ${cpu_delta} ticks over 1s"
      fi
    fi ;;
esac

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

# `get=1` reads allowed IPs out of the device's routing trie, which is keyed
# by prefix rather than by peer. Getting each peer its own prefixes back --
# and nobody else's -- is the part that a grouping bug would silently break,
# and neither ping proves it: the datapath would still work if `awg show`
# attributed every prefix to one peer.
aips=$(ip netns exec "$NS_SRV" awg show "$IF_SRV" allowed-ips)
check_allowed_ips() { # <pubkey-file> <expected-prefix-list>
  local line got
  line=$(grep -F "$(cat "$1")" <<<"$aips" || true)
  # Compare the whole field list, so an extra prefix fails as loudly as a
  # missing one -- attributing another peer's prefix here is the worse bug.
  got=$(cut -f2- <<<"$line")
  if [ "$got" = "$2" ]; then
    ok "awg show attributes $2 to its own peer, and only that"
  else
    bad "wrong allowed-ips for $1: expected '$2', got '${got:-<no line>}'"
  fi
}
check_allowed_ips cli.pub 10.66.201.2/32
check_allowed_ips cli2.pub 10.66.201.3/32

info "6. Wire format: the S-prefix and H-range tag are really on the wire"
# Without this, tests 3 and 5 would also pass if both ends silently agreed to
# speak vanilla WireGuard -- which would prove nothing about obfuscation.
ip netns exec "$NS_SRV" timeout 10 tcpdump -i "$VETH_S1" -c 2 -w "$WORKDIR/wire.pcap" udp port "$PORT" >/dev/null 2>&1 &
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

info "7. Probe replies: the port answers the protocol it imitates, and only that"
# The camouflage claim is bidirectional: a port that emits DNS-shaped datagrams
# and answers no DNS query describes a host that does not exist. Nothing below
# is reachable from a unit test -- it needs the real ingress path, a real socket
# and a real source address.

# 7a. The server from checks 1-6 has no imitation configured, so the responder
# must be inert. This is the control that gives the next two checks meaning: if
# the port answered here, 7c would prove nothing about the imitation setting.
probe_reply=$(udp_probe "$NS_CLI" 10.201.0.1 "$PORT" "$DNS_PROBE")
expect_silence "no imitation configured: a DNS probe gets silence" "$probe_reply"

# 7b. Imitating STUN. A DNS probe is detected -- the classifier does not care
# what we configured -- but must not be answered, because answering every
# protocol on one port describes a host that does not exist either.
stop_server
SRV_EXTRA_ARGS=(--imitate-protocol stun)
if start_server srv.conf; then
  probe_reply=$(udp_probe "$NS_CLI" 10.201.0.1 "$PORT" "$DNS_PROBE")
  expect_silence "imitating STUN: a DNS probe gets silence" "$probe_reply"
else
  bad "could not start the STUN-imitating server -- not a probe-reply result"
fi

# 7b2. The kill switch. Imitation on, replies explicitly off. This is the knob
# an operator reaches for if the responder ever becomes a liability, so it is
# worth knowing it works separately from the protocol setting.
stop_server
SRV_EXTRA_ARGS=(--imitate-protocol dns --probe-reply-rate 0)
if start_server srv.conf; then
  probe_reply=$(udp_probe "$NS_CLI" 10.201.0.1 "$PORT" "$DNS_PROBE")
  expect_silence "imitating DNS with --probe-reply-rate 0: silence" "$probe_reply"
else
  bad "could not start the server with replies disabled -- not a probe-reply result"
fi

# 7c. Imitating DNS. Now the same probe must come back as a SERVFAIL that a
# resolver client would accept: the transaction id echoed (otherwise every
# client discards it), QR set, RD copied from the query (a resolver answering a
# recursion-desired query with RD clear is its own tell) and RCODE 2.
stop_server
SRV_EXTRA_ARGS=(--imitate-protocol dns)
if ! start_server srv.conf; then
  bad "could not start the DNS-imitating server -- not a probe-reply result"
else
  probe_reply=$(udp_probe "$NS_CLI" 10.201.0.1 "$PORT" "$DNS_PROBE")
  # 24 hex chars = the 12-byte header; anything shorter cannot be parsed at all.
  case "$probe_reply" in
    SENDFAIL|HARNESSFAIL*)
      bad "imitating DNS: the probe never reached the server ($probe_reply) -- harness failure, not a result" ;;
  esac
  if [ "${#probe_reply}" -lt 24 ]; then
    bad "imitating DNS: no usable reply to a DNS probe (got '${probe_reply:-<silence>}')"
  else
    id=${probe_reply:0:4}
    b2=${probe_reply:4:2}
    b3=${probe_reply:6:2}
    if ! is_hex8 "0000$b2$b3"; then
      bad "imitating DNS: reply header is not hex: '$probe_reply'"
    else
      flags_ok=1
      [ "$id" = "abcd" ] || { bad "transaction id not echoed: sent abcd, got $id"; flags_ok=0; }
      [ $(( 0x$b2 & 0x80 )) -ne 0 ] || { bad "QR bit clear: the reply is not marked as a response"; flags_ok=0; }
      [ $(( 0x$b2 & 0x01 )) -eq 1 ] || { bad "RD not copied from the query"; flags_ok=0; }
      [ $(( 0x$b3 & 0x0f )) -eq 2 ] || { bad "RCODE is $(( 0x$b3 & 0x0f )), expected 2 (SERVFAIL)"; flags_ok=0; }
      [ "$flags_ok" -eq 1 ] && ok "imitating DNS: probe answered with a well-formed SERVFAIL ($probe_reply)"
    fi
  fi

  # 7d. The ordering guarantee against a *real* client. Under `ip=dns` our own
  # S-junk is a valid DNS query by construction, so a server that asked "is this
  # a probe?" before "is this one of my peers?" would SERVFAIL its own clients'
  # handshakes. The unit test
  # `a_conforming_initiation_is_tunnel_traffic_even_though_it_is_a_valid_dns_query`
  # pins that deterministically; this is the kernel-module confirmation.
  #
  # `-w 30`, not `-W3`. Checks 7b and 7c each restarted the daemon, so the
  # server has no session for a peer the *client* still considers valid. Kernel
  # WireGuard does not re-initiate on the first dropped packet: it arms
  # `timer_new_handshake` only after KEEPALIVE_TIMEOUT + REKEY_TIMEOUT = 15 s.
  # A 5-second ping would report "classification order is wrong" for a timer it
  # never waited on -- pointing a reviewer at the one thing that is not broken.
  # `-c3` still exits as soon as three replies arrive, so a healthy run is fast.
  if ip netns exec "$NS_CLI" ping -c3 -w 30 -q 10.66.201.1 >/dev/null 2>&1; then
    ok "a real AmneziaWG client still handshakes while the port answers probes"
  else
    bad "no traffic from a real client while the port answers probes -- either the classification order is wrong or the re-handshake did not happen within 30s"
  fi
fi
SRV_EXTRA_ARGS=()

info "8. NEGATIVE CONTROL: a vanilla server must NOT serve an AmneziaWG client"
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
