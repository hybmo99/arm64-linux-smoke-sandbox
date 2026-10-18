#!/usr/bin/env bash
# Synthetic GitHub-hosted ARM64 Tier-0B probe: does an nftables `socket cgroupv2` rule ACTUALLY block one systemd service and only that one?
# NO PRIVATE CODE.  Installs no packages, makes no external connection (no DNS, no internet, no API), reads no secret, touches no host firewall.
#
# Everything happens inside a uniquely named, disposable network namespace that has only a loopback interface:
#   listener  - a transient systemd service (own slice) bound to 127.0.0.1:PORT inside the namespace
#   target    - a transient systemd service (own slice) whose agent connects to the listener when asked
#   control   - a second transient systemd service (a DIFFERENT slice) whose agent does the same
# All namespace work uses `nsenter --net=` (in_ns), NOT `ip netns exec`: the latter swaps in a fresh /sys, which hides /sys/fs/cgroup, and nft then cannot resolve a cgroup
# path ("cgroupv2 path fails: No such file or directory" - observed in the v2 hosted run 39157494544).  nsenter joins only the network namespace.
# Phases: (1) both connect  (2) install ONE nft table INSIDE the namespace: reject the target's cgroup, count the control's  (3) target refused,
# control still connects, counters prove which rule matched  (4) delete the table: target connects again.  Then cleanup and a residue check.
# Exit codes: 0 PASS; 30 INCOMPLETE (platform lacks something, or the host baseline cannot be read completely; not a pass); 40-59 FAIL (59 = the host
# state differs from its baseline, also after a FAILED run); 143 terminated.  `cleanup-verify` (the always-run workflow step) compares the persisted baseline one
# last time and is the only place that removes it:  CLEAN 0, RESIDUE / HOST_CHANGED / HOST_UNVERIFIED 1.  Never falls back to the host firewall.
#   sudo --preserve-env=GITHUB_RUN_ID,ImageVersion,ImageOS bash scripts/egress_enforcement.sh            # the probe (root)
#   sudo --preserve-env=GITHUB_RUN_ID bash scripts/egress_enforcement.sh cleanup-verify                  # idempotent cleanup + residue check
set -Eeuo pipefail
umask 077

PORT=18080
LIFETIME=150          # seconds the listener and the agents may live (systemd RuntimeMaxSec=160 is the backstop)
VERDICT=INCOMPLETE
CLEANED=0
NS="" WORK="" RPC="" TABLE="" RUN_ID="" BASELINE_FILE="" STARTED_FILE="" HOST_COMPARED=0
U_TARGET="" U_CONTROL="" U_LISTEN="" S_TARGET="" S_CONTROL="" S_LISTEN=""
NS_ID="" HOST_NS_ID="" HOST_BEFORE="" N_LEVEL="" MATCH_T="" MATCH_C=""
V_PID="" V_CG="" A_JSON="" DENY_PKTS="" CTRL_PKTS=""
PID_TARGET="" PID_CONTROL="" PID_LISTEN="" CG_TARGET="" CG_CONTROL="" CG_LISTEN=""

harden_env() { export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin; }
log() { printf '%s\n' "$*"; }
log_err() { printf '%s\n' "$*" >&2; }
fail() { local code=$1; shift; log "FAIL: $*"; VERDICT=FAIL; exit "$code"; }
incomplete() { local code=$1; shift; log "INCOMPLETE: $*"; VERDICT=INCOMPLETE; exit "$code"; }

# ---- primitives that read the platform (small, so a test can stand in for them) --------------------------------------------------------------------
platform_identity() {   # prints: machine id version pid1
  local machine id version pid1
  machine=$(uname -m); id=""; version=""
  if [[ -r /etc/os-release ]]; then id=$(. /etc/os-release; printf '%s' "${ID:-}"); version=$(. /etc/os-release; printf '%s' "${VERSION_ID:-}"); fi
  pid1=$(ps -p 1 -o comm= | tr -d '[:space:]')
  printf '%s %s %s %s\n' "$machine" "$id" "$version" "$pid1"
}
proc_cgroup() { awk -F: '$1==0 && $2=="" {print $3; found=1; exit} END {if (!found) exit 1}' "/proc/$1/cgroup"; }
proc_comm()   { cat "/proc/$1/comm"; }
proc_netns()  { readlink "/proc/$1/ns/net"; }
netns_file_id() { printf 'net:[%s]\n' "$(stat -L -c %i "/run/netns/$1")"; }
# in_ns CMD... : run CMD with ONLY the network namespace of the disposable namespace joined (mounts, /sys and cgroup visibility stay the host's).  The single place
# any firewall or interface command enters the namespace.
in_ns() { timeout 10 nsenter --net="/run/netns/$NS" -- "$@"; }
ns_current_id()         { in_ns readlink /proc/self/ns/net; }
cgroup_fstype_ns()      { in_ns stat -f -c %T /sys/fs/cgroup; }
cgroup_fstype_host()    { stat -f -c %T /sys/fs/cgroup; }
cgroup_dir_visible_ns() { in_ns test -d "/sys/fs/cgroup/$1"; }

# ---- names: derived ONLY from the numeric run id, so a collision or a stray cleanup cannot touch anything else ------------------------------------
init_names() {
  local run_id="${GITHUB_RUN_ID:-}"
  [[ "$run_id" =~ ^[0-9]{1,18}$ ]] || incomplete 30 "GITHUB_RUN_ID is not a plain number; refusing to derive names"
  NS="t0b${run_id}"; TABLE="t0b${run_id}"
  S_TARGET="t0btarget${run_id}.slice"; S_CONTROL="t0bcontrol${run_id}.slice"; S_LISTEN="t0blisten${run_id}.slice"
  U_TARGET="t0b-target-${run_id}.service"; U_CONTROL="t0b-control-${run_id}.service"; U_LISTEN="t0b-listen-${run_id}.service"
  BASELINE_FILE="/run/t0b-baseline-${run_id}"      # deliberately NOT matched by the work-directory glob: it must outlive a cleanup, a killed probe and the probe's own exit
  STARTED_FILE="/run/t0b-started-${run_id}"        # written right after the baseline; its presence means "a baseline WAS taken", so a vanished baseline is detectable
  RUN_ID="$run_id"
}

# ---- host snapshot: firewall (counters stripped), interfaces, addresses, routes, namespaces ------------------------------------------------------------
# FAIL CLOSED: any command that fails, or an implausible result (no loopback interface listed), makes the whole snapshot fail - a partial or error-text
# "snapshot" must never be comparable.  Diagnostics go to stderr so they can never become snapshot content.
snap_part() {   # snap_part TITLE CMD... : one section; its failure fails the snapshot
  local title=$1 out; shift
  out=$("$@" 2>&1) || { log_err "host snapshot: '$*' failed: $(printf '%s' "$out" | head -c 200)"; return 1; }
  printf '## %s\n%s\n' "$title" "$out"
}
host_snapshot() {
  local rules links
  rules=$(nft list ruleset 2>&1) || { log_err "host snapshot: 'nft list ruleset' failed: $(printf '%s' "$rules" | head -c 200)"; return 1; }
  printf '## nft ruleset\n%s\n' "$(printf '%s\n' "$rules" | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/')"
  links=$(ip -br link 2>&1) || { log_err "host snapshot: 'ip -br link' failed: $(printf '%s' "$links" | head -c 200)"; return 1; }
  printf '%s\n' "$links" | grep -q '^lo[[:space:]]' || { log_err "host snapshot: no loopback interface in 'ip -br link' output"; return 1; }
  printf '## links\n%s\n' "$links"
  snap_part addresses ip -br addr || return 1
  snap_part routes ip route || return 1
  snap_part namespaces ip netns list || return 1
}
compare_host_state() {   # read-only; 0 = identical to the baseline (or none was ever recorded); 1 = changed or not verifiable
  local baseline after
  HOST_COMPARED=1
  if [[ -z "$BASELINE_FILE" || ! -f "$BASELINE_FILE" ]]; then log "HOST-STATE: no baseline file present (none was taken in this process or it was already consumed); nothing to compare here"; return 0; fi
  baseline=$(cat "$BASELINE_FILE")
  after=$(host_snapshot) || { log "HOST-STATE: the current host state could not be read completely, so it cannot be shown to be unchanged"; return 1; }
  if [[ "$after" != "$baseline" ]]; then
    log "HOST-STATE CHANGED (baseline vs now):"; diff <(printf '%s\n' "$baseline") <(printf '%s\n' "$after") | head -n 30 || true
    return 1
  fi
  log "HOST-STATE: unchanged from the baseline (sha256 $(printf '%s' "$after" | sha256sum | cut -c1-16))"
}

# ---- cleanup: idempotent, and only the names derived above ------------------------------------------------------------------------------------------
cleanup() {
  [[ "$CLEANED" == 1 ]] && return 0
  CLEANED=1
  set +e
  local unit
  for unit in "$U_TARGET" "$U_CONTROL" "$U_LISTEN"; do
    [[ -n "$unit" ]] || continue
    systemctl stop "$unit" >/dev/null 2>&1
    systemctl reset-failed "$unit" >/dev/null 2>&1
  done
  for unit in "$S_TARGET" "$S_CONTROL" "$S_LISTEN"; do   # an emptied transient slice stays loaded (and its cgroup directory stays) until it is stopped: run 39157494544 left all three
    [[ -n "$unit" ]] || continue
    systemctl stop "$unit" >/dev/null 2>&1
    systemctl reset-failed "$unit" >/dev/null 2>&1
  done
  if [[ -n "$NS" ]] && ip netns list 2>/dev/null | grep -q "^${NS}\([[:space:]]\|$\)"; then
    ip netns delete "$NS" >/dev/null 2>&1           # deleting the namespace destroys its firewall state: no separate (and possibly mis-aimed) table delete is needed
  fi
  if [[ "$RUN_ID" =~ ^[0-9]{1,18}$ ]]; then   # the glob can only match this run's own directories (the run id is numeric and validated)
    local dir
    for dir in /run/t0b-"$RUN_ID".*; do [[ -d "$dir" ]] && rm -rf -- "$dir"; done
  fi
  set -e
  return 0
}
verify_clean() {   # nothing of this run may remain: units, slices, cgroup directories, namespace, work directory
  local bad=0 out slice i
  out=$(systemctl list-units --all --plain --no-legend "t0b-*-${RUN_ID}.service" 2>/dev/null | awk '{print $1}')
  [[ -z "$out" ]] || { log "RESIDUE: units: $out"; bad=1; }
  out=$(systemctl list-units --all --plain --no-legend --type=slice "t0b*${RUN_ID}.slice" 2>/dev/null | awk '{print $1}')
  [[ -z "$out" ]] || { log "RESIDUE: slice units: $out"; bad=1; }
  for i in 1 2 3 4 5 6 7 8 9 10; do
    out=""
    for slice in "$S_TARGET" "$S_CONTROL" "$S_LISTEN"; do
      [[ -e "/sys/fs/cgroup/$slice" ]] && out="$out $slice"
    done
    [[ -z "$out" ]] && break
    sleep 0.5
  done
  [[ -z "$out" ]] || { log "RESIDUE: cgroups:$out"; bad=1; }
  if ip netns list 2>/dev/null | grep -q "^${NS}\([[:space:]]\|$\)"; then log "RESIDUE: namespace $NS"; bad=1; fi
  if compgen -G "/run/t0b-${RUN_ID}.*" >/dev/null; then log "RESIDUE: work directory"; bad=1; fi
  return "$bad"
}

# ---- embedded synthetic helpers (stdlib Python; written to the private work directory at run time) -------------------------------------------------
write_helpers() {
  cat >"$WORK/listener.py" <<'PY'
import json, os, socket, sys, time
port, log_path, ready_path, lifetime = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4])
def cgroup():
    for line in open("/proc/self/cgroup"):
        if line.startswith("0::"):
            return line[3:].strip()
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
srv.settimeout(0.5)
tmp = ready_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump({"pid": os.getpid(), "cgroup": cgroup(), "netns": os.readlink("/proc/self/ns/net"), "bound": list(srv.getsockname())}, fh)
os.replace(tmp, ready_path)
deadline = time.monotonic() + lifetime
while time.monotonic() < deadline:
    try:
        conn, peer = srv.accept()
    except socket.timeout:
        continue
    with conn:
        with open(log_path, "a") as fh:            # the accept is logged BEFORE the client is answered, so a client that sees OK has been counted
            fh.write("accept %s:%d\n" % peer)
            fh.flush()
            os.fsync(fh.fileno())
        conn.sendall(b"OK\n")
PY
  cat >"$WORK/agent.py" <<'PY'
import errno, glob, json, os, socket, sys, time
name, rpc, port, lifetime = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
def cgroup():
    for line in open("/proc/self/cgroup"):
        if line.startswith("0::"):
            return line[3:].strip()
def put(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)
ident = {"name": name, "pid": os.getpid(), "cgroup": cgroup(), "netns": os.readlink("/proc/self/ns/net")}
put(os.path.join(rpc, name + ".hello.json"), ident)
deadline = time.monotonic() + lifetime
done = set()
while time.monotonic() < deadline:
    for req in sorted(glob.glob(os.path.join(rpc, name + ".req.*"))):
        if req.endswith(".tmp") or req in done:
            continue
        done.add(req)
        seq = req.rsplit(".", 1)[1]
        result = dict(ident, seq=seq, ok=False, errno=None, errname=None, reply=None, local=None, peer=["127.0.0.1", port])
        started = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # created HERE, by the service, after it joined the namespace and its cgroup
        sock.settimeout(3.0)
        try:
            sock.connect(("127.0.0.1", port))
            result["local"] = list(sock.getsockname())
            result["reply"] = sock.recv(16).decode("ascii", "replace").strip()
            result["ok"] = result["reply"] == "OK"
        except socket.timeout:
            result["errname"] = "TIMEOUT"
        except OSError as error:
            result["errno"], result["errname"] = error.errno, errno.errorcode.get(error.errno, "OSERROR")
        finally:
            sock.close()
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        put(os.path.join(rpc, "%s.res.%s.json" % (name, seq)), result)
        os.unlink(req)
    time.sleep(0.05)
PY
  cat >"$WORK/tools.py" <<'PY'
import json, re, sys
def jget(path, *keys):
    value = json.load(open(path))
    for key in keys:
        value = value[int(key)] if isinstance(value, list) else value[key]
    print(str(value).lower() if isinstance(value, bool) else value)
def counters(path):
    """packets matched by the rule commented t0b-deny-target and by the one commented t0b-count-control (nft JSON, or text as a fallback)"""
    text = open(path).read()
    found = {}
    try:
        for item in json.loads(text).get("nftables", []):
            rule = item.get("rule")
            if not rule or "comment" not in rule:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    found[rule["comment"]] = int(expr["counter"]["packets"])
    except ValueError:
        for line in text.splitlines():
            match = re.search(r"counter packets (\d+) bytes \d+.*comment \"([^\"]+)\"", line)
            if match:
                found[match.group(2)] = int(match.group(1))
    if "t0b-deny-target" not in found or "t0b-count-control" not in found:
        sys.exit(2)
    print("deny=%d control=%d" % (found["t0b-deny-target"], found["t0b-count-control"]))
def levelpath(target_cg, control_cg, target_slice):
    t, c = target_cg.strip("/").split("/"), control_cg.strip("/").split("/")
    if target_slice not in t:
        sys.exit(3)
    level = t.index(target_slice) + 1
    if len(t) <= level or len(c) <= level or t[level - 1] == c[level - 1] or t[:level] == c[:level]:
        sys.exit(3)
    for part in t[:level] + c[:level]:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", part):
            sys.exit(3)
    print(level, "/".join(t[:level]), "/".join(c[:level]))
{"jget": jget, "counters": counters, "levelpath": levelpath}[sys.argv[1]](*sys.argv[2:])
PY
}
tool() { /usr/bin/python3 "$WORK/tools.py" "$@"; }

# ---- systemd units -----------------------------------------------------------------------------------------------------------------------------------
start_unit() {   # start_unit UNIT SLICE COMMAND...   (a transient service that JOINS the disposable namespace and lives in its own slice)
  local unit=$1 slice=$2; shift 2
  systemd-run --quiet --unit="$unit" --slice="$slice" --property=Type=exec --property=Restart=no --property=NoNewPrivileges=yes \
    --property=RuntimeMaxSec=160 --property="NetworkNamespacePath=/run/netns/$NS" "$@"
}
verify_unit() {  # verify_unit UNIT SLICE : exact identity; sets V_PID and V_CG
  local unit=$1 slice=$2 id active sl netpath main cg pcg nsid
  id=$(systemctl show -P Id "$unit"); active=$(systemctl show -P ActiveState "$unit"); sl=$(systemctl show -P Slice "$unit")
  netpath=$(systemctl show -P NetworkNamespacePath "$unit"); main=$(systemctl show -P MainPID "$unit"); cg=$(systemctl show -P ControlGroup "$unit")
  [[ "$id" == "$unit" && "$active" == active && "$sl" == "$slice" && "$netpath" == "/run/netns/$NS" ]] || return 1
  [[ "$main" =~ ^[0-9]+$ ]] || return 1
  (( 10#$main > 1 )) || return 1
  (( 10#$main != $$ )) || return 1
  [[ "$cg" == "/$slice/$unit" ]] || return 1
  pcg=$(proc_cgroup "$main") || return 1
  [[ "$pcg" == "$cg" ]] || return 1
  [[ "$(proc_comm "$main")" == python3 ]] || return 1
  nsid=$(proc_netns "$main") || return 1
  [[ "$nsid" == "$NS_ID" && "$nsid" != "$HOST_NS_ID" ]] || return 1
  V_PID=$main; V_CG=$cg
}
wait_unit() {    # wait_unit UNIT SLICE : active with a verifiable identity within ~6 s
  local i
  for i in $(seq 1 30); do verify_unit "$1" "$2" && return 0; sleep 0.2; done
  return 1
}

# ---- one connection attempt, made BY a service ------------------------------------------------------------------------------------------------------
attempt() {      # attempt NAME SEQ : ask the named agent to connect; waits up to 10 s; sets A_JSON
  local name=$1 seq=$2 res="$RPC/$1.res.$2.json" i
  printf '%s\n' "$seq" >"$RPC/$name.req.$seq.tmp" && mv "$RPC/$name.req.$seq.tmp" "$RPC/$name.req.$seq"
  for i in $(seq 1 100); do [[ -f "$res" ]] && break; sleep 0.1; done
  [[ -f "$res" ]] || return 1
  A_JSON=$res
}
agent_identity_ok() {   # the agent that made the attempt IS the unit's main process, in its cgroup and in the namespace
  local want_pid=$1 want_cg=$2
  [[ "$(tool jget "$A_JSON" pid)" == "$want_pid" && "$(tool jget "$A_JSON" cgroup)" == "$want_cg" && "$(tool jget "$A_JSON" netns)" == "$NS_ID" ]]
}
expect_connect() {   # expect_connect NAME SEQ PID CG LABEL
  local name=$1 seq=$2 pid=$3 cg=$4 label=$5
  attempt "$name" "$seq" || fail 41 "$label: no answer from the $name service"
  agent_identity_ok "$pid" "$cg" || fail 42 "$label: the attempt was not made by the verified $name service (pid/cgroup/namespace mismatch)"
  [[ "$(tool jget "$A_JSON" ok)" == true ]] || fail 43 "$label: $name did not connect (errname=$(tool jget "$A_JSON" errname))"
  [[ "$(tool jget "$A_JSON" local 0)" == 127.0.0.1 ]] || fail 44 "$label: unexpected local address"
  log "  $label: $name connected (agent pid $pid, local port $(tool jget "$A_JSON" local 1), ${A_JSON##*/})"
}
expect_refused() {   # expect_refused NAME SEQ PID CG LABEL
  local name=$1 seq=$2 pid=$3 cg=$4 label=$5
  attempt "$name" "$seq" || fail 41 "$label: no answer from the $name service"
  agent_identity_ok "$pid" "$cg" || fail 42 "$label: the attempt was not made by the verified $name service (pid/cgroup/namespace mismatch)"
  [[ "$(tool jget "$A_JSON" ok)" == false ]] || fail 45 "$label: $name connected although its cgroup should be rejected"
  [[ "$(tool jget "$A_JSON" errname)" == ECONNREFUSED ]] || fail 46 "$label: $name failed, but with $(tool jget "$A_JSON" errname) rather than the expected ECONNREFUSED from reject-with-tcp-reset"
  log "  $label: $name refused (ECONNREFUSED after $(tool jget "$A_JSON" elapsed_ms) ms)"
}
accepts() { if [[ -f "$WORK/listener.log" ]]; then wc -l <"$WORK/listener.log" | tr -d '[:space:]'; else printf 0; fi; }
read_counters() {   # sets DENY_PKTS and CTRL_PKTS from the rules INSIDE the namespace
  in_ns nft -j list chain inet "$TABLE" out >"$WORK/chain.json" 2>"$WORK/chain.err" || fail 47 "cannot read the rule counters back: $(head -c 200 "$WORK/chain.err")"
  local out; out=$(tool counters "$WORK/chain.json") || fail 47 "the counters of both rules were not found in the read-back"
  DENY_PKTS=${out#deny=}; DENY_PKTS=${DENY_PKTS%% *}; CTRL_PKTS=${out##*control=}
}

# ---- the probe ---------------------------------------------------------------------------------------------------------------------------------------
platform_checks() {
  local ident machine id version pid1 sd
  ident=$(platform_identity); read -r machine id version pid1 <<<"$ident"
  [[ "$machine" == aarch64 ]] || incomplete 30 "not an ARM64 runner ($machine)"
  [[ "$id" == ubuntu && "$version" == 24.04 ]] || incomplete 30 "not Ubuntu 24.04 ($id $version)"
  [[ "$pid1" == systemd ]] || incomplete 30 "systemd is not PID 1 ($pid1)"
  local tool_name
  for tool_name in systemd-run systemctl ip nft nsenter python3 timeout awk sed; do command -v "$tool_name" >/dev/null || incomplete 30 "missing command: $tool_name"; done
  sd=$(systemctl --version | head -n 1 | awk '{print $2}')
  [[ "$sd" =~ ^[0-9]+$ ]] && (( sd >= 242 )) || incomplete 30 "systemd $sd lacks NetworkNamespacePath"
  [[ "$(id -u)" == 0 ]] || incomplete 30 "must run as root (the workflow uses sudo)"
  log "platform: $machine $id $version, systemd $sd, kernel $(uname -r), $(nft --version | head -n 1), image ${ImageOS:-?}/${ImageVersion:-?}"
}

run_probe() {
  platform_checks
  WORK=$(mktemp -d "/run/t0b-${RUN_ID}.XXXXXX"); RPC="$WORK/rpc"; mkdir -p "$RPC"
  HOST_BEFORE=$(host_snapshot) || incomplete 30 "the host baseline could not be read completely; refusing to compare against partial data"
  printf '%s\n' "$HOST_BEFORE" >"$BASELINE_FILE.tmp" && mv -f "$BASELINE_FILE.tmp" "$BASELINE_FILE" && : >"$STARTED_FILE"      # kept outside the work directory so a failed or killed run can still be compared
  log "host baseline taken (ruleset, links, addresses, routes, namespaces): sha256 $(printf '%s' "$HOST_BEFORE" | sha256sum | cut -c1-16)"
  write_helpers

  # namespace: loopback only
  ip netns add "$NS" || incomplete 30 "could not create network namespace $NS"
  in_ns ip link set lo up || incomplete 30 "could not bring up lo in $NS"
  NS_ID=$(netns_file_id "$NS"); HOST_NS_ID=$(proc_netns 1)
  [[ -n "$NS_ID" && "$NS_ID" != "$HOST_NS_ID" ]] || incomplete 30 "the namespace is not distinct from the host namespace"
  log "namespace $NS ($NS_ID) created; host namespace $HOST_NS_ID is not used by any service below"

  # services: listener, target, control - each in its own slice, each joined to the namespace by systemd
  start_unit "$U_LISTEN" "$S_LISTEN" /usr/bin/python3 "$WORK/listener.py" "$PORT" "$WORK/listener.log" "$WORK/listener.ready" "$LIFETIME" \
    || incomplete 30 "systemd-run could not start the listener (NetworkNamespacePath unsupported here?)"
  wait_unit "$U_LISTEN" "$S_LISTEN" || fail 48 "listener service identity could not be verified"; PID_LISTEN=$V_PID; CG_LISTEN=$V_CG
  for _ in $(seq 1 50); do [[ -f "$WORK/listener.ready" ]] && break; sleep 0.1; done
  [[ -f "$WORK/listener.ready" ]] || fail 48 "the listener never bound 127.0.0.1:$PORT inside the namespace"
  start_unit "$U_TARGET" "$S_TARGET" /usr/bin/python3 "$WORK/agent.py" target "$RPC" "$PORT" "$LIFETIME" || incomplete 30 "could not start the target service"
  start_unit "$U_CONTROL" "$S_CONTROL" /usr/bin/python3 "$WORK/agent.py" control "$RPC" "$PORT" "$LIFETIME" || incomplete 30 "could not start the control service"
  wait_unit "$U_TARGET" "$S_TARGET" || fail 48 "target service identity could not be verified"; PID_TARGET=$V_PID; CG_TARGET=$V_CG
  wait_unit "$U_CONTROL" "$S_CONTROL" || fail 48 "control service identity could not be verified"; PID_CONTROL=$V_PID; CG_CONTROL=$V_CG
  for _ in $(seq 1 50); do [[ -f "$RPC/target.hello.json" && -f "$RPC/control.hello.json" ]] && break; sleep 0.1; done
  log "services: target $U_TARGET pid $PID_TARGET cgroup $CG_TARGET"
  log "          control $U_CONTROL pid $PID_CONTROL cgroup $CG_CONTROL"
  log "          listener $U_LISTEN pid $PID_LISTEN cgroup $CG_LISTEN"
  [[ "$CG_TARGET" != "$CG_CONTROL" && "$CG_TARGET" != "$CG_LISTEN" && "$CG_CONTROL" != "$CG_LISTEN" ]] || fail 48 "the three services do not have distinct cgroups"

  # the matcher is DERIVED from the observed cgroup paths, never assumed
  local derived; derived=$(tool levelpath "$CG_TARGET" "$CG_CONTROL" "$S_TARGET") || fail 49 "cannot derive a cgroup level that separates target from control ($CG_TARGET vs $CG_CONTROL)"
  read -r N_LEVEL MATCH_T MATCH_C <<<"$derived"
  [[ "$N_LEVEL" =~ ^[0-9]+$ && "$MATCH_T" =~ ^[A-Za-z0-9._/-]+$ && "$MATCH_C" =~ ^[A-Za-z0-9._/-]+$ && "$MATCH_T" != "$MATCH_C" ]] || fail 49 "derived matcher is not usable"
  log "matcher: socket cgroupv2 level $N_LEVEL \"$MATCH_T\" (target) differs from \"$MATCH_C\" (control) at that level"

  # before ANY firewall mutation: the entry point really lands in the disposable namespace, and nft can see the cgroup directories it has to match.  Read-only diagnostics.
  local nsnow fs_ns fs_host
  nsnow=$(ns_current_id) || incomplete 30 "cannot enter the namespace to check where firewall commands would land"
  [[ "$nsnow" == "$NS_ID" && "$nsnow" != "$HOST_NS_ID" ]] || incomplete 30 "the namespace entry point lands in $nsnow, not in $NS_ID; refusing to touch any firewall"
  fs_ns=$(cgroup_fstype_ns 2>&1) || fs_ns="unreadable"; fs_host=$(cgroup_fstype_host 2>&1) || fs_host="unreadable"
  log "diagnostic (read-only): /sys/fs/cgroup is $fs_ns in the namespace-entry context and $fs_host on the host"
  for _slice_path in "$MATCH_T" "$MATCH_C"; do
    cgroup_dir_visible_ns "$_slice_path" || incomplete 30 "/sys/fs/cgroup/$_slice_path is not visible to nft in the namespace context (fs type there: $fs_ns; on the host: $fs_host)"
  done
  log "diagnostic (read-only): both matcher cgroup directories are visible from the namespace-entry context"

  # PHASE 1 - baseline: both connect, no rule exists
  log "PHASE 1 - before any rule: both services connect"
  local base; base=$(accepts)
  expect_connect target 1 "$PID_TARGET" "$CG_TARGET" "phase 1"
  expect_connect control 1 "$PID_CONTROL" "$CG_CONTROL" "phase 1"
  [[ "$(accepts)" == $(( base + 2 )) ]] || fail 50 "phase 1: the listener did not log exactly two accepts"
  log "PASS: phase 1 (both services connected; listener accepted 2)"

  # PHASE 2 - one table, INSIDE the namespace only
  log "PHASE 2 - install the rule inside $NS only"
  local rules
  rules=$(cat <<NFT
table inet $TABLE {
  chain out {
    type filter hook output priority 0; policy accept;
    socket cgroupv2 level $N_LEVEL "$MATCH_T" tcp dport $PORT counter reject with tcp reset comment "t0b-deny-target"
    socket cgroupv2 level $N_LEVEL "$MATCH_C" tcp dport $PORT counter accept comment "t0b-count-control"
  }
}
NFT
)
  printf '%s\n' "$rules" | in_ns nft --check -f - >/dev/null 2>"$WORK/check.err" || incomplete 30 "nft rejected the cgroupv2 ruleset here: $(head -c 200 "$WORK/check.err")"
  printf '%s\n' "$rules" | in_ns nft -f - 2>"$WORK/load.err" || fail 51 "could not load the rule inside the namespace: $(head -c 200 "$WORK/load.err")"
  log "rule readback (inside $NS):"; in_ns nft list table inet "$TABLE" | sed 's/^/    /'
  read_counters; local deny0=$DENY_PKTS ctrl0=$CTRL_PKTS
  [[ "$deny0" == 0 && "$ctrl0" == 0 ]] || fail 51 "counters are not zero right after installation (deny=$deny0 control=$ctrl0)"
  log "PASS: phase 2 (rule installed and read back; counters deny=$deny0 control=$ctrl0)"

  # PHASE 3 - enforcement, with a negative control and counter attribution
  log "PHASE 3 - the rule blocks only the target"
  base=$(accepts)
  expect_connect control 2 "$PID_CONTROL" "$CG_CONTROL" "phase 3a"
  read_counters
  [[ "$DENY_PKTS" == "$deny0" ]] || fail 52 "phase 3a: the deny counter moved ($deny0 -> $DENY_PKTS) when only the control connected"
  (( CTRL_PKTS > ctrl0 )) || fail 52 "phase 3a: the control counter did not move although the control connected"
  local deny1=$DENY_PKTS ctrl1=$CTRL_PKTS
  expect_refused target 2 "$PID_TARGET" "$CG_TARGET" "phase 3b"
  expect_refused target 3 "$PID_TARGET" "$CG_TARGET" "phase 3b (second attempt)"
  read_counters
  (( DENY_PKTS >= deny1 + 2 )) || fail 53 "phase 3b: the deny counter did not rise for two refused attempts ($deny1 -> $DENY_PKTS)"
  [[ "$CTRL_PKTS" == "$ctrl1" ]] || fail 53 "phase 3b: the control counter moved ($ctrl1 -> $CTRL_PKTS) during target-only attempts"
  local deny2=$DENY_PKTS ctrl2=$CTRL_PKTS
  expect_connect control 3 "$PID_CONTROL" "$CG_CONTROL" "phase 3c (control after the target was blocked)"
  read_counters
  [[ "$DENY_PKTS" == "$deny2" ]] || fail 54 "phase 3c: the deny counter moved when only the control connected"
  (( CTRL_PKTS > ctrl2 )) || fail 54 "phase 3c: the control counter did not move"
  [[ "$(accepts)" == $(( base + 2 )) ]] || fail 54 "phase 3: the listener accepted a connection from the blocked target, or missed a control connection"
  log "counters: deny $deny0 -> $DENY_PKTS, control $ctrl0 -> $CTRL_PKTS; listener accepted only the 2 control connections"
  log "PASS: phase 3 (target refused with ECONNREFUSED, control unaffected, counters attribute each decision)"

  # identity must be unchanged: the same processes, not restarted ones
  local before_pid_t=$PID_TARGET before_pid_c=$PID_CONTROL
  verify_unit "$U_TARGET" "$S_TARGET" && [[ "$V_PID" == "$before_pid_t" ]] || fail 55 "target service identity changed or was lost during the test"
  verify_unit "$U_CONTROL" "$S_CONTROL" && [[ "$V_PID" == "$before_pid_c" ]] || fail 55 "control service identity changed or was lost during the test"

  # PHASE 4 - remove only this table; the target recovers
  log "PHASE 4 - remove the rule: the target recovers"
  in_ns nft delete table inet "$TABLE" || fail 56 "could not delete the table inside the namespace"
  if in_ns nft list table inet "$TABLE" >/dev/null 2>&1; then fail 56 "the table is still present after deletion"; fi
  base=$(accepts)
  expect_connect target 4 "$PID_TARGET" "$CG_TARGET" "phase 4"
  expect_connect control 4 "$PID_CONTROL" "$CG_CONTROL" "phase 4"
  [[ "$(accepts)" == $(( base + 2 )) ]] || fail 57 "phase 4: the listener did not log exactly two accepts"
  log "PASS: phase 4 (table removed; both services connect again)"

  # cleanup, then prove it
  cleanup
  verify_clean || fail 58 "residue after cleanup"
  compare_host_state || fail 59 "the host firewall/network state changed or could not be verified"
  log "PASS: cleanup complete (no units, slices, cgroups, namespace or work files left) and the host state is unchanged; the baseline is kept for the final standalone comparison"
  VERDICT=PASS
}

on_exit() {
  local rc=$?
  trap - EXIT
  cleanup || true
  if [[ "$HOST_COMPARED" != 1 ]]; then      # a failed, early-stopped or terminated run is compared against the baseline too
    if ! compare_host_state; then VERDICT=FAIL; rc=59; fi
  fi
  log "VERDICT: $VERDICT"
  exit "$rc"
}

main() {
  harden_env
  init_names
  if [[ "${1:-}" == cleanup-verify ]]; then   # the always-run workflow step: covers a probe that was killed, and gives an independent final comparison
    local residue=0 changed=0 unverified=0
    cleanup
    verify_clean || residue=1
    if [[ -f "$STARTED_FILE" && ! -f "$BASELINE_FILE" ]]; then
      log "HOST-STATE: a baseline was taken (marker present) but it is gone; the host state cannot be verified"; unverified=1
    else
      compare_host_state || changed=1
    fi
    rm -f -- "$BASELINE_FILE" "$BASELINE_FILE.tmp" "$STARTED_FILE"       # the one and only place the baseline is consumed
    if [[ "$residue" == 0 && "$changed" == 0 && "$unverified" == 0 ]]; then log "VERDICT: CLEAN"; return 0; fi
    if [[ "$residue" == 1 ]]; then log "VERDICT: RESIDUE"; elif [[ "$changed" == 1 ]]; then log "VERDICT: HOST_CHANGED"; else log "VERDICT: HOST_UNVERIFIED"; fi
    return 1
  fi
  trap on_exit EXIT
  trap 'log "FAIL: unexpected error at line $LINENO"; VERDICT=FAIL' ERR
  trap 'VERDICT=FAIL; exit 143' TERM INT
  run_probe
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
