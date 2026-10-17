#!/usr/bin/env bash
# Synthetic GitHub-hosted ARM64 Tier-0 platform probe. NO PRIVATE CODE.
# Installs no packages, invokes no external services, never modifies firewall rules.
set -Eeuo pipefail
umask 077

unit=""
cleanup() {
  if [[ -n "$unit" ]]; then
    sudo systemctl stop "$unit" >/dev/null 2>&1 || :
    sudo systemctl reset-failed "$unit" >/dev/null 2>&1 || :
  fi
}
trap cleanup EXIT
trap 'printf "FAIL: platform probe exited at line %s\n" "$LINENO" >&2' ERR

[[ "$(uname -m)" == aarch64 ]] || { echo 'FAIL: not an ARM64 runner'; exit 10; }
[[ -r /etc/os-release ]] || { echo 'FAIL: no OS identity'; exit 11; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == '24.04' ]] || { echo 'FAIL: not Ubuntu 24.04'; exit 12; }
[[ "$(ps -p 1 -o comm= | tr -d '[:space:]')" == systemd ]] || { echo 'FAIL: systemd is not PID1'; exit 13; }
command -v systemd-run >/dev/null || { echo 'FAIL: no systemd-run'; exit 14; }
command -v systemctl >/dev/null || { echo 'FAIL: no systemctl'; exit 15; }
# Check the parser without installing packages or touching firewall state.
# Continue to collect systemd evidence even when nft is missing or incompatible.
nft_result=0
if ! command -v nft >/dev/null; then
  nft_result=16
  echo 'INCOMPLETE: nft not installed; syntax support remains unknown'
elif sudo nft --check -f - <<'NFT'
table inet arm_probe {
  chain output_probe {
    type filter hook output priority 0; policy accept;
    socket cgroupv2 level 1 "system.slice" counter
  }
}
NFT
then
  echo 'PASS: nft cgroupv2 rule validation (syntax only, no rule installed)'
else
  nft_result=21
  echo 'INCOMPLETE: nft cgroupv2 check failed; no firewall rule installed'
fi

# Unit name contains only trusted numeric run id (or fixed fallback) and bash PID.
run_id="${GITHUB_RUN_ID:-0}"
[[ "$run_id" =~ ^[0-9]+$ ]] || { echo 'FAIL: invalid run id'; exit 17; }
unit="arm-smoke-${run_id}-$$.service"
sudo systemd-run --unit="$unit" --property=Type=exec --property=Restart=no /usr/bin/sleep 120 >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do
  active=$(sudo systemctl show -P ActiveState "$unit")
  [[ "$active" == active ]] && break
  sleep 0.2
done

verify_target() {
  local id active main cg proc_cg
  id=$(sudo systemctl show -P Id "$unit")
  active=$(sudo systemctl show -P ActiveState "$unit")
  main=$(sudo systemctl show -P MainPID "$unit")
  cg=$(sudo systemctl show -P ControlGroup "$unit")
  [[ "$id" == "$unit" && "$active" == active ]] || return 1
  [[ "$main" =~ ^[0-9]+$ ]] || return 1
  (( 10#$main > 1 )) || return 1
  (( 10#$main != $$ )) || return 1
  [[ -n "$cg" && "$cg" == /* ]] || return 1
  sudo kill -0 "$main" 2>/dev/null || return 1
  [[ "$(cat "/proc/$main/comm" 2>/dev/null)" == sleep ]] || return 1
  [[ -r "/proc/$main/cgroup" ]] || return 1
  proc_cg=$(awk -F: '$1==0 && $2=="" {print $3; found=1; exit} END {if (!found) exit 1}' "/proc/$main/cgroup") || return 1
  [[ "$proc_cg" == "$cg" ]] || return 1
  TARGET_PID="$main"
}

TARGET_PID=""
verify_target || { echo 'FAIL: systemd MainPID/cgroup validation'; exit 18; }
verify_target || { echo 'FAIL: PID could not be reverified; no signal sent'; exit 19; }
sudo /bin/kill -s KILL -- "$TARGET_PID"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sudo kill -0 "$TARGET_PID" 2>/dev/null || break
  sleep 0.2
done
# The PID may linger as a zombie briefly; systemd should report the unit no longer active.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ "$(sudo systemctl show -P ActiveState "$unit")" != active ]] && break
  sleep 0.2
done
[[ "$(sudo systemctl show -P ActiveState "$unit")" != active ]] || { echo 'FAIL: disposable service stayed active'; exit 20; }
echo 'PASS: systemd synthetic service PID/cgroup identity and guarded single-process SIGKILL'
if [[ $nft_result -ne 0 ]]; then
  echo 'INCOMPLETE: service probe passed, but nft syntax could not be verified'
  exit "$nft_result"
fi
echo 'PASS: probe complete (NOT a durability, egress-enforcement, power-cut or production rehearsal)'
