#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/Bin"
GROUP_NAME="${1:-}"

TOOLS=(
  arp_scan
  arp_spoofing
  dhcp
  dhcp_server
  dhcpv6
  dns_rr
  dns_scan
  icmp6_scan
  ndp_spoofing
  netlink
  release_aclients
  release_fclients
)

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0 [admin-group]" >&2
  exit 1
fi

if [[ -z "${GROUP_NAME}" ]]; then
  if getent group admin >/dev/null; then
    GROUP_NAME="admin"
  elif getent group sudo >/dev/null; then
    GROUP_NAME="sudo"
  elif getent group wheel >/dev/null; then
    GROUP_NAME="wheel"
  else
    echo "No admin group found. Pass one explicitly, for example: sudo $0 admin" >&2
    exit 1
  fi
fi

if ! getent group "${GROUP_NAME}" >/dev/null; then
  echo "Group not found: ${GROUP_NAME}" >&2
  exit 1
fi

if ! command -v setcap >/dev/null; then
  echo "setcap not found. Install libcap tools first." >&2
  echo "Debian/Ubuntu: sudo apt install libcap2-bin" >&2
  exit 1
fi

mkdir -p "${BIN_DIR}/Clients"
chgrp "${GROUP_NAME}" "${BIN_DIR}" "${BIN_DIR}/Clients"
chmod 750 "${BIN_DIR}"
chmod 770 "${BIN_DIR}/Clients"

for tool in "${TOOLS[@]}"; do
  path="${BIN_DIR}/${tool}"

  if [[ ! -f "${path}" ]]; then
    echo "Skipping missing binary: ${path}"
    continue
  fi

  chown root:"${GROUP_NAME}" "${path}"
  chmod 750 "${path}"
  setcap cap_net_raw,cap_net_admin,cap_net_bind_service+ep "${path}"
  echo "Configured ${path}"
done

echo
echo "Done. Users in group '${GROUP_NAME}' can execute the configured binaries."
echo "If a user was just added to the group, they must log out and log in again."
echo "Check capabilities with: getcap ${BIN_DIR}/*"
