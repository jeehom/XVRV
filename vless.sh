#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Xray VLESS + REALITY + Vision Manager (Debian/Ubuntu)
# - Install/Uninstall
# - Multi-user UUID management
# - Port change
# - IPv4-only outbound for specific domains (split routing)
# - Auto backup & rollback for config.json
#
# Install interactive flow (as requested):
#   1) Choose listen port (default random)
#   2) Input SNI (accept domain:port, auto-split). Default icloud.com:443
#   3) DEST default = SNI_domain:443, allow override
# ============================================================

XRAY_BIN="/usr/local/bin/xray"
XRAY_ETC_DIR="/etc/xray"
XRAY_CFG="${XRAY_ETC_DIR}/config.json"
XRAY_PUBKEY_FILE="${XRAY_ETC_DIR}/reality_public.key"
XRAY_SYSTEMD="/etc/systemd/system/xray.service"
XRAY_LOG_DIR="/var/log/xray"

# Defaults (can be overridden by env)
XRAY_PORT="${XRAY_PORT:-}"                 # empty => will choose random default during install prompt
XRAY_LISTEN="${XRAY_LISTEN:-0.0.0.0}"
XRAY_FINGERPRINT="${XRAY_FINGERPRINT:-chrome}"
XRAY_LOG_LEVEL="${XRAY_LOG_LEVEL:-warning}"
XRAY_TAG="${XRAY_TAG:-}"                   # empty => latest

# REALITY params (may be provided by env; otherwise prompted during install if TTY)
XRAY_REALITY_DEST="${XRAY_REALITY_DEST:-}"
XRAY_REALITY_SNI="${XRAY_REALITY_SNI:-}"

# Optional during install:
# - Single UUID: XRAY_UUID="..."
# - Multiple UUIDs: XRAY_UUIDS="uuid1,uuid2,uuid3"
XRAY_UUID="${XRAY_UUID:-}"
XRAY_UUIDS="${XRAY_UUIDS:-}"

# Optional split routing domains to force IPv4 outbound:
# comma-separated: "example.com,foo.bar"
XRAY_IPV4_DOMAINS="${XRAY_IPV4_DOMAINS:-}"

log()  { echo -e "[*] $*"; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run as root (sudo -i)."
}

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "64" ;;
    aarch64|arm64) echo "arm64-v8a" ;;
    armv7l|armv7) echo "arm32-v7a" ;;
    *) die "Unsupported arch: $m" ;;
  esac
}

apt_install_deps() {
  log "Installing dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends curl unzip jq openssl uuid-runtime ca-certificates
}

fetch_latest_tag() {
  curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r .tag_name
}

download_xray() {
  local tag="$1"
  local arch filename url tmpdir
  arch="$(detect_arch)"
  filename="Xray-linux-${arch}.zip"
  url="https://github.com/XTLS/Xray-core/releases/download/${tag}/${filename}"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  log "Downloading Xray ${tag} (${filename})..."
  curl -fL --retry 3 --retry-delay 1 -o "${tmpdir}/${filename}" "$url"

  log "Unzipping..."
  unzip -q "${tmpdir}/${filename}" -d "$tmpdir"

  install -m 0755 "${tmpdir}/xray" "${XRAY_BIN}"

  mkdir -p /usr/local/share/xray || true
  if [[ -f "${tmpdir}/geoip.dat" ]]; then
    install -m 0644 "${tmpdir}/geoip.dat" /usr/local/share/xray/geoip.dat
  fi
  if [[ -f "${tmpdir}/geosite.dat" ]]; then
    install -m 0644 "${tmpdir}/geosite.dat" /usr/local/share/xray/geosite.dat
  fi
}

ensure_user_and_dirs() {
  log "Creating xray user & directories..."
  if ! id -u xray >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin xray
  fi
  install -d -m 0755 "${XRAY_ETC_DIR}"
  install -d -m 0755 "${XRAY_LOG_DIR}"
  chown -R xray:xray "${XRAY_LOG_DIR}"
}

# ---------------- Backup & rollback ----------------
backup_config() {
  if [[ -f "${XRAY_CFG}" ]]; then
    local ts bak
    ts="$(date +"%Y%m%d-%H%M%S")"
    bak="${XRAY_CFG}.bak-${ts}"
    cp -a "${XRAY_CFG}" "${bak}"
    log "Backup created: ${bak}"
  fi
}

list_backups() {
  ls -1 "${XRAY_CFG}.bak-"* 2>/dev/null | sort || true
}

latest_backup() {
  list_backups | tail -n 1 || true
}

rollback_config() {
  need_root
  local target="${1:-}"

  if [[ -z "$target" ]]; then
    target="$(latest_backup)"
    [[ -n "$target" ]] || die "No backups found."
  else
    # allow passing only timestamp
    if [[ "$target" =~ ^[0-9]{8}-[0-9]{6}$ ]]; then
      target="${XRAY_CFG}.bak-${target}"
    fi
  fi

  [[ -f "$target" ]] || die "Backup not found: $target"

  # Backup current before rollback
  backup_config
  cp -a "$target" "${XRAY_CFG}"
  chown -R xray:xray "${XRAY_ETC_DIR}" || true

  if systemctl list-unit-files | grep -q '^xray\.service'; then
    if systemctl is-active --quiet xray; then
      systemctl restart xray
    else
      systemctl start xray || true
    fi
  fi

  log "Rolled back to: $target"
}

# ---------------- Utilities ----------------
random_port() {
  # choose a random high port (avoid 1-1023 and common ports)
  # range: 20000-59999
  shuf -i 20000-59999 -n 1
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 1
  return 0
}

# parse "domain:port" into "domain|port"
# - If no port, returns "domain|"
# - IPv6 in [] supported: "[::1]:443"
parse_host_port() {
  local s="$1"
  s="$(echo "$s" | tr -d ' ')"

  if [[ "$s" =~ ^\[.+\]:[0-9]+$ ]]; then
    local host port
    host="${s%%]:*}]"
    host="${host#[}"
    port="${s##*:}"
    echo "${host}|${port}"
    return
  fi

  # single colon => host:port
  if [[ "$s" == *:* ]] && [[ "$(echo "$s" | awk -F: '{print NF-1}')" -eq 1 ]]; then
    local host port
    host="${s%%:*}"
    port="${s##*:}"
    if validate_port "$port"; then
      echo "${host}|${port}"
      return
    fi
  fi

  echo "${s}|"
}

gen_uuid_list() {
  local list=""
  if [[ -n "${XRAY_UUIDS}" ]]; then
    list="${XRAY_UUIDS}"
  elif [[ -n "${XRAY_UUID}" ]]; then
    list="${XRAY_UUID}"
  else
    list="$(uuidgen)"
  fi
  list="$(echo "$list" | tr -d ' ')"
  echo "$list"
}

gen_short_id() {
  openssl rand -hex 8
}

gen_reality_keypair() {
  # Newer xray prints:
  #   PrivateKey: ...
  #   Password:  ...   (this is used as REALITY "public key"/pbk)
  #   Hash32:    ...   (not used by REALITY)
  # Older xray prints:
  #   Private key: ...
  #   Public key: ...
  local out priv pub
  out="$("${XRAY_BIN}" x25519 2>&1 || true)"

  priv="$(echo "$out" | awk -F': *' '/^(Private key|PrivateKey):/ {print $2; exit}')"
  pub="$(echo "$out" | awk -F': *' '/^(Public key|Password):/ {print $2; exit}')"

  if [[ -z "$priv" || -z "$pub" ]]; then
    echo "$out" >&2
    die "Failed to generate x25519 keypair (output format may have changed)."
  fi

  echo "$priv|$pub"
}


# ======= NEW: Install interactive flow (per your requirements) =======
prompt_install_params() {
  # If NOT TTY and vars missing -> must be provided by env
  if [[ ! -t 0 ]]; then
    [[ -n "${XRAY_PORT}" ]] || XRAY_PORT="$(random_port)"
    [[ -n "${XRAY_REALITY_SNI}" ]]  || die "Missing XRAY_REALITY_SNI (non-interactive)."
    [[ -n "${XRAY_REALITY_DEST}" ]] || die "Missing XRAY_REALITY_DEST (non-interactive)."
    return
  fi

  # 1) Port: default random (if XRAY_PORT empty, generate; if set by env, keep it as default)
  local default_port
  if [[ -n "${XRAY_PORT}" ]] && validate_port "${XRAY_PORT}"; then
    default_port="${XRAY_PORT}"
  else
    default_port="$(random_port)"
    XRAY_PORT=""
  fi

  local in_port
  read -r -p "Listen port (default ${default_port}): " in_port
  if [[ -z "$in_port" ]]; then
    XRAY_PORT="${default_port}"
  else
    validate_port "$in_port" || die "Invalid port: $in_port"
    XRAY_PORT="$in_port"
  fi

  # 2) SNI: accept domain:port; default icloud.com  (<<< 改这里：默认不带端口)
  local default_sni_raw="icloud.com"
  local in_sni_raw
  read -r -p "SNI (domain[:port]) (default ${default_sni_raw}): " in_sni_raw
  if [[ -z "$in_sni_raw" ]]; then
    in_sni_raw="${default_sni_raw}"
  fi

  local parsed host port
  parsed="$(parse_host_port "$in_sni_raw")"
  host="${parsed%%|*}"
  port="${parsed##*|}"  # may be empty

  [[ -n "$host" ]] || die "SNI cannot be empty."

  # REALITY serverNames wants only domain (no port)
  XRAY_REALITY_SNI="$host"

  # 3) DEST: default = SNI_domain:443 (<<< 这里本来就是你要的)
  local default_dest="${XRAY_REALITY_SNI}:443"
  local in_dest
  read -r -p "DEST (host:port) (default ${default_dest}): " in_dest
  if [[ -z "$in_dest" ]]; then
    XRAY_REALITY_DEST="${default_dest}"
  else
    # basic validation: must contain ":" and have a port
    local p2 h2
    parsed="$(parse_host_port "$in_dest")"
    h2="${parsed%%|*}"
    p2="${parsed##*|}"
    [[ -n "$h2" && -n "$p2" ]] || die "DEST must be in host:port format."
    validate_port "$p2" || die "Invalid DEST port: $p2"
    XRAY_REALITY_DEST="${h2}:${p2}"
  fi

  echo
  log "Install parameters:"
  echo "  Listen port: ${XRAY_PORT}"
  echo "  SNI:         ${XRAY_REALITY_SNI}"
  echo "  DEST:        ${XRAY_REALITY_DEST}"
  echo
}


write_systemd() {
  log "Writing systemd unit..."
  cat >"${XRAY_SYSTEMD}" <<'EOF'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=xray
Group=xray
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable xray
}

build_clients_json() {
  local uuids_csv="$1"
  local IFS=',' u
  local arr="[]"
  for u in $uuids_csv; do
    [[ -n "$u" ]] || continue
    arr="$(echo "$arr" | jq --arg id "$u" '. + [{"id":$id,"flow":"xtls-rprx-vision"}]')"
  done
  echo "$arr"
}

normalize_domains_to_json_array() {
  local csv="$1"
  csv="$(echo "$csv" | tr -d ' ' | sed 's/,,*/,/g' | sed 's/^,//; s/,$//')"
  if [[ -z "$csv" ]]; then
    echo "[]"
    return
  fi
  printf "%s\n" "$csv" | tr ',' '\n' | awk 'NF' | jq -R . | jq -s .
}

write_config_fresh() {
  local uuid_csv="$1"
  local privkey="$2"
  local shortid="$3"

  local clients_json domains_json
  clients_json="$(build_clients_json "$uuid_csv")"
  domains_json="$(normalize_domains_to_json_array "${XRAY_IPV4_DOMAINS}")"

  log "Writing ${XRAY_CFG} ..."

  jq -n \
    --arg listen "${XRAY_LISTEN}" \
    --argjson port "${XRAY_PORT}" \
    --arg loglevel "${XRAY_LOG_LEVEL}" \
    --arg access "${XRAY_LOG_DIR}/access.log" \
    --arg error "${XRAY_LOG_DIR}/error.log" \
    --arg dest "${XRAY_REALITY_DEST}" \
    --arg sni "${XRAY_REALITY_SNI}" \
    --arg priv "${privkey}" \
    --arg sid "${shortid}" \
    --argjson clients "${clients_json}" \
    --argjson ipv4domains "${domains_json}" \
    'def ipv4_rule:
       if ($ipv4domains|length) > 0
       then [{"type":"field","domain":$ipv4domains,"outboundTag":"direct_ipv4"}]
       else []
       end;
     {
      "log": {"loglevel": $loglevel, "access": $access, "error": $error},
      "inbounds": [
        {
          "listen": $listen,
          "port": $port,
          "protocol": "vless",
          "tag": "in-vless-reality",
          "settings": {"clients": $clients, "decryption": "none"},
          "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
              "show": false,
              "dest": $dest,
              "xver": 0,
              "serverNames": [$sni],
              "privateKey": $priv,
              "shortIds": [$sid]
            }
          },
          "sniffing": {"enabled": true, "destOverride": ["http","tls"], "routeOnly": true}
        }
      ],
      "outbounds": [
        { "protocol": "freedom", "tag": "direct" },
        { "protocol": "freedom", "tag": "direct_ipv4", "settings": { "domainStrategy": "UseIPv4" } },
        { "protocol": "blackhole", "tag": "block" }
      ],
      "routing": {
        "domainStrategy": "AsIs",
        "rules": (ipv4_rule + [
          {"type":"field","ip":["geoip:private"],"outboundTag":"block"}
        ])
      }
     }' >"${XRAY_CFG}"

  chmod 0644 "${XRAY_CFG}"
  chown -R xray:xray "${XRAY_ETC_DIR}"
}

restart_if_running() {
  if systemctl is-active --quiet xray; then
    systemctl restart xray
  else
    warn "xray service is not active; starting..."
    systemctl start xray
  fi
}

open_firewall_and_hints() {
  local port="$1"

  if command -v ufw >/dev/null 2>&1; then
    log "UFW detected, allowing TCP ${port} ..."
    ufw allow "${port}/tcp" >/dev/null || true
  else
    warn "UFW not found. If you use a firewall, open TCP ${port} manually."
  fi

  if [[ "${port}" != "443" ]]; then
    echo
    warn "Port is ${port} (not 443). Remember to open it in:"
    echo "  - Cloud security group / firewall (if any)"
    echo "  - Local firewall (ufw/iptables/nftables)"
    echo
    echo "iptables hint (if you use iptables):"
    echo "  iptables -I INPUT -p tcp --dport ${port} -j ACCEPT"
    echo
    echo "Optional setcap hint (NOT required with this systemd unit):"
    echo "  setcap 'cap_net_bind_service=+ep' ${XRAY_BIN}"
    echo
  fi
}

get_server_ip() {
  curl -fsSL --max-time 2 https://api.ipify.org 2>/dev/null || true
}

require_config() {
  [[ -f "${XRAY_CFG}" ]] || die "Config not found: ${XRAY_CFG}. Install first."
}

show_links() {
  require_config
  [[ -f "${XRAY_PUBKEY_FILE}" ]] || die "Public key not found: ${XRAY_PUBKEY_FILE}"

  local pubkey shortid sni port fp ip uuids i uuid link name
  pubkey="$(cat "${XRAY_PUBKEY_FILE}")"
  shortid="$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "${XRAY_CFG}")"
  sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "${XRAY_CFG}")"
  port="$(jq -r '.inbounds[0].port' "${XRAY_CFG}")"
  fp="${XRAY_FINGERPRINT}"
  ip="$(get_server_ip)"
  [[ -n "$ip" ]] || ip="<YOUR_SERVER_IP>"

  uuids="$(jq -r '.inbounds[0].settings.clients[].id' "${XRAY_CFG}")"

  echo
  echo "=== Client links (VLESS + REALITY + Vision) ==="
  i=0
  while IFS= read -r uuid; do
    [[ -n "$uuid" ]] || continue
    i=$((i+1))
    name="xray-reality-${i}"
    link="vless://${uuid}@${ip}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pubkey}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#${name}"
    echo
    echo "User #${i}: ${uuid}"
    echo "${link}"
  done <<<"$uuids"
  echo
}

# ---------------- Core actions ----------------
install_xray() {
  need_root
  prompt_install_params
  apt_install_deps

  local tag
  if [[ -n "${XRAY_TAG}" ]]; then
    tag="${XRAY_TAG}"
  else
    tag="$(fetch_latest_tag)"
  fi
  [[ "$tag" == v* ]] || die "Failed to get Xray release tag."

  download_xray "$tag"
  ensure_user_and_dirs

  local uuid_csv shortid keypair priv pub
  uuid_csv="$(gen_uuid_list)"
  shortid="$(gen_short_id)"
  keypair="$(gen_reality_keypair)"
  priv="${keypair%%|*}"
  pub="${keypair##*|}"

  echo -n "${pub}" > "${XRAY_PUBKEY_FILE}"
  chmod 0644 "${XRAY_PUBKEY_FILE}"
  chown xray:xray "${XRAY_PUBKEY_FILE}"

  backup_config
  write_config_fresh "$uuid_csv" "$priv" "$shortid"

  write_systemd
  systemctl restart xray

  open_firewall_and_hints "$(jq -r '.inbounds[0].port' "${XRAY_CFG}")"

  echo
  log "Installed successfully."
  echo "  Config: ${XRAY_CFG}"
  echo "  PublicKey saved: ${XRAY_PUBKEY_FILE}"
  echo
  show_links
}

uninstall_xray() {
  need_root
  log "Stopping service..."
  systemctl stop xray >/dev/null 2>&1 || true
  systemctl disable xray >/dev/null 2>&1 || true

  log "Removing systemd unit..."
  rm -f "${XRAY_SYSTEMD}"
  systemctl daemon-reload || true

  log "Removing files..."
  rm -rf "${XRAY_ETC_DIR}"
  rm -rf "${XRAY_LOG_DIR}"
  rm -f "${XRAY_BIN}"

  log "Removing user..."
  if id -u xray >/dev/null 2>&1; then
    userdel xray >/dev/null 2>&1 || true
  fi

  log "Uninstall done."
}

status_xray() { systemctl --no-pager --full status xray || true; }
logs_xray()   { journalctl -u xray -e --no-pager || true; }

# ---------------- Config mutation helpers (always backup) ----------------
apply_jq_inplace_with_backup() {
  local filter="$1"; shift
  require_config
  backup_config
  jq "$@" "$filter" "${XRAY_CFG}" > "${XRAY_CFG}.tmp"
  mv "${XRAY_CFG}.tmp" "${XRAY_CFG}"
  chown -R xray:xray "${XRAY_ETC_DIR}" || true
}

set_port() {
  need_root
  require_config
  local newport="${1:-}"
  if [[ -z "$newport" ]]; then
    read -r -p "New port: " newport
  fi
  validate_port "$newport" || die "Invalid port: $newport"

  apply_jq_inplace_with_backup '.inbounds[0].port = $p' --argjson p "$newport"
  restart_if_running
  open_firewall_and_hints "$newport"
  log "Port updated to $newport."
}

list_users() {
  require_config
  echo
  echo "=== Users ==="
  jq -r '.inbounds[0].settings.clients | to_entries[] | "\(.key+1)) \(.value.id)"' "${XRAY_CFG}" || true
  echo
}

add_user() {
  need_root
  require_config
  local uuid="${1:-}"
  if [[ -z "$uuid" ]]; then
    uuid="$(uuidgen)"
  fi

  apply_jq_inplace_with_backup '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision"}]' --arg id "$uuid"
  restart_if_running
  log "Added user: $uuid"
  show_links
}

remove_user() {
  need_root
  require_config
  list_users
  local idx="${1:-}"
  if [[ -z "$idx" ]]; then
    read -r -p "Remove which user number? " idx
  fi
  [[ "$idx" =~ ^[0-9]+$ ]] || die "Invalid number."
  local zero=$((idx-1))
  local count
  count="$(jq '.inbounds[0].settings.clients | length' "${XRAY_CFG}")"
  [[ "$zero" -ge 0 && "$zero" -lt "$count" ]] || die "Out of range."

  apply_jq_inplace_with_backup \
    '.inbounds[0].settings.clients |= (to_entries | map(select(.key != $i)) | map(.value))' \
    --argjson i "$zero"

  restart_if_running
  log "Removed user #$idx"
  show_links
}

replace_user_uuid() {
  need_root
  require_config
  list_users
  local idx="${1:-}"
  local newuuid="${2:-}"
  if [[ -z "$idx" ]]; then
    read -r -p "Modify which user number? " idx
  fi
  [[ "$idx" =~ ^[0-9]+$ ]] || die "Invalid number."
  if [[ -z "$newuuid" ]]; then
    read -r -p "New UUID: " newuuid
  fi
  [[ -n "$newuuid" ]] || die "UUID cannot be empty."

  local zero=$((idx-1))
  local count
  count="$(jq '.inbounds[0].settings.clients | length' "${XRAY_CFG}")"
  [[ "$zero" -ge 0 && "$zero" -lt "$count" ]] || die "Out of range."

  apply_jq_inplace_with_backup \
    '.inbounds[0].settings.clients |= (to_entries | map(if .key == $i then (.value.id=$id) else .value end))' \
    --argjson i "$zero" --arg id "$newuuid"

  restart_if_running
  log "Updated user #$idx UUID."
  show_links
}

set_ipv4_domains() {
  need_root
  require_config
  local csv="${1:-}"
  if [[ -z "$csv" ]]; then
    echo "Enter domains (comma-separated). Empty to clear."
    read -r -p "Domains: " csv
  fi
  XRAY_IPV4_DOMAINS="$csv"

  local domains_json
  domains_json="$(normalize_domains_to_json_array "${XRAY_IPV4_DOMAINS}")"

  apply_jq_inplace_with_backup '
    .routing.rules =
      ( (if ($ipv4domains|length) > 0
          then [{"type":"field","domain":$ipv4domains,"outboundTag":"direct_ipv4"}]
          else []
        end)
        + [{"type":"field","ip":["geoip:private"],"outboundTag":"block"}]
      )' --argjson ipv4domains "${domains_json}"

  restart_if_running
  log "IPv4-only domains updated."
  echo "Current routing.rules[0] (if set):"
  jq -r '.routing.rules[0] // empty' "${XRAY_CFG}" || true
}

menu_list_backups() {
  echo
  echo "=== Backups ==="
  local b
  b="$(list_backups)"
  if [[ -z "$b" ]]; then
    echo "(none)"
  else
    echo "$b"
  fi
  echo
}

menu_rollback() {
  need_root
  menu_list_backups
  local ts
  read -r -p "Rollback to which timestamp (YYYYmmdd-HHMMSS), empty=latest: " ts
  if [[ -z "$ts" ]]; then
    rollback_config
  else
    rollback_config "$ts"
  fi
}

menu() {
  while true; do
    echo
    echo "================ Xray REALITY Manager ================"
    echo "1) Install (VLESS+REALITY+Vision)"
    echo "2) Uninstall (stop + remove files/user)"
    echo "3) Status"
    echo "4) Show links"
    echo "5) Change port"
    echo "6) List users (UUIDs)"
    echo "7) Add user (UUID)"
    echo "8) Remove user (by number)"
    echo "9) Modify user UUID (by number)"
    echo "10) Set IPv4-only domains (split routing)"
    echo "11) View logs (journalctl)"
    echo "12) List config backups"
    echo "13) Rollback config"
    echo "0) Exit"
    echo "======================================================"
    read -r -p "Select: " choice

    case "$choice" in
      1) install_xray ;;
      2) uninstall_xray ;;
      3) status_xray ;;
      4) show_links ;;
      5) set_port ;;
      6) list_users ;;
      7) add_user ;;
      8) remove_user ;;
      9) replace_user_uuid ;;
      10) set_ipv4_domains ;;
      11) logs_xray ;;
      12) menu_list_backups ;;
      13) menu_rollback ;;
      0) exit 0 ;;
      *) warn "Unknown selection." ;;
    esac
  done
}

usage() {
  cat <<EOF
Usage:
  $0                         # interactive menu
  $0 install                 # install (will prompt port/SNI/DEST if TTY)
  $0 uninstall               # uninstall
  $0 status                  # status
  $0 links                   # show client links
  $0 set-port <port>         # change port (auto backup)
  $0 users                   # list users
  $0 add-user [uuid]         # add user (auto backup)
  $0 rm-user <number>        # remove user by number (auto backup)
  $0 set-user <number> <uuid># replace UUID by number (auto backup)
  $0 set-ipv4-domains "a.com,b.com"  # (auto backup)
  $0 backups                 # list backups
  $0 rollback [timestamp]    # rollback (timestamp: YYYYmmdd-HHMMSS)

Non-interactive install requires env:
  XRAY_REALITY_SNI="example.com"
  XRAY_REALITY_DEST="example.com:443"
Optional:
  XRAY_PORT=12345
  XRAY_UUIDS="uuid1,uuid2"
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    "" ) menu ;;
    help|-h|--help) usage ;;
    install) install_xray ;;
    uninstall) uninstall_xray ;;
    status) status_xray ;;
    links) show_links ;;
    set-port) shift; set_port "${1:-}" ;;
    users) list_users ;;
    add-user) shift; add_user "${1:-}" ;;
    rm-user) shift; remove_user "${1:-}" ;;
    set-user) shift; replace_user_uuid "${1:-}" "${2:-}" ;;
    set-ipv4-domains) shift; set_ipv4_domains "${1:-}" ;;
    backups) menu_list_backups ;;
    rollback) shift; rollback_config "${1:-}" ;;
    *) warn "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
