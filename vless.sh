#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Xray VLESS + REALITY + Vision 管理脚本（Debian/Ubuntu）
# - 安装/卸载
# - 多用户 UUID 管理
# - 修改端口
# - 分流：指定域名走 IPv4 出口
# - 配置自动备份/回滚（每次修改前备份 config.json.bak-时间戳）
#
# 安装交互流程（按你的要求）：
#   1) 选择监听端口（默认：随机端口，回车使用默认）
#   2) 输入 SNI（支持 域名:端口，会自动拆分）。默认 icloud.com（回车使用默认）
#   3) DEST 默认自动用 SNI域名:443，可覆盖（回车使用默认）
# ============================================================

XRAY_BIN="/usr/local/bin/xray"
XRAY_ETC_DIR="/etc/xray"
XRAY_CFG="${XRAY_ETC_DIR}/config.json"
XRAY_PUBKEY_FILE="${XRAY_ETC_DIR}/reality_public.key"
XRAY_SYSTEMD="/etc/systemd/system/xray.service"
XRAY_LOG_DIR="/var/log/xray"

# 默认值（可用环境变量覆盖）
XRAY_PORT="${XRAY_PORT:-}"                 # 空 => 安装交互时默认随机端口
XRAY_LISTEN="${XRAY_LISTEN:-0.0.0.0}"
XRAY_FINGERPRINT="${XRAY_FINGERPRINT:-chrome}"
XRAY_LOG_LEVEL="${XRAY_LOG_LEVEL:-warning}"
XRAY_TAG="${XRAY_TAG:-}"                   # 空 => latest

# REALITY 参数（可由 env 提供；否则安装时 TTY 交互输入）
XRAY_REALITY_DEST="${XRAY_REALITY_DEST:-}"
XRAY_REALITY_SNI="${XRAY_REALITY_SNI:-}"

# 可选：安装时指定 UUID
XRAY_UUID="${XRAY_UUID:-}"
XRAY_UUIDS="${XRAY_UUIDS:-}"

# 可选：分流域名（这些域名强制走 IPv4 出口）
XRAY_IPV4_DOMAINS="${XRAY_IPV4_DOMAINS:-}"

log()  { echo -e "[*] $*"; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 运行（例如：sudo -i）。"
}

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "64" ;;
    aarch64|arm64) echo "arm64-v8a" ;;
    armv7l|armv7) echo "arm32-v7a" ;;
    *) die "不支持的架构：$m" ;;
  esac
}

apt_install_deps() {
  log "正在安装依赖..."
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

  log "正在下载 Xray ${tag}（${filename}）..."
  curl -fL --retry 3 --retry-delay 1 -o "${tmpdir}/${filename}" "$url"

  log "正在解压..."
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
  log "创建 xray 用户与目录..."
  if ! id -u xray >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin xray
  fi
  install -d -m 0755 "${XRAY_ETC_DIR}"
  install -d -m 0755 "${XRAY_LOG_DIR}"
  chown -R xray:xray "${XRAY_LOG_DIR}"
}

# ---------------- 备份 & 回滚 ----------------
backup_config() {
  if [[ -f "${XRAY_CFG}" ]]; then
    local ts bak
    ts="$(date +"%Y%m%d-%H%M%S")"
    bak="${XRAY_CFG}.bak-${ts}"
    cp -a "${XRAY_CFG}" "${bak}"
    log "已创建配置备份：${bak}"
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
    [[ -n "$target" ]] || die "未找到任何备份文件。"
  else
    # 允许只传时间戳
    if [[ "$target" =~ ^[0-9]{8}-[0-9]{6}$ ]]; then
      target="${XRAY_CFG}.bak-${target}"
    fi
  fi

  [[ -f "$target" ]] || die "备份文件不存在：$target"

  # 回滚前先备份当前配置
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

  log "已回滚到备份：$target"
}

# ---------------- 工具函数 ----------------
random_port() {
  # 随机高端口：20000-59999
  shuf -i 20000-59999 -n 1
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 1
  return 0
}

# 解析 "domain:port" => "domain|port"
# - 没端口则返回 "domain|"
# - 支持 IPv6: "[::1]:443"
parse_host_port() {
  local s="$1"
  s="$(echo "$s" | tr -d ' ')"

  # IPv6 in []
  if [[ "$s" =~ ^\[.+\]:[0-9]+$ ]]; then
    local host port
    host="${s#\[}"
    host="${host%%\]:*}"
    port="${s##*:}"
    echo "${host}|${port}"
    return
  fi

  # 仅一个冒号：host:port
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
  # 16 hex chars
  openssl rand -hex 8
}

gen_reality_keypair() {
  # 兼容新旧 xray x25519 输出：
  # 新版：
  #   PrivateKey: ...
  #   Password:  ...   (客户端 pbk 用这个)
  #   Hash32:    ...   (REALITY 不用)
  # 旧版：
  #   Private key: ...
  #   Public key:  ...
  local out priv pub
  out="$("${XRAY_BIN}" x25519 2>&1 || true)"

  priv="$(echo "$out" | awk -F': *' '/^(Private key|PrivateKey):/ {print $2; exit}')"
  pub="$(echo "$out" | awk -F': *' '/^(Public key|Password):/ {print $2; exit}')"

  if [[ -z "$priv" || -z "$pub" ]]; then
    echo "$out" >&2
    die "生成 x25519 密钥对失败（可能是 xray 输出格式变更导致）。"
  fi

  echo "$priv|$pub"
}

# ---------------- 安装交互参数（中文） ----------------
prompt_install_params() {
  # 非交互：必须通过 env 提供关键参数
  if [[ ! -t 0 ]]; then
    [[ -n "${XRAY_PORT}" ]] || XRAY_PORT="$(random_port)"
    [[ -n "${XRAY_REALITY_SNI}" ]]  || die "非交互模式下缺少 XRAY_REALITY_SNI。"
    [[ -n "${XRAY_REALITY_DEST}" ]] || die "非交互模式下缺少 XRAY_REALITY_DEST。"
    return
  fi

  # 1) 端口：默认随机
  local default_port
  if [[ -n "${XRAY_PORT}" ]] && validate_port "${XRAY_PORT}"; then
    default_port="${XRAY_PORT}"
  else
    default_port="$(random_port)"
    XRAY_PORT=""
  fi

  local in_port
  read -r -p "监听端口（默认随机 ${default_port}，回车使用默认）： " in_port
  if [[ -z "$in_port" ]]; then
    XRAY_PORT="${default_port}"
  else
    validate_port "$in_port" || die "端口不合法：$in_port"
    XRAY_PORT="$in_port"
  fi

  # 2) SNI：默认 icloud.com（可输入 域名:端口，会自动拆分）
  local default_sni_raw="icloud.com"
  local in_sni_raw
  read -r -p "SNI（域名[可带:端口]，默认 ${default_sni_raw}，回车使用默认）： " in_sni_raw
  if [[ -z "$in_sni_raw" ]]; then
    in_sni_raw="${default_sni_raw}"
  fi

  local parsed host port
  parsed="$(parse_host_port "$in_sni_raw")"
  host="${parsed%%|*}"
  port="${parsed##*|}"  # 可能为空

  [[ -n "$host" ]] || die "SNI 不能为空。"

  # REALITY 的 serverNames 只要域名，不要端口
  XRAY_REALITY_SNI="$host"

  # 3) DEST：默认 SNI:443，可覆盖
  local default_dest="${XRAY_REALITY_SNI}:443"
  local in_dest
  read -r -p "DEST（host:port，默认 ${default_dest}，回车使用默认）： " in_dest
  if [[ -z "$in_dest" ]]; then
    XRAY_REALITY_DEST="${default_dest}"
  else
    local p2 h2
    parsed="$(parse_host_port "$in_dest")"
    h2="${parsed%%|*}"
    p2="${parsed##*|}"
    [[ -n "$h2" && -n "$p2" ]] || die "DEST 必须是 host:port 格式。"
    validate_port "$p2" || die "DEST 端口不合法：$p2"
    XRAY_REALITY_DEST="${h2}:${p2}"
  fi

  echo
  log "本次安装参数："
  echo "  监听端口：${XRAY_PORT}"
  echo "  SNI：     ${XRAY_REALITY_SNI}"
  echo "  DEST：    ${XRAY_REALITY_DEST}"
  echo
}

write_systemd() {
  log "写入 systemd 服务..."
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

  log "写入配置：${XRAY_CFG} ..."

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
    warn "xray 服务未运行，正在启动..."
    systemctl start xray
  fi
}

open_firewall_and_hints() {
  local port="$1"

  if command -v ufw >/dev/null 2>&1; then
    log "检测到 UFW，正在放行 TCP ${port} ..."
    ufw allow "${port}/tcp" >/dev/null || true
  else
    warn "未检测到 UFW。如你使用其它防火墙，请手动放行 TCP ${port}。"
  fi

  if [[ "${port}" != "443" ]]; then
    echo
    warn "当前端口为 ${port}（非 443），请确认已在以下位置放行："
    echo "  - 云厂商安全组/防火墙（如有）"
    echo "  - 本机防火墙（ufw/iptables/nftables）"
    echo
    echo "iptables 参考（如你使用 iptables）："
    echo "  iptables -I INPUT -p tcp --dport ${port} -j ACCEPT"
    echo
    echo "setcap 参考（本脚本的 systemd 已含 CAP_NET_BIND_SERVICE，一般不需要）："
    echo "  setcap 'cap_net_bind_service=+ep' ${XRAY_BIN}"
    echo
  fi
}

get_server_ip() {
  curl -fsSL --max-time 2 https://api.ipify.org 2>/dev/null || true
}

require_config() {
  [[ -f "${XRAY_CFG}" ]] || die "未找到配置文件：${XRAY_CFG}（请先安装）。"
}

show_links() {
  require_config
  [[ -f "${XRAY_PUBKEY_FILE}" ]] || die "未找到公钥文件：${XRAY_PUBKEY_FILE}"

  local pubkey shortid sni port fp ip uuids i uuid link name
  pubkey="$(cat "${XRAY_PUBKEY_FILE}")"
  shortid="$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "${XRAY_CFG}")"
  sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "${XRAY_CFG}")"
  port="$(jq -r '.inbounds[0].port' "${XRAY_CFG}")"
  fp="${XRAY_FINGERPRINT}"
  ip="$(get_server_ip)"
  [[ -n "$ip" ]] || ip="<你的服务器IP>"

  uuids="$(jq -r '.inbounds[0].settings.clients[].id' "${XRAY_CFG}")"

  echo
  echo "=== 客户端链接（VLESS + REALITY + Vision）==="
  i=0
  while IFS= read -r uuid; do
    [[ -n "$uuid" ]] || continue
    i=$((i+1))
    name="xray-reality-${i}"
    link="vless://${uuid}@${ip}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pubkey}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#${name}"
    echo
    echo "用户 #${i}：${uuid}"
    echo "${link}"
  done <<<"$uuids"
  echo
}

# ---------------- 核心动作 ----------------
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
  [[ "$tag" == v* ]] || die "获取 Xray 版本号失败。"

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
  log "安装完成。"
  echo "  配置文件：${XRAY_CFG}"
  echo "  公钥文件：${XRAY_PUBKEY_FILE}"
  echo
  show_links
}

uninstall_xray() {
  need_root
  log "正在停止服务..."
  systemctl stop xray >/dev/null 2>&1 || true
  systemctl disable xray >/dev/null 2>&1 || true

  log "正在删除 systemd 服务文件..."
  rm -f "${XRAY_SYSTEMD}"
  systemctl daemon-reload || true

  log "正在删除文件..."
  rm -rf "${XRAY_ETC_DIR}"
  rm -rf "${XRAY_LOG_DIR}"
  rm -f "${XRAY_BIN}"

  log "正在删除用户..."
  if id -u xray >/dev/null 2>&1; then
    userdel xray >/dev/null 2>&1 || true
  fi

  log "卸载完成。"
}

status_xray() { systemctl --no-pager --full status xray || true; }
logs_xray()   { journalctl -u xray -e --no-pager || true; }

# ---------------- 修改配置辅助（每次修改前自动备份） ----------------
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
    read -r -p "请输入新的端口： " newport
  fi
  validate_port "$newport" || die "端口不合法：$newport"

  apply_jq_inplace_with_backup '.inbounds[0].port = $p' --argjson p "$newport"
  restart_if_running
  open_firewall_and_hints "$newport"
  log "端口已修改为：$newport"
}

list_users() {
  require_config
  echo
  echo "=== 用户列表（UUID）==="
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
  log "已添加用户：$uuid"
  show_links
}

remove_user() {
  need_root
  require_config
  list_users
  local idx="${1:-}"
  if [[ -z "$idx" ]]; then
    read -r -p "请输入要删除的用户序号： " idx
  fi
  [[ "$idx" =~ ^[0-9]+$ ]] || die "序号不合法。"
  local zero=$((idx-1))
  local count
  count="$(jq '.inbounds[0].settings.clients | length' "${XRAY_CFG}")"
  [[ "$zero" -ge 0 && "$zero" -lt "$count" ]] || die "序号超出范围。"

  apply_jq_inplace_with_backup \
    '.inbounds[0].settings.clients |= (to_entries | map(select(.key != $i)) | map(.value))' \
    --argjson i "$zero"

  restart_if_running
  log "已删除用户 #$idx"
  show_links
}

replace_user_uuid() {
  need_root
  require_config
  list_users
  local idx="${1:-}"
  local newuuid="${2:-}"
  if [[ -z "$idx" ]]; then
    read -r -p "请输入要修改的用户序号： " idx
  fi
  [[ "$idx" =~ ^[0-9]+$ ]] || die "序号不合法。"
  if [[ -z "$newuuid" ]]; then
    read -r -p "请输入新的 UUID： " newuuid
  fi
  [[ -n "$newuuid" ]] || die "UUID 不能为空。"

  local zero=$((idx-1))
  local count
  count="$(jq '.inbounds[0].settings.clients | length' "${XRAY_CFG}")"
  [[ "$zero" -ge 0 && "$zero" -lt "$count" ]] || die "序号超出范围。"

  apply_jq_inplace_with_backup \
    '.inbounds[0].settings.clients |= (to_entries | map(if .key == $i then (.value.id=$id) else .value end))' \
    --argjson i "$zero" --arg id "$newuuid"

  restart_if_running
  log "已修改用户 #$idx 的 UUID。"
  show_links
}

set_ipv4_domains() {
  need_root
  require_config
  local csv="${1:-}"
  if [[ -z "$csv" ]]; then
    echo "请输入需要强制走 IPv4 出口的域名（逗号分隔），留空表示清空："
    read -r -p "域名列表： " csv
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
  log "IPv4 分流域名已更新。"
  echo "当前 routing.rules[0]（如已设置）："
  jq -r '.routing.rules[0] // empty' "${XRAY_CFG}" || true
}

menu_list_backups() {
  echo
  echo "=== 配置备份列表 ==="
  local b
  b="$(list_backups)"
  if [[ -z "$b" ]]; then
    echo "(无)"
  else
    echo "$b"
  fi
  echo
}

menu_rollback() {
  need_root
  menu_list_backups
  local ts
  read -r -p "请输入要回滚的时间戳（YYYYmmdd-HHMMSS），留空=最新备份： " ts
  if [[ -z "$ts" ]]; then
    rollback_config
  else
    rollback_config "$ts"
  fi
}

menu() {
  while true; do
    echo
    echo "================ Xray REALITY 管理菜单 ================"
    echo "1) 安装（VLESS + REALITY + Vision）"
    echo "2) 卸载（停止服务 + 删除文件/用户）"
    echo "3) 查看状态"
    echo "4) 显示客户端链接"
    echo "5) 修改端口"
    echo "6) 查看用户（UUID 列表）"
    echo "7) 添加用户（UUID）"
    echo "8) 删除用户（按序号）"
    echo "9) 修改用户 UUID（按序号）"
    echo "10) 设置 IPv4 分流域名（这些域名走 IPv4 出口）"
    echo "11) 查看日志（journalctl）"
    echo "12) 查看配置备份"
    echo "13) 回滚配置"
    echo "0) 退出"
    echo "======================================================"
    read -r -p "请选择操作编号： " choice

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
      *) warn "无效选项，请重新输入。" ;;
    esac
  done
}

usage() {
  cat <<EOF
用法：
  $0                        # 进入交互菜单
  $0 install                 # 安装（交互终端会提示输入端口/SNI/DEST）
  $0 uninstall               # 卸载
  $0 status                  # 查看状态
  $0 links                   # 显示客户端链接
  $0 set-port <端口>          # 修改端口（自动备份）
  $0 users                   # 查看用户列表
  $0 add-user [uuid]         # 添加用户（自动备份）
  $0 rm-user <序号>           # 删除用户（自动备份）
  $0 set-user <序号> <uuid>   # 修改用户 UUID（自动备份）
  $0 set-ipv4-domains "a.com,b.com"  # 设置 IPv4 分流域名（自动备份）
  $0 backups                 # 查看备份列表
  $0 rollback [时间戳]         # 回滚到指定时间戳（或最新），格式：YYYYmmdd-HHMMSS

非交互安装需要环境变量：
  XRAY_REALITY_SNI="example.com"
  XRAY_REALITY_DEST="example.com:443"

可选：
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
    *) warn "未知命令：$cmd"; usage; exit 1 ;;
  esac
}

main "$@"
