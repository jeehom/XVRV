#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Xray VLESS + REALITY + Vision 管理脚本（Debian/Ubuntu）
# 使用方法：bash -c 'curl -fsSL "https://raw.githubusercontent.com/jeehom/XVRV/main/vless.sh" -o /usr/local/bin/vless && chmod +x /usr/local/bin/vless && exec /usr/local/bin/vless'
# ============================================================

SCRIPT_VERSION="2026-01-01 19:56"
AUTO_CHECK_UPDATES="${AUTO_CHECK_UPDATES:-1}"   # 1=启用；0=关闭
XRAY_BIN="/usr/local/bin/xray"
XRAY_ETC_DIR="/etc/xray"
XRAY_CFG="${XRAY_ETC_DIR}/config.json"
XRAY_PUBKEY_FILE="${XRAY_ETC_DIR}/reality_public.key"
XRAY_SYSTEMD="/etc/systemd/system/xray.service"
XRAY_LOG_DIR="/var/log/xray"
GAI_CONF="/etc/gai.conf"
IPV6_SYSCTL_DROPIN="/etc/sysctl.d/99-xray-disable-ipv6.conf"
SELF_URL="${SELF_URL:-https://raw.githubusercontent.com/jeehom/XVRV/main/vless.sh}"
SELF_INSTALL_PATH_DEFAULT="/usr/local/bin/vless"


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

# ================= HY2 (Hysteria 2) =================
HY2_INSTALL_URL="${HY2_INSTALL_URL:-https://get.hy2.sh/}"
HY2_REPO="${HY2_REPO:-apernet/hysteria}"
HY2_SERVICE="hysteria-server.service"
HY2_CFG="/etc/hysteria/config.yaml"

# 常见安装后二进制名（官方脚本通常装为 hysteria）
HY2_BIN_CANDIDATES=(
  "/usr/local/bin/hysteria"
  "/usr/bin/hysteria"
  "$(command -v hysteria 2>/dev/null || true)"
)



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

  # 因为脚本有 set -euo pipefail，这里要暂时允许失败，否则 apt-get update 一失败就直接退出整个脚本
  set +e
  apt-get update -y
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    warn "apt-get update 失败（通常是第三方源失效/404/没有 Release 文件）。"
    echo
    echo "你可以用下面命令定位坏源（例如 rspamd）："
    echo "  grep -R --line-number \"rspamd\" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null"
    echo
    echo "临时禁用 rspamd 源（示例）："
    echo "  sudo mv /etc/apt/sources.list.d/rspamd*.list /etc/apt/sources.list.d/rspamd.disabled 2>/dev/null || true"
    echo
    echo "然后重试："
    echo "  sudo apt-get update -y"
    echo
    return 1
  fi
    if ! apt-get install -y --no-install-recommends curl unzip jq openssl uuid-runtime ca-certificates; then
      warn "依赖安装失败，尝试使用 --fix-missing 重试一次..."
      apt-get install -y --no-install-recommends --fix-missing curl unzip jq openssl uuid-runtime ca-certificates || return 1
    fi
    return 0
}


fetch_latest_tag() {
  local tag=""

  # 方式 A：GitHub API（可能会被限流或访问失败）
  tag="$(curl -fsSL --max-time 8 \
      "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null \
      | jq -r '.tag_name // empty' 2>/dev/null || true)"

  if [[ -n "$tag" && "$tag" == v* ]]; then
    echo "$tag"
    return 0
  fi

  # 方式 B：解析 releases/latest 的 Location（更不容易被 API 限流）
  # 会返回类似：https://github.com/XTLS/Xray-core/releases/tag/v25.12.8
  local loc
  loc="$(curl -fsSIL --max-time 8 "https://github.com/XTLS/Xray-core/releases/latest" 2>/dev/null \
        | awk -F': ' 'BEGIN{IGNORECASE=1} /^location:/ {print $2}' \
        | tr -d '\r' | tail -n 1 || true)"

  if [[ "$loc" == *"/tag/v"* ]]; then
    tag="${loc##*/tag/}"
  fi

  if [[ -n "$tag" && "$tag" == v* ]]; then
    echo "$tag"
    return 0
  fi

  # 都失败
  echo ""
  return 1
}


get_installed_tag() {
  # 尝试从 xray version 输出提取版本号，例如：Xray 25.12.8
  if [[ -x "${XRAY_BIN}" ]]; then
    "${XRAY_BIN}" version 2>/dev/null | head -n 1 | awk '{print $2}' | sed 's/^v//'
  else
    echo ""
  fi
}

update_xray() {
  need_root

  if [[ ! -x "${XRAY_BIN}" ]]; then
    warn "未检测到 Xray 可执行文件：${XRAY_BIN}"
    warn "请先执行安装。"
    return 0
  fi

  log "正在检测 Xray 更新..."

  local latest_tag installed_ver latest_ver
  latest_tag="$(fetch_latest_tag || true)"

  if [[ -z "$latest_tag" ]]; then
    warn "获取最新版本失败：可能是无法访问 GitHub、DNS/网络问题、或 API 限流。"
    echo "你可以："
    echo "  1) 直接指定版本更新（例如）：XRAY_TAG=v25.12.8 运行安装/更新"
    echo "  2) 先测试网络：curl -I https://github.com/XTLS/Xray-core/releases/latest"
    return 0
  fi

  installed_ver="$(get_installed_tag || true)"
  latest_ver="${latest_tag#v}"

  echo
  echo "当前版本：${installed_ver:-unknown}"
  echo "最新版本：${latest_ver}"
  echo

  # 避免降级：如果当前版本 >= 最新版本，则不更新
  if [[ -n "$installed_ver" ]]; then
    local newest
    newest="$(printf "%s\n%s\n" "$installed_ver" "$latest_ver" | sort -V | tail -n 1)"
    if [[ "$newest" == "$installed_ver" ]]; then
      log "当前版本（${installed_ver}）不低于最新版本（${latest_ver}），无需更新。"
      return 0
    fi
  fi

  read -r -p "发现新版本，是否更新到 ${latest_ver}？输入 yes 确认，回车/0/q 取消： " ans
  case "${ans:-}" in
    yes) ;;
    ""|0|q|Q)
      log "已取消更新。"
      return 0
      ;;
    *)
      warn "未输入 yes，已取消。"
      return 0
      ;;
  esac

  # 备份当前二进制
  if [[ -f "${XRAY_BIN}" ]]; then
    local ts
    ts="$(date +"%Y%m%d-%H%M%S")"
    cp -a "${XRAY_BIN}" "${XRAY_BIN}.bak-${ts}"
    log "已备份旧二进制：${XRAY_BIN}.bak-${ts}"
  fi

  # 下载并安装新版本（download_xray 内部会 die；这里尽量把错误显出来）
  if ! download_xray "$latest_tag"; then
    warn "下载/安装 Xray 失败。请检查网络是否能访问 GitHub releases。"
    return 0
  fi

  # 重启服务
  if systemctl list-unit-files | grep -q '^xray\.service'; then
    systemctl restart xray || true
  fi

  echo
  log "更新完成。"
  echo "更新后版本：$("${XRAY_BIN}" version 2>/dev/null | head -n 1 || true)"
}


download_xray() {
  local tag="$1"
  local arch filename url tmpdir
  arch="$(detect_arch)"
  filename="Xray-linux-${arch}.zip"
  url="https://github.com/XTLS/Xray-core/releases/download/${tag}/${filename}"

  tmpdir="$(mktemp -d)"
  trap '[[ -n "${tmpdir:-}" ]] && rm -rf "$tmpdir"' RETURN

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

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts bak
  ts="$(date +"%Y%m%d-%H%M%S")"
  bak="${f}.bak-${ts}"
  cp -a "$f" "$bak"
  log "已创建备份：${bak}"
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
  if ! apt_install_deps; then
    warn "依赖安装未完成：请先修复 apt 源问题后再重试安装。"
    return 0
  fi


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

start_xray() {
  need_root
  systemctl start xray
  log "已启动 xray 服务。"
}

stop_xray() {
  need_root
  systemctl stop xray
  log "已停止 xray 服务。"
}

restart_xray() {
  need_root
  systemctl restart xray
  log "已重启 xray 服务。"
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

  local curport
  curport="$(jq -r '.inbounds[0].port' "${XRAY_CFG}" 2>/dev/null || echo "")"

  local newport="${1:-}"

  # 交互模式：回车取消
  if [[ -z "${newport}" ]]; then
    echo "当前端口：${curport}"
    read -r -p "请输入新的端口（回车/0/q 取消）： " newport
    case "${newport:-}" in
      ""|0|q|Q)
        log "已取消，未修改端口。"
        return 0
        ;;
    esac
  fi

  validate_port "$newport" || die "端口不合法：$newport"

  # 如果新端口和旧端口一致，直接返回
  if [[ -n "$curport" && "$newport" == "$curport" ]]; then
    log "新端口与当前端口相同（${curport}），未做修改。"
    return 0
  fi

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
    read -r -p "请输入要删除的用户序号（回车/0/q 取消）： " idx
    case "${idx:-}" in
      ""|0|q|Q)
        log "已取消，未删除任何用户。"
        return 0
        ;;
    esac
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
    read -r -p "请输入要修改的用户序号（回车/0/q 取消）： " idx
    case "${idx:-}" in
      ""|0|q|Q)
        log "已取消，未修改任何用户。"
        return 0
        ;;
    esac
  fi
  [[ "$idx" =~ ^[0-9]+$ ]] || die "序号不合法。"

  local zero=$((idx-1))
  local count
  count="$(jq '.inbounds[0].settings.clients | length' "${XRAY_CFG}")"
  [[ "$zero" -ge 0 && "$zero" -lt "$count" ]] || die "序号超出范围。"

  local olduuid
  olduuid="$(jq -r ".inbounds[0].settings.clients[$zero].id" "${XRAY_CFG}")"
  echo "当前用户 #${idx} UUID：${olduuid}"

  if [[ -z "$newuuid" ]]; then
    read -r -p "请输入新的 UUID（回车/0/q 取消）： " newuuid
    case "${newuuid:-}" in
      ""|0|q|Q)
        log "已取消，未修改 UUID。"
        return 0
        ;;
    esac
  fi
  [[ -n "$newuuid" ]] || die "UUID 不能为空。"

  if [[ "$newuuid" == "$olduuid" ]]; then
    log "新 UUID 与当前相同，未做修改。"
    return 0
  fi

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

  # 先显示当前配置（进入 10 就能看到）
  echo
  echo "=== 当前 IPv4 分流配置 ==="
  local cur
  cur="$(jq -r '
    (.routing.rules // [])
    | map(select(.outboundTag=="direct_ipv4"))
    | .[0].domain // empty
    | if type=="array" then join(",") else "" end
  ' "${XRAY_CFG}" 2>/dev/null || true)"

  if [[ -z "$cur" ]]; then
    echo "当前：未设置 IPv4 分流域名（没有 direct_ipv4 规则）"
  else
    echo "当前 IPv4 分流域名：${cur}"
  fi

  echo "当前 routing.rules："
  jq -c '.routing.rules // []' "${XRAY_CFG}" 2>/dev/null | jq . || true
  echo "=========================="
  echo

  # 命令行参数传入：保持原行为（允许传空来清空）
  if [[ -n "${1+set}" ]]; then
    XRAY_IPV4_DOMAINS="$csv"
  else
    echo "请输入需要强制走 IPv4 出口的域名（逗号分隔）。"
    echo "  - 回车 / 0 / q：取消，不做任何修改"
    echo "  - 输入 clear：清空 IPv4 分流域名"
    read -r -p "域名列表： " csv

    case "${csv:-}" in
      ""|0|q|Q)
        log "已取消，未修改配置。"
        return 0
        ;;
      clear|CLEAR|Clear)
        csv=""
        ;;
      *)
        ;;
    esac

    XRAY_IPV4_DOMAINS="$csv"
  fi

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
  if [[ -z "${XRAY_IPV4_DOMAINS}" ]]; then
    log "已清空 IPv4 分流域名。"
  else
    log "IPv4 分流域名已更新。"
  fi

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
  read -r -p "请输入要回滚的时间戳（YYYYmmdd-HHMMSS），输入 latest=最新备份，回车/0/q 取消： " ts
  case "${ts:-}" in
    ""|0|q|Q)
      log "已取消，未回滚配置。"
      return 0
      ;;
    latest|LATEST|Latest)
      rollback_config
      ;;
    *)
      rollback_config "$ts"
      ;;
  esac
}


pause_or_exit() {
  echo
  while true; do
    read -r -p "（回车）继续 / 输入 0 退出脚本： " ans
    case "${ans:-}" in
      "") return 0 ;;
      0) exit 0 ;;
      *) echo "无效输入，请回车返回或输入 0 退出。" ;;
    esac
  done
}

show_ipv4_prefer_status() {
  if [[ ! -f "$GAI_CONF" ]]; then
    echo "IPv4 优先：未启用（$GAI_CONF 不存在）"
    return 0
  fi

  local enabled commented
  enabled="$(grep -nE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "$GAI_CONF" 2>/dev/null || true)"
  commented="$(grep -nE '^[[:space:]]*#[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "$GAI_CONF" 2>/dev/null || true)"

  if [[ -n "$enabled" ]]; then
    echo "IPv4 优先：已启用（命中行如下）"
    echo "$enabled"
  elif [[ -n "$commented" ]]; then
    echo "IPv4 优先：未启用（存在被注释的规则）"
    echo "$commented"
  else
    echo "IPv4 优先：未启用（未找到 precedence 规则）"
  fi
}


set_ipv4_prefer() {
  need_root
  # 确保文件存在
  [[ -f "$GAI_CONF" ]] || touch "$GAI_CONF"

  echo
  echo "=== 设置 IPv4 优先（glibc gai.conf）==="
  show_ipv4_prefer_status

  backup_file "$GAI_CONF"

  # 1) 如果存在被注释的规则，取消注释
  if grep -qE '^[[:space:]]*#[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "$GAI_CONF"; then
    sed -i -E 's/^[[:space:]]*#[[:space:]]*(precedence[[:space:]]+::ffff:0:0\/96[[:space:]]+100)/\1/' "$GAI_CONF"
  else
    # 2) 如果不存在该规则，则追加
    if ! grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "$GAI_CONF"; then
      printf "\n# 由 xray 管理脚本添加：优先使用 IPv4\nprecedence ::ffff:0:0/96  100\n" >> "$GAI_CONF"
    fi
  fi

  log "已设置 IPv4 优先。部分程序可能需要重启后才完全生效。"
  show_ipv4_prefer_status
}

restore_ipv4_prefer() {
  need_root
  [[ -f "$GAI_CONF" ]] || die "找不到 $GAI_CONF"

  echo
  echo "=== 恢复默认（取消 IPv4 优先）==="
  show_ipv4_prefer_status

  # 只有在确实启用时才备份并改动
  if grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "$GAI_CONF"; then
    backup_file "$GAI_CONF"
    # 注释掉所有启用的 precedence 行（保守可逆）
    sed -i -E 's/^[[:space:]]*(precedence[[:space:]]+::ffff:0:0\/96[[:space:]]+100)/# \1/' "$GAI_CONF"
    log "已取消 IPv4 优先（已将 precedence 行注释）。"
  else
    log "当前未启用 IPv4 优先，无需修改。"
  fi

  show_ipv4_prefer_status
}

show_ipv6_status() {
  local a d lo
  a="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")"
  d="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "unknown")"
  lo="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo "unknown")"

  echo "当前 sysctl：all.disable_ipv6=${a}  default.disable_ipv6=${d}  lo.disable_ipv6=${lo}"

  if [[ "$a" == "1" || "$d" == "1" || "$lo" == "1" ]]; then
    echo "IPv6 当前状态：已禁用（至少一个 disable_ipv6=1）"
  elif [[ "$a" == "0" && "$d" == "0" && "$lo" == "0" ]]; then
    echo "IPv6 当前状态：未禁用（disable_ipv6 全为 0）"
  else
    echo "IPv6 当前状态：未知（无法读取完整 sysctl 值）"
  fi

  if [[ -f "$IPV6_SYSCTL_DROPIN" ]]; then
    echo "脚本禁用配置文件：存在（$IPV6_SYSCTL_DROPIN）"
  else
    echo "脚本禁用配置文件：不存在（$IPV6_SYSCTL_DROPIN）"
  fi

  # 查找其它来源：/etc/sysctl.conf 与 /etc/sysctl.d
  local hits
  hits="$(grep -R --line-number -E '^[[:space:]]*net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6[[:space:]]*=[[:space:]]*1' \
    /etc/sysctl.conf /etc/sysctl.d 2>/dev/null | head -n 10 || true)"

  if [[ -n "$hits" ]]; then
    echo "检测到可能的“禁用来源”（文件中设置为 1）："
    echo "$hits"
  else
    echo "未在 /etc/sysctl.conf 或 /etc/sysctl.d 检测到 disable_ipv6=1（可能由其它方式设置）。"
  fi

  # 检查内核启动参数
  if grep -q 'ipv6.disable=1' /proc/cmdline 2>/dev/null; then
    echo "检测到内核启动参数：ipv6.disable=1（这会强制禁用 IPv6）"
  fi
}


disable_ipv6() {
  need_root
  echo
  echo "=== 禁用服务器 IPv6（sysctl）==="
  echo "提示：如果你通过 IPv6 登录/依赖 IPv6 业务，禁用后可能断连或影响服务。"
  show_ipv6_status

  # 如已存在则备份再覆盖
  if [[ -f "$IPV6_SYSCTL_DROPIN" ]]; then
    backup_file "$IPV6_SYSCTL_DROPIN"
  fi

  cat > "$IPV6_SYSCTL_DROPIN" <<'EOF'
# 由 xray 管理脚本写入：禁用 IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

  sysctl --system >/dev/null 2>&1 || true

  log "已写入并应用：禁用 IPv6。"
  show_ipv6_status
}

restore_ipv6() {
  need_root
  echo
  echo "=== 恢复服务器 IPv6（撤销禁用）==="
  show_ipv6_status
  echo

  if grep -q 'ipv6.disable=1' /proc/cmdline 2>/dev/null; then
    warn "检测到内核启动参数 ipv6.disable=1：这会强制禁用 IPv6。"
    warn "仅修改 sysctl 不会生效；需要修改 grub/启动参数并重启服务器。"
    return 1
  fi

  echo "将要执行的操作："
  echo "  - 在 /etc/sysctl.conf 中把以下三项改为 0（或恢复为未禁用）："
  echo "      net.ipv6.conf.all.disable_ipv6"
  echo "      net.ipv6.conf.default.disable_ipv6"
  echo "      net.ipv6.conf.lo.disable_ipv6"
  echo "  - 然后执行 sysctl --system 使其生效"
  echo
  echo "输入 yes 确认执行；回车/0/q 取消。"
  read -r -p "确认： " ans

  case "${ans:-}" in
    yes)
      ;;
    ""|0|q|Q)
      log "已取消，未修改任何内容。"
      return 0
      ;;
    *)
      warn "未输入 yes，已取消。"
      return 0
      ;;
  esac

  # 备份
  backup_file /etc/sysctl.conf

  # 将三项设置为 0（如果不存在则追加）
  # 1) 先替换已有行（无论原来是 1 还是 0 都统一成 0）
  sed -i -E \
    's/^[[:space:]]*(net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6[[:space:]]*=[[:space:]]*).*/\10/' \
    /etc/sysctl.conf

  # 2) 若文件中完全没有这些键，则追加（避免“替换不到”导致没效果）
  if ! grep -qE '^[[:space:]]*net\.ipv6\.conf\.all\.disable_ipv6[[:space:]]*=' /etc/sysctl.conf; then
    printf "\n# 由 xray 管理脚本写入：恢复 IPv6\nnet.ipv6.conf.all.disable_ipv6 = 0\n" >> /etc/sysctl.conf
  fi
  if ! grep -qE '^[[:space:]]*net\.ipv6\.conf\.default\.disable_ipv6[[:space:]]*=' /etc/sysctl.conf; then
    printf "net.ipv6.conf.default.disable_ipv6 = 0\n" >> /etc/sysctl.conf
  fi
  if ! grep -qE '^[[:space:]]*net\.ipv6\.conf\.lo\.disable_ipv6[[:space:]]*=' /etc/sysctl.conf; then
    printf "net.ipv6.conf.lo.disable_ipv6 = 0\n" >> /etc/sysctl.conf
  fi

  # 应用配置（用 --system 更贴近真实启动加载路径）
  sysctl --system >/dev/null 2>&1 || true

  # 再保险：即时写入（避免某些系统加载顺序影响）
  sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true

  log "已尝试恢复 IPv6（已修改 /etc/sysctl.conf 并应用）。"
  echo
  show_ipv6_status
}


server_settings_menu() {
  while true; do
    echo
    echo "================ 服务器设置 ================"
    echo "1) 设置服务器 IPv4 优先（gai.conf）"
    echo "2) 恢复默认地址优先级（取消 IPv4 优先）"
    echo "3) 禁用服务器 IPv6（sysctl）"
    echo "4) 恢复服务器 IPv6（撤销禁用）"
    echo "5) 查看当前服务器网络设置状态"
    echo "0) 返回主菜单"
    echo "==========================================="
    read -r -p "请选择操作编号： " c

    case "$c" in
      1) set_ipv4_prefer;     pause_or_exit ;;
      2) restore_ipv4_prefer; pause_or_exit ;;
      3) disable_ipv6;        pause_or_exit ;;
      4) restore_ipv6;        pause_or_exit ;;
      5)
        echo
        echo "=== 当前服务器网络设置状态 ==="
        echo "[IPv4 优先]"
        show_ipv4_prefer_status
        echo
        echo "[IPv6 状态]"
        show_ipv6_status
        pause_or_exit
        ;;
      0) return 0 ;;
      *) warn "无效选项，请重新输入。" ;;
    esac
  done
}
user_menu() {
  while true; do
    echo
    echo "================ 用户管理（UUID） ================"
    echo "1) 查看用户列表（UUID）"
    echo "2) 添加用户（UUID）"
    echo "3) 删除用户（按序号）"
    echo "4) 修改用户 UUID（按序号）"
    echo "0) 返回主菜单"
    echo "=================================================="
    read -r -p "请选择操作编号： " c

    case "$c" in
      1) list_users;        pause_or_exit ;;
      2) add_user;          pause_or_exit ;;
      3) remove_user;       pause_or_exit ;;
      4) replace_user_uuid; pause_or_exit ;;
      0) return 0 ;;
      *) warn "无效选项，请重新输入。" ;;
    esac
  done
}

service_menu() {
  while true; do
    echo
    echo "================ 服务管理（Xray） ================"
    echo "1) 查看状态"
    echo "2) 启动服务"
    echo "3) 停止服务"
    echo "4) 重启服务"
    echo "5) 检测/更新 Xray"
    echo "0) 返回主菜单"
    echo "=================================================="
    read -r -p "请选择操作编号： " c

    case "$c" in
      1) status_xray;  pause_or_exit ;;
      2) start_xray;   pause_or_exit ;;
      3) stop_xray;    pause_or_exit ;;
      4) restart_xray; pause_or_exit ;;
      5) update_xray;  pause_or_exit ;;
      0) return 0 ;;
      *) warn "无效选项，请重新输入。" ;;
    esac
  done
}

get_remote_script_version() {
  # 从远端脚本里提取 SCRIPT_VERSION="..."
  # 加“防缓存”参数 + no-cache 头，尽量避免拿到旧版本
  local url="${SELF_URL}"
  local bust
  bust="$(date +%s)"

  curl -fsSL --max-time 10 \
    -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
    "${url}?_=${bust}" 2>/dev/null \
    | head -n 200 \
    | awk -F'"' '/^[[:space:]]*SCRIPT_VERSION="/ {print $2; exit}' \
    | tr -d '\r' \
    || true
}


auto_check_self_update() {
  [[ "${AUTO_CHECK_UPDATES}" == "1" ]] || return 0
  [[ -t 0 ]] || return 0
  command -v curl >/dev/null 2>&1 || return 0
  [[ -n "${SELF_URL:-}" ]] || return 0

  local remote_ver local_ver
  local_ver="${SCRIPT_VERSION:-unknown}"
  remote_ver="$(get_remote_script_version || true)"
  [[ -n "$remote_ver" ]] || return 0

  # 只在“远端版本更大”时提示更新
  # 你的版本格式是：YYYY-MM-DD HH:MM ，可以直接转 epoch 比较
  local local_ts remote_ts
  local_ts="$(date -d "$local_ver" +%s 2>/dev/null || echo 0)"
  remote_ts="$(date -d "$remote_ver" +%s 2>/dev/null || echo 0)"

  # 如果解析失败（=0），就退化为“不提示”，避免误报
  if [[ "$local_ts" -le 0 || "$remote_ts" -le 0 ]]; 键，然后
    return 0
  fi

  # 远端不比本地新：不提示（包括远端更旧的情况）
  if [[ "$remote_ts" -le "$local_ts" ]]; 键，然后
    return 0
  fi

  echo
  echo "[!] 检测到脚本有新版本："
  echo "    本地：${local_ver}"
  echo "    远端：${remote_ver}"
  read -r -p "是否现在更新脚本？输入 yes 更新（回车跳过）： " ans
  if [[ "${ans:-}" == "yes" ]]; 键，然后
    UPDATE_SELF_MODE="auto" update_self
  fi
}


auto_check_xray_update() {
  [[ "${AUTO_CHECK_UPDATES}" == "1" ]] || return 0
  [[ -t 0 ]] || return 0   # 非交互不提示
  [[ -x "${XRAY_BIN}" ]] || return 0

  # fetch_latest_tag 你已经有“稳健版”（API+redirect），这里直接用即可
  local latest_tag installed_ver latest_ver
  latest_tag="$(fetch_latest_tag || true)"
  [[ -n "$latest_tag" ]] || return 0

  installed_ver="$(get_installed_tag || true)"
  latest_ver="${latest_tag#v}"

  [[ -n "$installed_ver" ]] || return 0

  # 避免降级：installed >= latest 就不提示
  local newest
  newest="$(printf "%s\n%s\n" "$installed_ver" "$latest_ver" | sort -V | tail -n 1)"
  if [[ "$newest" == "$installed_ver" ]]; 键，然后
    return 0
  fi

  echo
  echo "[!] 检测到 Xray 可更新："
  echo "    当前：${installed_ver}"
  echo "    最新：${latest_ver}"
  read -r -p "是否现在更新 Xray？输入 yes 更新（回车跳过）： " ans
  if [[ "${ans:-}" == "yes" ]]; 键，然后
    update_xray
  fi
}

update_self() {
  need_root

  local url="${SELF_URL}"
  local cur="${0}"
  local target=""
  local local_ver="${SCRIPT_VERSION:-unknown}"
  local mode="${UPDATE_SELF_MODE:-manual}"   # manual=菜单手动更新；auto=启动自动更新

  echo
  echo "=== 更新脚本 ==="
  echo "更新地址：${url}"
  echo "当前运行路径：${cur}"
  echo "本地脚本版本：${local_ver}"

  target="${SELF_INSTALL_PATH_DEFAULT}"
  if [[ "$(readlink -f "$cur" 2>/dev/null || echo "$cur")" == "$target" ]]; 键，然后
    target="$cur"
  fi
  echo "将更新到：${target}"
  echo

  # 先获取远端版本号（不落盘）
  local remote_ver
  remote_ver="$(get_remote_script_version || true)"
  [[ -n "$remote_ver" ]] || remote_ver="unknown"
  echo "远端脚本版本：${remote_ver}"
  echo

  # ✅ 相同版本直接退出（不下载、不备份、不覆盖）
  if [[ "$remote_ver" != "unknown" && "$local_ver" == "$remote_ver" ]]; then
    log "本地与远端版本一致，无需更新。"
    return 0
  fi

  # 手动更新才需要确认；自动更新模式直接继续
  if [[ "$mode" == "manual" ]]; then
    if ! confirm_yes "发现新版本，是否更新脚本？输入 yes 确认，回车/0/q 取消： "; then
      log "已取消更新脚本。"
      return 0
    fi
  fi

  local tmp ts bak
  tmp="$(mktemp -t vless.XXXXXX)"
  ts="$(date +"%Y%m%d-%H%M%S")"
  trap 'rm -f "$tmp"' RETURN

  log "正在下载最新脚本..."
  if ! curl -fsSL --retry 3 --retry-delay 1 "$url" -o "$tmp"; then
    warn "下载失败：请检查 GitHub raw 是否可访问。"
    return 0
  fi

  # 简单自检：避免下载到 HTML/错误页
  if ! head -n 1 "$tmp" | grep -qE '^#!/usr/bin/env bash'; then
    warn "下载内容疑似不是脚本（首行不是 shebang）。已取消写入。"
    echo "前几行内容如下："
    head -n 5 "$tmp" || true
    return 0
  fi

  # 再从下载文件里提一次版本号，作为最终展示（更准确）
  remote_ver="$(awk -F'"' '/^SCRIPT_VERSION="/ {print $2; exit}' "$tmp" | tr -d '\r' || true)"
  [[ -n "$remote_ver" ]] || remote_ver="unknown"

  # ✅ 如果下载后发现还是同版本（比如刚刚 remote 变化），也不写入
  if [[ "$remote_ver" != "unknown" && "$local_ver" == "$remote_ver" ]]; then
    log "下载后确认本地与远端版本一致，无需更新。"
    return 0
  fi

  # 备份旧文件
  if [[ -f "$target" ]]; then
    bak="${target}.bak-${ts}"
    cp -a "$target" "$bak" || true
    log "已备份旧脚本：${bak}"
  fi

  install -m 0755 "$tmp" "$target"
  log "脚本已更新：${target}"

  echo
  echo "更新完成："
  echo "  原版本：${local_ver}"
  echo "  新版本：${remote_ver}"
  echo

  # 自动更新模式：继续保持自动重启
  if [[ "$mode" == "auto" ]]; then
    exec "$target"
  fi

  return 0
}

# ================ hy2 管理==========================================

hy2_bin_path() {
  local p
  for p in "${HY2_BIN_CANDIDATES[@]}"; do
    [[ -n "${p:-}" && -x "$p" ]] && { echo "$p"; return 0; }
  done
  echo ""
  return 1
}

hy2_installed_ver() {
  local bin
  bin="$(hy2_bin_path || true)"
  [[ -n "$bin" ]] || { echo ""; return 0; }

  # 尽量兼容不同输出
  local out
  out="$("$bin" version 2>/dev/null | head -n 1 || true)"
  if [[ -z "$out" ]]; then
    out="$("$bin" --version 2>/dev/null | head -n 1 || true)"
  fi

  # 提取类似 2.6.5 / v2.6.5
  echo "$out" | grep -Eo 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 | sed 's/^v//'
}

hy2_fetch_latest_tag() {
  local tag=""
  tag="$(curl -fsSL --max-time 8 "https://api.github.com/repos/${HY2_REPO}/releases/latest" 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true)"
  if [[ -n "$tag" && "$tag" == v* ]]; then
    echo "$tag"; return 0
  fi

  # fallback: parse redirect
  local loc
  loc="$(curl -fsSIL --max-time 8 "https://github.com/${HY2_REPO}/releases/latest" 2>/dev/null \
        | awk -F': ' 'BEGIN{IGNORECASE=1} /^location:/ {print $2}' \
        | tr -d '\r' | tail -n 1 || true)"
  if [[ "$loc" == *"/tag/v"* ]]; then
    tag="${loc##*/tag/}"
  fi
  [[ -n "$tag" && "$tag" == v* ]] && { echo "$tag"; return 0; }

  echo ""
  return 1
}

install_or_upgrade_hy2() {
  need_root
  echo
  echo "=== 安装/升级 HY2（Hysteria 2）==="
  echo "将执行官方安装脚本：bash <(curl -fsSL https://get.hy2.sh/)"
  read -r -p "输入 yes 确认继续（回车/0/q 取消）： " ans
  case "${ans:-}" in
    yes) ;;
    ""|0|q|Q) log "已取消。"; return 0 ;;
    *) warn "未输入 yes，已取消。"; return 0 ;;
  esac

  # 安装/升级
  if ! bash <(curl -fsSL https://get.hy2.sh/); then
    warn "官方安装脚本执行失败。"
    return 0
  fi

  log "HY2 安装/升级完成，进入配置向导..."
  hy2_config_wizard
}


uninstall_hy2() {
  need_root
  echo
  echo "=== 卸载 HY2（删除二进制 + 停服务 + 移除 systemd）==="
  echo "将执行官方卸载：bash <(curl -fsSL ${HY2_INSTALL_URL}) --remove :contentReference[oaicite:3]{index=3}"
  echo "注意：配置文件是否删除取决于官方脚本行为；如需彻底清理可手动删除 /etc/hysteria/"
  echo

  read -r -p "输入 yes 确认卸载（回车/0/q 取消）： " ans
  case "${ans:-}" in
    yes) ;;
    ""|0|q|Q) log "已取消卸载。"; return 0 ;;
    *) warn "未输入 yes，已取消。"; return 0 ;;
  esac

  bash <(curl -fsSL "${HY2_INSTALL_URL}") --remove || true
  log "已执行卸载流程。"
}

hy2_status()  { systemctl --no-pager --full status "${HY2_SERVICE}" || true; }
hy2_start()   { need_root; systemctl start  "${HY2_SERVICE}" || true; log "已启动 HY2 服务。"; }
hy2_stop()    { need_root; systemctl stop   "${HY2_SERVICE}" || true; log "已停止 HY2 服务。"; }
hy2_restart() { need_root; systemctl restart "${HY2_SERVICE}" || true; log "已重启 HY2 服务。"; }
hy2_logs()    { journalctl -u "${HY2_SERVICE}" -e --no-pager || true; }

update_hy2() {
  need_root
  echo
  echo "=== 检测/更新 HY2（Hysteria 2）==="

  local bin installed_ver latest_tag latest_ver
  installed_ver="$(hy2_installed_ver || true)"
  latest_tag="$(hy2_fetch_latest_tag || true)"
  latest_ver="${latest_tag#v}"

  echo "当前版本：${installed_ver:-unknown}"
  echo "最新版本：${latest_ver:-unknown}"
  echo

  if [[ -z "$latest_tag" ]]; then
    warn "获取最新版本失败：可能网络无法访问 GitHub 或被限流。"
    return 0
  fi

  # 如果本地版本可读且 >= 最新版本 -> 不更新
  if [[ -n "$installed_ver" ]]; then
    local newest
    newest="$(printf "%s\n%s\n" "$installed_ver" "$latest_ver" | sort -V | tail -n 1)"
    if [[ "$newest" == "$installed_ver" ]]; then
      log "当前已是最新或更高版本，无需更新。"
      return 0
    fi
  fi

  read -r -p "发现新版本，是否更新到 ${latest_ver}？输入 yes 更新（回车/0/q 取消）： " ans
  case "${ans:-}" in
    yes) ;;
    ""|0|q|Q) log "已取消更新。"; return 0 ;;
    *) warn "未输入 yes，已取消。"; return 0 ;;
  esac

  # 官方脚本“安装或升级到最新版本”就是再跑一次
  if ! bash <(curl -fsSL "${HY2_INSTALL_URL}"); then
    warn "更新失败：请检查网络是否能访问 GitHub Release。"
    return 0
  fi

  # 尝试重启服务（存在则重启）
  systemctl list-unit-files | grep -q "^${HY2_SERVICE}" && systemctl restart "${HY2_SERVICE}" || true
  log "HY2 已更新完成。"
}

hy2_random_password() {
  openssl rand -base64 18 | tr -d '\n'
}

hy2_validate_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 && "$1" -le 65535 ]]
}

hy2_open_firewall_hints() {
  local port="$1"
  echo
  warn "HY2 使用 UDP 端口，请确认已放行 UDP ${port}："
  echo "  - 云厂商安全组/防火墙（如有）"
  echo "  - 本机防火墙（ufw/iptables/nftables）"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${port}/udp" >/dev/null 2>&1 || true
    log "已尝试通过 UFW 放行 UDP ${port}（如启用 UFW）。"
  fi
  echo
}

hy2_config_wizard() {
  need_root

  echo
  echo "=== HY2 配置向导（生成可用服务端配置）==="
  echo "配置文件：${HY2_CFG}"
  echo

  # 端口
  local default_port="443"
  local port=""
  read -r -p "监听端口（UDP，默认 ${default_port}，回车/0/q 取消）： " port
  case "${port:-}" in
    "" ) port="$default_port" ;;
    0|q|Q) log "已取消，未修改 HY2 配置。"; return 0 ;;
  esac
  hy2_validate_port "$port" || die "端口不合法：$port"

  echo
  echo "证书方式："
  echo "1) ACME 自动申请证书（需要域名解析到本机；通常走 80 端口完成验证）"
  echo "2) 使用已有证书文件（cert/key 路径）"
  echo "（回车/0/q 取消）"
  local mode=""
  read -r -p "请选择： " mode
  case "${mode:-}" in
    ""|0|q|Q) log "已取消，未修改 HY2 配置。"; return 0 ;;
  esac

  local auth_pass
  auth_pass="$(hy2_random_password)"

  # 备份旧配置（如果存在）
  if [[ -f "$HY2_CFG" ]]; then
    backup_file "$HY2_CFG"
  fi

  if [[ "$mode" == "1" ]]; then
    local domain email
    read -r -p "请输入域名（例如 hy2.example.com；回车/0/q 取消）： " domain
    case "${domain:-}" in ""|0|q|Q) log "已取消，未修改 HY2 配置。"; return 0 ;; esac
    read -r -p "请输入邮箱（用于 ACME；回车/0/q 取消）： " email
    case "${email:-}" in ""|0|q|Q) log "已取消，未修改 HY2 配置。"; return 0 ;; esac

    # 参考官方快速配置模板：listen + acme + auth(password):contentReference[oaicite:1]{index=1}
    cat >"$HY2_CFG" <<EOF
listen: :${port}

acme:
  domains:
    - ${domain}
  email: ${email}

auth:
  type: password
  password: ${auth_pass}
EOF

    log "已写入 ACME 配置。注意：ACME 通常需要 80 端口可达用于验证。"
  elif [[ "$mode" == "2" ]]; then
    local cert key
    read -r -p "cert 证书路径（例如 /etc/ssl/fullchain.pem；回车/0/q 取消）： " cert
    case "${cert:-}" in ""|0|q|Q) log "已取消，未修改 HY2 配置。"; return 0 ;; esac
    read -r -p "key 私钥路径（例如 /etc/ssl/privkey.pem；回车/0/q 取消）： " key
    case "${key:-}" in ""|0|q|Q) log "已取消，未修改 HY2 配置。"; return 0 ;; esac

    [[ -f "$cert" ]] || warn "证书文件不存在：$cert（如果稍后才放上来也可以，但服务启动会失败）"
    [[ -f "$key"  ]] || warn "私钥文件不存在：$key（如果稍后才放上来也可以，但服务启动会失败）"

    # 参考官方快速配置模板：listen + tls(cert/key) + auth(password):contentReference[oaicite:2]{index=2}
    cat >"$HY2_CFG" <<EOF
listen: :${port}

tls:
  cert: ${cert}
  key: ${key}

auth:
  type: password
  password: ${auth_pass}
EOF

    log "已写入自有证书配置。"
  else
    warn "无效选择：$mode"
    return 0
  fi

  chmod 600 "$HY2_CFG" 2>/dev/null || true

  # 启动并自启
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now "$HY2_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$HY2_SERVICE" >/dev/null 2>&1 || true

  echo
  log "HY2 配置完成并已尝试启动服务。"
  echo "服务密码（请保存）：${auth_pass}"
  hy2_open_firewall_hints "$port"
  systemctl --no-pager --full status "$HY2_SERVICE" || true
}

hy2_service_menu() {
  while true; do
    echo
    echo "================ HY2 服务管理 ================"
    echo "1) 查看状态"
    echo "2) 启动服务"
    echo "3) 停止服务"
    echo "4) 重启服务"
    echo "5) 查看日志"
    echo "0) 返回上一层"
    echo "============================================="
    read -r -p "请选择操作编号： " c
    case "$c" in
      1) hy2_status;  pause_or_exit ;;
      2) hy2_start;   pause_or_exit ;;
      3) hy2_stop;    pause_or_exit ;;
      4) hy2_restart; pause_or_exit ;;
      5) hy2_logs;    pause_or_exit ;;
      0) return 0 ;;
      *) warn "无效选项，请重新输入。" ;;
    esac
  done
}

hy2_menu() {
  while true; do
    echo
    echo "================ HY2 管理（Hysteria 2） ================"
    echo "1) 安装/升级 HY2"
    echo "2) 卸载 HY2（删二进制/删服务/停服务）"
    echo "3) 服务管理（状态/启动/停止/重启/日志）"
    echo "4) 检测/更新 HY2（类似 update_xray）"
    echo "0) 返回主菜单"
    echo "========================================================"
    read -r -p "请选择操作编号： " c
    case "$c" in
      1) install_or_upgrade_hy2;     pause_or_exit ;;
      2) uninstall_hy2;   pause_or_exit ;;
      3) hy2_service_menu ;;
      4) update_hy2;      pause_or_exit ;;
      0) return 0 ;;
      *) warn "无效选项，请重新输入。" ;;
    esac
  done
}

menu() {
  while true; do
    echo
    echo "================ Xray REALITY 管理菜单 ================"
    echo "1) 安装（VLESS + REALITY + Vision）"
    echo "2) 卸载（停止服务 + 删除文件/用户）"
    echo "3) 服务管理（状态/启动/停止/重启/更新）"
    echo "4) 显示客户端链接"
    echo "5) 修改端口"
    echo "6) 用户管理（查看/添加/删除/修改 UUID）"
    echo "7) 设置 IPv4 分流域名（这些域名走 IPv4 出口）"
    echo "8) 查看日志（journalctl）"
    echo "9) 查看配置备份"
    echo "10) 回滚配置"
    echo "11) 服务器设置"
    echo "12) 更新脚本（当前：${SCRIPT_VERSION}）"
    echo "13) HY2 管理（安装/卸载/服务/更新）"
    echo "0) 退出"
    echo "======================================================"
    read -r -p "请选择操作编号： " choice

    case "$choice" in
      1) install_xray;        pause_or_exit ;;
      2) uninstall_xray;      pause_or_exit ;;
      3) service_menu ;;
      4) show_links;          pause_or_exit ;;
      5) set_port;            pause_or_exit ;;
      6) user_menu ;;
      7) set_ipv4_domains;   pause_or_exit ;;
      8) logs_xray;          pause_or_exit ;;
      9) menu_list_backups;  pause_or_exit ;;
      10) menu_rollback;      pause_or_exit ;;
      11) server_settings_menu ;;
      12) update_self; pause_or_exit ;;
      13) hy2_menu ;;
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
    "")
      auto_check_self_update
      auto_check_xray_update
      menu
      ;;
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
