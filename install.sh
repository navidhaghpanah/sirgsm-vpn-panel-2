#!/usr/bin/env bash
# SirGSM VPN Panel 2 — Ubuntu 24.04 LTS, amd64 / arm64.
set -Eeuo pipefail
umask 027
LANGUAGE=en
SERVER_IP=${SIRGSM_SERVER_IP:-}
UPGRADE=0
RELEASE=v0.1.0
while (($#)); do
 case "$1" in
  --lang) LANGUAGE=${2:?}; shift 2 ;;
  --server-ip) SERVER_IP=${2:?}; shift 2 ;;
  --upgrade) UPGRADE=1; shift ;;
  --help) echo 'Usage: sudo bash install.sh [--lang en|fa] [--server-ip PUBLIC_IPV4] [--upgrade]'; exit 0 ;;
  *) echo "Unknown argument: $1" >&2; exit 2 ;;
 esac
done
[[ "$LANGUAGE" == en || "$LANGUAGE" == fa ]] || exit 2
say(){ if [[ "$LANGUAGE" == fa ]]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }
[[ $EUID == 0 ]] || { say 'Run this installer with sudo.' 'نصب‌کننده را با sudo اجرا کنید.'; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || { say 'Ubuntu 24.04 LTS is required.' 'اوبونتو ۲۴٫۰۴ لازم است.'; exit 1; }
case "$(uname -m)" in x86_64) ARCH=amd64; NODE_ARCH=x64; XRAY_ARCH=64 ;; aarch64) ARCH=arm64; NODE_ARCH=arm64; XRAY_ARCH=arm64-v8a ;; *) exit 1 ;; esac
if [[ -e /var/lib/separ/panel.db && $UPGRADE != 1 ]]; then
 say 'An existing panel was found. Back up first, then pass --upgrade.' 'پنل قبلاً نصب شده است؛ پس از پشتیبان‌گیری از --upgrade استفاده کنید.';exit 1
fi
if [[ ! -e /var/lib/separ/panel.db ]] && { command -v xray >/dev/null || [[ -e /etc/openvpn/server/amazon.conf ]] || [[ -e /etc/swanctl/conf.d/separ.conf ]]; }; then
 say 'Existing VPN configuration detected. Use a fresh server; this installer does not overwrite unrelated VPN installations.' 'تنظیمات VPN دیگری پیدا شد؛ نصب خودکار را روی سرور تازه اجرا کنید.';exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y ca-certificates curl unzip xz-utils tar python3 python3-venv openvpn easy-rsa charon-systemd strongswan-swanctl libcharon-extra-plugins libstrongswan-extra-plugins nginx iptables
SERVER_IP=${SERVER_IP:-$(curl -4fsS --max-time 15 https://api.ipify.org)}
python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); assert a.is_global' "$SERVER_IP"
TASK_TMP=$(mktemp -d /tmp/sirgsm-install.XXXXXXXX)
trap 'rm -rf -- "$TASK_TMP"' EXIT
if [[ -e /var/lib/separ/panel.db ]]; then
 install -d -m 700 /var/backups/sirgsm
 BACKUP="/var/backups/sirgsm/$(date -u +%Y%m%d-%H%M%S).tar.gz"
 # Backups include secrets. They are root-only and never stored in the source checkout.
 BACKUP_PATHS=()
 for path in opt/separ etc/separ etc/openvpn etc/swanctl usr/local/etc/xray var/lib/separ var/lib/separ-exports; do
  [[ ! -e "/$path" ]] || BACKUP_PATHS+=("$path")
 done
 tar -czf "$BACKUP" -C / "${BACKUP_PATHS[@]}"
 chmod 600 "$BACKUP"
 say "Backup: $BACKUP" "نسخهٔ پشتیبان: $BACKUP"
fi
if [[ -n "${SIRGSM_SOURCE_DIR:-}" ]]; then
 SOURCE=$(realpath -- "$SIRGSM_SOURCE_DIR")
 [[ -f "$SOURCE/deploy/configure.py" && -f "$SOURCE/frontend/package-lock.json" ]] || exit 1
else
 curl -fL --retry 3 "https://codeload.github.com/navidhaghpanah/sirgsm-vpn-panel-2/tar.gz/refs/tags/$RELEASE" -o "$TASK_TMP/source.tar.gz"
 tar -xzf "$TASK_TMP/source.tar.gz" -C "$TASK_TMP"
 SOURCE="$TASK_TMP/sirgsm-vpn-panel-2-${RELEASE#v}"
fi
say 'Building the interface…' 'در حال ساخت رابط کاربری…'
curl -fsSL --retry 3 https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt -o "$TASK_TMP/node-sha.txt"
NODE_TAR=$(awk -v arch="$NODE_ARCH" '$2 ~ "^node-v22\\.[0-9]+\\.[0-9]+-linux-" arch "\\.tar\\.xz$" {print $2; exit}' "$TASK_TMP/node-sha.txt")
[[ "$NODE_TAR" =~ ^node-v22\.[0-9]+\.[0-9]+-linux-(x64|arm64)\.tar\.xz$ ]] || exit 1
curl -fsSL --retry 3 "https://nodejs.org/dist/latest-v22.x/$NODE_TAR" -o "$TASK_TMP/$NODE_TAR"
(cd "$TASK_TMP"; awk -v file="$NODE_TAR" '$2==file' node-sha.txt | sha256sum -c -)
install -d -m 755 /opt/sirgsm-node
tar -xJf "$TASK_TMP/$NODE_TAR" --strip-components=1 -C /opt/sirgsm-node
export PATH="/opt/sirgsm-node/bin:$PATH"
(cd "$SOURCE/frontend"; npm ci --no-audit --no-fund; npm run build)
install -d -m 755 /opt/separ
cp -a "$SOURCE/backend" "$SOURCE/deploy" "$SOURCE/requirements.txt" /opt/separ/
install -d -m 755 /opt/separ/frontend
rm -rf -- /opt/separ/frontend/dist
cp -a "$SOURCE/frontend/dist" /opt/separ/frontend/
chown -R root:root /opt/separ
chmod -R go-w /opt/separ
find /opt/separ/frontend/dist -type d -exec chmod 755 {} +
find /opt/separ/frontend/dist -type f -exec chmod 644 {} +
find /opt/separ/backend -type d -exec chmod 755 {} +
find /opt/separ/backend -type f -name '*.py' -exec chmod 644 {} +
python3 -m venv /opt/sirgsm-runtime
/opt/sirgsm-runtime/bin/pip install -r /opt/separ/requirements.txt
python3 -m venv /opt/sirgsm-certbot
/opt/sirgsm-certbot/bin/pip install 'certbot==5.10.0'
if ! command -v xray >/dev/null; then
 XRAY_VERSION=v26.11.9
 curl -fL --retry 3 "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$XRAY_ARCH.zip" -o "$TASK_TMP/xray.zip"
 curl -fL --retry 3 "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$XRAY_ARCH.zip.dgst" -o "$TASK_TMP/xray.dgst"
 python3 /opt/separ/deploy/check_xray_digest.py "$TASK_TMP/xray.zip" "$TASK_TMP/xray.dgst"
 unzip -q "$TASK_TMP/xray.zip" -d "$TASK_TMP/xray"
 install -m 755 "$TASK_TMP/xray/xray" /usr/local/bin/xray
 install -d -m 755 /usr/local/share/xray /usr/local/etc/xray
 install -m 644 "$TASK_TMP/xray/geoip.dat" "$TASK_TMP/xray/geosite.dat" /usr/local/share/xray/
 getent passwd xray >/dev/null || useradd --system --home /var/lib/xray --shell /usr/sbin/nologin xray
 cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=SirGSM Xray core
After=network-online.target
[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
UMask=0077
Restart=always
RestartSec=2
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
fi
# MTProto is public/shared and intentionally independent of user quotas.
MTG_VERSION=2.3.0
MTG_TAR="mtg-$MTG_VERSION-linux-$ARCH.tar.gz"
curl -fL --retry 3 "https://github.com/9seconds/mtg/releases/download/v$MTG_VERSION/$MTG_TAR" -o "$TASK_TMP/$MTG_TAR"
curl -fL --retry 3 "https://github.com/9seconds/mtg/releases/download/v$MTG_VERSION/mtg-$MTG_VERSION-checksums.txt" -o "$TASK_TMP/mtg-checksums.txt"
(cd "$TASK_TMP"; awk -v file="$MTG_TAR" '$2==file' mtg-checksums.txt | sha256sum -c -)
mkdir "$TASK_TMP/mtg"
tar -xzf "$TASK_TMP/$MTG_TAR" -C "$TASK_TMP/mtg"
MTG_BIN=$(find "$TASK_TMP/mtg" -type f -name mtg -print -quit)
[[ -n "$MTG_BIN" ]] || exit 1
install -m 755 "$MTG_BIN" /usr/local/bin/mtg
if command -v ufw >/dev/null && ufw status | head -n1 | grep -q 'Status: active'; then
 for port in 80 443 8443 2053 2083 2087 2096 8388; do ufw allow "$port/tcp"; done
 for port in 500 4500 8388; do ufw allow "$port/udp"; done
fi
say 'Configuring VPN services and public IP certificate…' 'در حال تنظیم سرویس‌ها و گواهی معتبر IP…'
/opt/sirgsm-runtime/bin/python /opt/separ/deploy/configure.py --server-ip "$SERVER_IP"
say 'Ready. Credentials are in /root/sirgsm-admin.txt. Allow the documented ports in your cloud firewall.' 'آماده است. اطلاعات ورود در /root/sirgsm-admin.txt قرار دارد. پورت‌های مستندشده را در فایروال ابری باز کنید.'
