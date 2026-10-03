#!/bin/sh
set -eu

# Run from a downloaded source/release directory:
# sudo sh deploy/install.sh ./dist/anquan-master-linux-amd64
if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 或 sudo 执行安装。" >&2
  exit 1
fi
binary=${1:-./dist/anquan-master-linux-amd64}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -f "$binary" ]; then
  echo "找不到主控程序：$binary" >&2
  exit 1
fi
command -v systemctl >/dev/null 2>&1 || { echo '此脚本需要 systemd。' >&2; exit 1; }
if systemctl is-active --quiet anquan-master; then
  systemctl stop anquan-master
fi
if ! id anquan >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /data/anquan --shell /usr/sbin/nologin anquan
fi
install -d -m 0700 -o anquan -g anquan /data/anquan
for file in /data/anquan/anquan.db /data/anquan/anquan.db-wal /data/anquan/anquan.db-shm; do
  if [ -f "$file" ]; then
    chown anquan:anquan "$file"
    chmod 0600 "$file"
  fi
done
install -m 0755 "$binary" /usr/local/bin/anquan-master
install -m 0755 "$script_dir/reset-admin-password.sh" /usr/local/bin/anquan-reset-password
install -m 0644 "$script_dir/anquan-master.service" /etc/systemd/system/anquan-master.service
systemctl daemon-reload
systemctl enable anquan-master
systemctl restart anquan-master
echo '主控已安装：HTTP 10110 / UDP 55555，数据库目录 /data/anquan。'
echo '查看状态：systemctl status anquan-master'
echo '重置密码：sudo anquan-reset-password'
