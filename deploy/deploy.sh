#!/bin/sh
set -eu

[ "$#" -eq 0 ] || { echo '用法：sudo sh deploy/deploy.sh' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo '请使用 sudo 或 root 执行。' >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo '自动安装支持 Ubuntu 22.04+/Debian 12+。其他系统可编译后使用 deploy/install.sh。' >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo '需要 systemd。' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) arch=amd64; checksum=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445 ;;
  aarch64|arm64) arch=arm64; checksum=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec ;;
  *) echo '只支持 x86_64 / arm64。' >&2; exit 1 ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl tar gzip coreutils passwd

# Isolate the toolchain instead of replacing the server's existing Go.
go_dir=/opt/anquan-tools/go1.27.1
if [ ! -x "$go_dir/bin/go" ]; then
  [ ! -e "$go_dir" ] || { echo "工具目录不完整，请检查：$go_dir" >&2; exit 1; }
  install -d -m 0755 /opt/anquan-tools
  stage=$(mktemp -d /opt/anquan-tools/.go-install.XXXXXX)
  trap 'rm -rf "$stage"' EXIT
  trap 'exit 130' HUP INT TERM
  curl -fL --retry 3 "https://go.dev/dl/go1.27.1.linux-$arch.tar.gz" -o "$stage/archive.tar.gz"
  printf '%s  %s\n' "$checksum" "$stage/archive.tar.gz" | sha256sum -c -
  tar -xzf "$stage/archive.tar.gz" -C "$stage" --strip-components=1
  rm "$stage/archive.tar.gz"
  mv "$stage" "$go_dir"
  trap - EXIT HUP INT TERM
fi
cd "$repo_dir"
mkdir -p dist
CGO_ENABLED=0 "$go_dir/bin/go" build -trimpath -ldflags='-s -w' -o "dist/anquan-master-linux-$arch" ./cmd/anquan-master
sh "$script_dir/install.sh" "$repo_dir/dist/anquan-master-linux-$arch"
attempt=0
until curl -fsS --max-time 3 http://127.0.0.1:10110/healthz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    journalctl -u anquan-master -n 40 --no-pager >&2
    echo '后端健康检查失败，请检查日志及 /etc/anquan-master.env。' >&2
    exit 1
  fi
  sleep 1
done
echo '后端部署成功：TCP 10110 / UDP 55555；数据库 /data/anquan/anquan.db'
