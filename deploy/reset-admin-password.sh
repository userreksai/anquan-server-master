#!/bin/sh
set -eu

# Password is read on the terminal without echo, or from stdin with --stdin.
# Docker: printf '%s\n' 'new-password' | docker compose exec -T master \
#   /app/anquan-master reset-admin --data-dir /data/anquan --password-stdin
binary=${ANQUAN_BIN:-/usr/local/bin/anquan-master}
data_dir=${ANQUAN_DATA_DIR:-/data/anquan}
if [ ! -x "$binary" ]; then
  echo "找不到可执行主控程序：$binary；可设置 ANQUAN_BIN。" >&2
  exit 1
fi
if [ ! -d "$data_dir" ]; then
  echo "数据库目录不存在：$data_dir；请确认 ANQUAN_DATA_DIR。" >&2
  exit 1
fi
case "${1:-}" in
  --stdin) IFS= read -r password || [ -n "${password:-}" ] ;;
  '')
    if [ ! -r /dev/tty ]; then
      echo '无交互终端，请通过标准输入并加 --stdin 传入新密码。' >&2
      exit 1
    fi
    tty_settings=$(stty -g </dev/tty)
    trap 'stty "$tty_settings" </dev/tty 2>/dev/null || true; unset password confirmation' EXIT
    trap 'exit 130' HUP INT TERM
    stty -echo </dev/tty
    printf 'admin 新密码：' >/dev/tty
    IFS= read -r password </dev/tty
    printf '\n再次输入：' >/dev/tty
    IFS= read -r confirmation </dev/tty
    printf '\n' >/dev/tty
    stty "$tty_settings" </dev/tty
    if [ "$password" != "$confirmation" ]; then
      echo '两次密码不一致，未做任何修改。' >&2
      exit 1
    fi
    ;;
  *) echo "用法：$0 [--stdin]" >&2; exit 1 ;;
esac
if [ -z "$password" ]; then
  echo '新密码不能为空。' >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ] && id anquan >/dev/null 2>&1 && [ "$(stat -c %U "$data_dir")" = anquan ]; then
  if command -v runuser >/dev/null 2>&1; then
    printf '%s\n' "$password" | runuser -u anquan -- "$binary" reset-admin --data-dir "$data_dir" --password-stdin
  elif command -v su-exec >/dev/null 2>&1; then
    printf '%s\n' "$password" | su-exec anquan:anquan "$binary" reset-admin --data-dir "$data_dir" --password-stdin
  else
    echo '无法切换到数据库所属账号，需要 runuser 或 su-exec。' >&2
    exit 1
  fi
else
  printf '%s\n' "$password" | "$binary" reset-admin --data-dir "$data_dir" --password-stdin
fi
unset password
echo 'admin 密码已重置，旧登录会话已失效。'
