#!/usr/bin/env bash
# ipconv2.sh — конвертер списка в формате:
#   [3] kvmfri - IP: 198.51.100.7/30 (0000-00-00) -  [m]
# в формат check-ips.sh: по одному IP на строку (+ хост комментарием).
# Префикс [N], дата в скобках и хвост [m] игнорируются; CIDR /N в поле IP:
# отбрасывается (как и в ipconv.sh, флаг --cidr сохраняет его). ГОЛЫЕ строки
# вида "198.51.100.0/24" или "1.2.3.4" проходят без изменений — так /24
# доезжает до check-ips.sh, который раскрывает его во все адреса.
#
# Выход (удобно подавать прямо в check-ips.sh):
#   198.51.100.7	# kvmfri
#   203.0.113.42	# kvmfrw
#   198.51.100.0/24
#   ...

# Использование:
#   ./ipconv2.sh input.txt > ips.txt
#   ./ipconv2.sh < input.txt          # из stdin
#   cat list.txt | ./ipconv2.sh -
#   ./ipconv2.sh --cidr input.txt     # сохранять /CIDR в target

set -euo pipefail

export LANG=C.UTF-8 LC_ALL=C.UTF-8 2>/dev/null || true

KEEP_CIDR=0
[[ "${1:-}" == "--cidr" ]] && { KEEP_CIDR=1; shift; }
IN="${1:--}"

if [[ "$KEEP_CIDR" -eq 1 ]]; then
  PERL='my $m=0; while (/([A-Za-z0-9_.-]+)\s*-\s*IP:\s*([0-9]+(?:\.[0-9]+){3}(?:\/[0-9]+)?)/g) { $m=1; print "$2\t# $1\n"; }
    if (!$m && /^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\/[0-9]+)?)\s*$/) { print "$1\n"; }'
else
  PERL='my $m=0; while (/([A-Za-z0-9_.-]+)\s*-\s*IP:\s*([0-9]+(?:\.[0-9]+){3})(?:\/[0-9]+)?/g) { $m=1; print "$2\t# $1\n"; }
    if (!$m && /^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\/[0-9]+)?)\s*$/) { print "$1\n"; }'
fi

run() { perl -ne "$PERL" < "$1"; }

if [[ "$IN" == "-" ]]; then
  run /dev/stdin
else
  [[ -f "$IN" ]] || { echo "Файл не найден: $IN" >&2; exit 2; }
  run "$IN"
fi