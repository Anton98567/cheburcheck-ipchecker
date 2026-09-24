#!/usr/bin/env bash
# ipconv.sh — конвертер списка из формата «хост - IP: <адрес> - ...»
# в формат check-ips.sh: по одному IP на строку (+ хост комментарием).
#
# Вход (допускается несколько пар на одной строке):
#   vps-eu-01 - IP: 198.51.100.7 -
#   vps-az-05 - IP: 203.0.113.42 -
#   vps-eu-02 - IP: 198.51.100.9 - vps-az-01 - IP: 203.0.113.9 -
#
# Выход (удобно подавать прямо в check-ips.sh):
#   198.51.100.7	# vps-eu-01
#   203.0.113.42	# vps-az-05
#   ...

# Использование:
#   ./ipconv.sh input.txt > ips.txt
#   ./ipconv.sh < input.txt          # из stdin
#   cat list.txt | ./ipconv.sh -

set -euo pipefail

IN="${1:--}"
if [[ "$IN" == "-" ]]; then
  perl -ne '
    while (/([A-Za-z0-9_.-]+)\s*-\s*IP:\s*([0-9.]+)/g) {
      print "$2\t# $1\n";
    }'
else
  [[ -f "$IN" ]] || { echo "Файл не найден: $IN" >&2; exit 2; }
  perl -ne '
    while (/([A-Za-z0-9_.-]+)\s*-\s*IP:\s*([0-9.]+)/g) {
      print "$2\t# $1\n";
    }' < "$IN"
fi