#!/usr/bin/env bash
# check-ips.sh — пакетная проверка IP/доменов/CIDR на блокировку через cheburcheck.ru
#
# Использование:
#   ./check-ips.sh -f ips.txt
#   ./check-ips.sh -f ips.txt -j 4 -r 3 -o ./report
#   cat ips.txt | ./check-ips.sh -
#
# Формат входного файла: по одному IP/домену/CIDR/AS на строку,
# "#" — комментарий, пустые строки игнорируются, дубли убираются.

set -euo pipefail

# ---------- настройки по умолчанию ----------
API_BASE="https://cheburcheck.ru/api/v1/check"
PROBE_API="https://cheburcheck.ru/api/v1/probe"
STATUS_API="https://cheburcheck.ru/api/v1/status"
INPUT=""
OUTDIR="."
JOBS=3                # параллельных запроса (не злоупотребляйте — это чужой сервис)
RETRIES=3             # попыток на один адрес при ошибке
TIMEOUT=15            # таймаут curl, сек
DELAY=0.3             # пауза каждой воркер-границы, сек (анти-флуд)
VERIFY=1              # проверок на один адрес (1 = один снимок; 2+ = повторная верификация)
PROBE=1               # динамическая проверка зондами ТСПУ — ПО УМОЛЧАНИЮ ВКЛЮЧЕНА (-p); отключить: --no-probe
PROBE_TIMEOUT=120     # сколько ждать ответы зондов, сек (при неполном ответе — reconnect)
CSV=1                 # писать results.csv
QUIET=0

# ---------- цвета (отключаются, если stdout не терминал) ----------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_CYN=$'\033[36m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_DIM=""; C_RST=""
fi

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \?//'
  cat <<EOF

Опции:
  -f FILE    файл со списком (или "-" = stdin). Обязательно (либо позиционный аргумент)
  -o DIR     каталог отчёта (по умолчанию: .)
  -j N       параллельных проверок (по умолчанию: $JOBS, максимум разумно 5)
  -r N       повторов при ошибке/429 (по умолчанию: $RETRIES)
  -t SEC     таймаут одного запроса (по умолчанию: $TIMEOUT)
  -d SEC     пауза между запросами внутри воркера (по умолчанию: $DELAY)
  -v N       проверок на адрес: N последовательных опросов того же адреса;
             при расхождении результатов статус UNSTABLE (по умолчанию: $VERIFY)
  -p         ДИНАМИЧЕСКАЯ проверка зондами ТСПУ (как на сайте) — ВКЛЮЧЕНА ПО
             УМОЛЧАНИЮ! Медленно: каждый адрес опрашивает сеть сканеров.
             Отключить: --no-probe
                --no-probe          отключить зонды (только списки РКН/CDN)
                --probe-timeout SEC сколько ждать ответы зондов (по умолчанию: $PROBE_TIMEOUT)
  -q         тихий режим (только итог)
  -h         эта справка

Файлы отчёта в -o:
  results.tsv   target<TAB>status<TAB>blocked<TAB>asn<TAB>org<TAB>cdn<TAB>subnets<TAB>detail
  results.csv   то же, с заголовком (если включён CSV)
  blocked.txt   только заблокированные
  clean.txt     только чистые
  errors.txt    ошибки проверки (можно перепроверить: ./check-ips.sh -f errors.txt)
EOF
}

# ---------- разбор аргументов ----------
# длинная опция --probe-timeout SEC обрабатывается до getopts и убирается из аргументов
ARGS=()
for a in "$@"; do
  case "$a" in
    --probe-timeout=*) PROBE_TIMEOUT="${a#*=}" ;;
    --no-probe)        PROBE=0 ;;
    --no-probe=*)      PROBE=0 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]}"
while getopts ":f:o:j:r:t:d:v:pqh" opt; do
  case "$opt" in
    f) INPUT="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    r) RETRIES="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    d) DELAY="$OPTARG" ;;
    v) VERIFY="$OPTARG" ;;
    p) PROBE=1 ;;
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    \?) echo "Неизвестная опция: -$OPTARG" >&2; usage; exit 2 ;;
    :)  echo "Опция -$OPTARG требует аргумент" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[[ -z "$INPUT" && $# -gt 0 ]] && INPUT="$1"
if [[ -z "$INPUT" ]]; then
  echo "Укажите файл: $0 -f ips.txt" >&2
  usage; exit 2
fi
[[ "$JOBS" -lt 1 ]] && JOBS=1
[[ "$JOBS" -gt 8 ]] && JOBS=8
[[ "$VERIFY" -lt 1 ]] && VERIFY=1

# ---------- зависимости ----------
command -v curl >/dev/null || { echo "нужен curl" >&2; exit 1; }
HAVE_JQ=0; command -v jq >/dev/null && HAVE_JQ=1
HAVE_PY=0; command -v python3 >/dev/null && HAVE_PY=1
if [[ $HAVE_JQ -eq 0 && $HAVE_PY -eq 0 ]]; then
  echo "нужен jq или python3 для разбора JSON" >&2; exit 1
fi

# ---------- чтение и нормализация списка ----------
if [[ "$INPUT" == "-" ]]; then
  RAW=$(cat)
else
  [[ -f "$INPUT" ]] || { echo "Файл не найден: $INPUT" >&2; exit 2; }
  RAW=$(cat "$INPUT")
fi

TARGETS=$(printf '%s\n' "$RAW" \
  | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
  | grep -E . || true)
# дедупликация, сохраняя порядок
TARGETS=$(printf '%s\n' "$TARGETS" | awk '!seen[$0]++')

TOTAL=$(printf '%s\n' "$TARGETS" | grep -c . || true)
if [[ "$TOTAL" -eq 0 ]]; then
  echo "Пустой список." >&2; exit 2
fi

# ---------- свежесть базы cheburcheck ----------
DB_UPDATE=""; DB_DOMAINS=""; DB_V4=""
DB_JSON=$(curl -sS --max-time "$TIMEOUT" -H 'Accept: application/json' "$STATUS_API" 2>/dev/null || true)
if [[ -n "$DB_JSON" ]]; then
  if [[ $HAVE_JQ -eq 1 ]]; then
    DB_UPDATE=$(printf '%s' "$DB_JSON" | jq -r '.last_update // empty' 2>/dev/null || true)
    DB_DOMAINS=$(printf '%s' "$DB_JSON" | jq -r '.domain_count // empty' 2>/dev/null || true)
    DB_V4=$(printf '%s' "$DB_JSON" | jq -r '.v4_count // empty' 2>/dev/null || true)
  else
    DB_UPDATE=$(printf '%s' "$DB_JSON" | python3 -c 'import sys,json;
d=json.load(sys.stdin); print(d.get("last_update") or "")' 2>/dev/null || true)
  fi
  DB_AGE_H="?"
  if [[ -n "$DB_UPDATE" ]]; then
    TS=$(date -u +%s); UPS=$(date -u -d "$DB_UPDATE" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%S' "${DB_UPDATE%%.*}" +%s 2>/dev/null || echo 0)
    [[ "$UPS" -gt 0 ]] && DB_AGE_H=$(( (TS - UPS) / 3600 ))
  fi
fi

mkdir -p "$OUTDIR"
TSV="$OUTDIR/results.tsv"
CSV_FILE="$OUTDIR/results.csv"
BLOCKED_F="$OUTDIR/blocked.txt"
CLEAN_F="$OUTDIR/clean.txt"
ERRORS_F="$OUTDIR/errors.txt"
UNSTABLE_F="$OUTDIR/unstable.txt"
: > "$TSV"; : > "$BLOCKED_F"; : > "$CLEAN_F"; : > "$ERRORS_F"; : > "$UNSTABLE_F"
if [[ $CSV -eq 1 ]]; then
  printf 'target,status,blocked,asn,organisation,cdn,blocked_subnets,detail\n' > "$CSV_FILE"
fi

# ---------- разбор JSON ответа → TSV-строка ----------
# вход: $1 = target, stdin = JSON (или мусор при ошибке)
# выход: target \t status \t blocked \t asn \t org \t cdn \t subnets \t detail
parse_json() {
  local target="$1" body
  body=$(cat)
  if [[ $HAVE_JQ -eq 1 ]]; then
    printf '%s' "$body" | jq -r --arg t "$target" '
      def s: if . == null then "" else tostring end;
      [
        $t,
        (if .blocked == true then "BLOCKED" elif .blocked == false then "CLEAN" else "ERROR" end),
        ((.blocked // false) | tostring),
        ((.geo.asn // "") | s),
        ((.geo.organisation // "") | s),
        ((.cdn_providers // {}) | keys | join(",")),
        ((.blocked_subnets // []) | join(",")),
        ([(.rkn_domain // empty), (.target_type // empty),
          (if (.whitelist != null) then "whitelist" else empty end)] | join(";"))
      ] | @tsv' 2>/dev/null \
    || printf '%s\tERROR\t\t\t\t\t\tbad_json\n' "$target"
  else
    printf '%s' "$body" | python3 -c '
import sys, json, csv
t = sys.argv[1]
try:
    d = json.load(sys.stdin)
except Exception:
    print(f"{t}\tERROR\t\t\t\t\t\tbad_json", sep="\t")
    sys.exit(0)
blocked = d.get("blocked")
status = "BLOCKED" if blocked is True else ("CLEAN" if blocked is False else "ERROR")
geo = d.get("geo") or {}
cdn = ",".join((d.get("cdn_providers") or {}).keys())
sub = ",".join(d.get("blocked_subnets") or [])
detail = ";".join(x for x in [d.get("rkn_domain") or "", d.get("target_type") or "",
                               "whitelist" if d.get("whitelist") else ""] if x)
row = [t, status, str(blocked if blocked is not None else "").lower(),
       str(geo.get("asn") or ""), str(geo.get("organisation") or ""), cdn, sub, detail]
sys.stdout.write("\t".join(row) + "\n")
' "$target" 2>/dev/null \
    || printf '%s\tERROR\t\t\t\t\t\tbad_json\n' "$target"
  fi
}

# CSV-экранирование TSV-строки
tsv_to_csv() {
  awk -F'\t' '{
    for (i=1; i<=NF; i++) {
      gsub(/"/, "\"\"", $i)
      printf "%s\"%s\"", (i>1 ? "," : ""), $i
    }
    printf "\n"
  }'
}

# ---------- один HTTP-опрос адреса (с ретраями) ----------
# stdout: валидный JSON тела ответа, либо "" при неудаче
poll_target() {
  local target="$1" attempt=1 max=$RETRIES code="" body="" json="" sleep_s
  while [[ $attempt -le $max ]]; do
    body=$(curl -sS --max-time "$TIMEOUT" \
              -H 'Accept: application/json' \
              -H 'User-Agent: check-ips.sh/1.0' \
              -w '\n%{http_code}' \
              --get --data-urlencode "target=$target" \
              "$API_BASE" 2>/dev/null) || body=""
    code=$(printf '%s' "$body" | tail -n1)
    json=$(printf '%s' "$body" | sed '$d')

    if [[ "$code" == "200" && -n "$json" ]]; then
      printf '%s' "$json"
      return 0
    fi

    # ошибки, при которых есть смысл повторить
    if [[ "$code" == "429" || "$code" == "503" || "$code" == "502" || "$code" == "500" || -z "$code" ]]; then
      sleep_s=$(( attempt * 2 ))
      sleep "$sleep_s"
      attempt=$(( attempt + 1 ))
      continue
    fi

    # 4xx (кроме 429) — не повторяем
    return 1
  done
  return 1
}

# извлечь флаг "blocked" из JSON: true / false / "" (неизвестно)
blocked_of() {
  local json="$1"
  if [[ -z "$json" ]]; then echo ""; return 0; fi
  if [[ $HAVE_JQ -eq 1 ]]; then
    printf '%s' "$json" | jq -r 'if .blocked == true then "true" elif .blocked == false then "false" else "" end' 2>/dev/null || echo ""
  else
    printf '%s' "$json" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin)
  print("true" if d.get("blocked") is True else ("false" if d.get("blocked") is False else ""))
except Exception: print("")' 2>/dev/null || echo ""
  fi
}

# извлечь id сохранённого запроса (нужен для динамической проверки)
id_of() {
  local json="$1"
  [[ -z "$json" ]] && { echo ""; return 0; }
  if [[ $HAVE_JQ -eq 1 ]]; then
    printf '%s' "$json" | jq -r 'if .id == null then "" else .id end' 2>/dev/null || echo ""
  else
    printf '%s' "$json" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("id") or "")
except Exception: print("")' 2>/dev/null || echo ""
  fi
}

# ---------- динамическая проверка зондами (SSE /api/v1/probe/<id>) ----------
# подключается к потоку, ждёт ответы сканеров, при «тишине» переподключается
# с возрастающей паузой (лимиты сервиса). Отдаёт сводку:
#  verdict=<число>;...|votes=<N>|online=<M>
run_probe() {
  local id="$1" tmp tries=0 max_tries=4
  [[ -z "$id" ]] && { echo ""; return 0; }
  tmp=$(mktemp "${RESULTS_DIR}/probe.XXXXXX")
  while [[ $tries -lt $max_tries ]]; do
    curl -sSN --max-time "$PROBE_TIMEOUT" \
         -H 'Accept: text/event-stream' \
         -H 'User-Agent: check-ips.sh/2.0 probe' \
         -- "$PROBE_API/$id" > "$tmp" 2>/dev/null
    # успех: сервер прислал финальный done ИЛИ хотя бы какие-то вердикты
    if grep -q 'event:result' "$tmp" 2>/dev/null; then
      break
    fi
    # тишина (лимит/очередь/обрыв) — переподключаемся к тому же id после паузы
    tries=$((tries + 1))
    [[ $tries -lt $max_tries ]] && sleep $(( tries * 5 ))
  done
  # подсчёт вердиктов по строкам data: (малыми порциями, чтобы не съесть память)
  awk '/^data:/{ a=substr($0,6); if (index(a,"verdicts")>0) print a }' "$tmp" \
    | python3 -c '
import sys, json, collections
c = collections.Counter(); votes = 0; online = 0
for line in sys.stdin:
    try: d = json.loads(line)
    except Exception: continue
    votes += 1
    for v in set(d.get("verdicts") or []): c[v] += 1
    if d.get("online_probes"): online = d["online_probes"]
out = "verdict=" + ";".join(f"{k}={v}" for k, v in c.items())
print(out + "|votes=%d|online=%d" % (votes, online))
' 2>/dev/null || echo ""
  rm -f "$tmp"
}

# принять решение по сводке зондов: blocked:<тип> / clean / whitelist / nodata
# БИНАРНО: любой блокирующий вердикт = blocked (как решает сайт); иначе clean.
# nodata — зонды вообще не ответили (решает список).
probe_verdict() {
  local raw="$1"
  [[ -z "$raw" ]] && { echo "nodata"; return 0; }
  local verdicts=${raw%%|*}
  local tspu=0 sni=0 spoof=0 wl=0 ok=0 n
  local k
  for k in tspu_block sni_block dns_spoofing whitelist ok; do
    n=$(printf '%s' "$verdicts" | sed -n "s/.*[;=]${k}=\([0-9][0-9]*\).*/\1/p")
    [[ -n "$n" ]] || n=0
    case "$k" in
      tspu_block)   tspu=$n ;;
      sni_block)    sni=$n ;;
      dns_spoofing) spoof=$n ;;
      whitelist)    wl=$n ;;
      ok)           ok=$n ;;
    esac
  done
  local blocked=$((tspu + sni + spoof))
  local total_def=$((tspu + sni + spoof + wl + ok))
  if [[ "$blocked" -gt 0 ]]; then
    # любой блокирующий вердикт — адрес не открывается (совпадает с сайтом)
    if   [[ "$tspu" -gt 0 ]]; then echo "blocked:tspu_block"
    elif [[ "$sni"  -gt 0 ]]; then echo "blocked:sni_block"
    else echo "blocked:dns_spoofing"; fi
  elif [[ "$total_def" -eq 0 ]]; then
    echo "nodata"
  elif [[ "$wl" -gt 0 && "$wl" -ge "$ok" ]]; then
    echo "whitelist"
  else
    echo "clean"
  fi
}

# ---------- зонды: вторая фаза (вызывается ПОСЛЕДОВАТЕЛЬНО!) ----------
# вход: строка списка (8 колонок) + id сохранённого запроса
# выход: строка с окончательным бинарным статусом (CLEAN/BLOCKED)
apply_probe() {
  local row="$1" id="$2" tries=0 psum votes pver rest probe_note
  [[ -z "$id" ]] && { printf '%s\n' "$row"; return 0; }
  while [[ $tries -lt 2 ]]; do
    psum=$(run_probe "$id" || true)
    votes=${psum#*|votes=}; votes=${votes%%|*}; votes=${votes:-0}
    pver=$(probe_verdict "$psum" || true)
    case "$pver" in
      blocked:*)
        # зонды реально обнаружили блокировку — итог BLOCKED (сильнее списков)
        rest=${pver#blocked:}
        probe_note="probe:${rest};votes=${votes};$(printf '%s' "$psum" | sed 's/|votes=.*//;s/verdict=/pv=/')"
        row=$(printf '%s' "$row" \
          | awk -F'\t' -v n="$probe_note" 'BEGIN{OFS="\t"}
              { $2="BLOCKED"; $3="true"; if ($8=="") $8=n; else $8=$8";"n; print }')
        printf '%s\n' "$row"
        return 0
        ;;
      clean|whitelist)
        probe_note="probe:ok;votes=${votes}"
        row=$(printf '%s' "$row" \
          | awk -F'\t' -v n="$probe_note" 'BEGIN{OFS="\t"}
              { if ($8=="") $8=n; else $8=$8";"n; print }')
        printf '%s\n' "$row"
        return 0
        ;;
      *)
        # nodata: зонды молчат — свежий id запроса и ещё одна попытка,
        # затем финальный вердикт выносит список (100% CLEAN/BLOCKED)
        tries=$((tries + 1))
        if [[ $tries -eq 1 ]]; then
          sleep 5
          id=$(id_of "$(poll_target "$(printf '%s' "$row" | cut -f1)" || true)")
          continue
        fi
        row=$(printf '%s' "$row" \
          | awk -F'\t' -v n="probe:no_response" 'BEGIN{OFS="\t"}
              { if ($8=="") $8=n; else $8=$8";"n; print }')
        printf '%s\n' "$row"
        return 0
        ;;
    esac
  done
  printf '%s\n' "$row"
}

# ---------- проверка адреса с верификацией (VERIFY опросов) ----------
check_one() {
  local target="$1" first_json="" blocked_c=0 clean_c=0 bad_c=0 i json b row
  for (( i=1; i<=VERIFY; i++ )); do
    json=$(poll_target "$target" || true)
    b=$(blocked_of "$json")
    case "$b" in
      true)  blocked_c=$((blocked_c + 1)) ;;
      false) clean_c=$((clean_c + 1)) ;;
      *)     bad_c=$((bad_c + 1)) ;;
    esac
    [[ -z "$first_json" && -n "$json" ]] && first_json="$json"
    # пауза между опросами того же адреса
    if [[ $i -lt $VERIFY && "$DELAY" != "0" ]]; then
      sleep "$DELAY"
    fi
  done

  if [[ -z "$first_json" ]]; then
    printf '%s\tERROR\t\t\t\t\t\tall_checks_failed\n' "$target"
    return 0
  fi

  row=$(printf '%s' "$first_json" | parse_json "$target")

  # итоговый статус по совокупности опросов
  if [[ $bad_c -gt 0 && $blocked_c -eq 0 && $clean_c -eq 0 ]]; then
    # все опросы упали, но первый JSON всё же был — помечаем как ошибку
    printf '%s\tERROR\t\t\t\t\t\tall_checks_failed\n' "$target"
    return 0
  fi

  local st pollnote="" probe_note="" bl
  if [[ "$blocked_c" -gt 0 && "$clean_c" -eq 0 ]]; then
    st="BLOCKED"
  elif [[ "$clean_c" -gt 0 && "$blocked_c" -eq 0 ]]; then
    st="CLEAN"
  else
    st="UNSTABLE"
  fi

  if [[ "$VERIFY" -gt 1 ]]; then
    pollnote="verify:P=${VERIFY};B=${blocked_c};C=${clean_c};E=${bad_c}"
  fi

  # ---------- финальная строка TSV ----------
  # применить итоговый статус к колонке 2, признак блокировки к колонке 3,
  # добавить pollnote в detail (колонка 8); при зондах id сохранённого
  # запроса кладётся 9-й колонкой для второй (последовательной) фазы
  if [[ "$st" == "BLOCKED" || "$st" == "UNSTABLE" ]]; then bl="true"; else bl="false"; fi
  if [[ $PROBE -eq 1 ]]; then
    printf '%s' "$row" \
      | awk -F'\t' -v st="$st" -v bl="$bl" -v p1="$pollnote" -v id="$(id_of "$first_json")" \
            'BEGIN{OFS="\t"}
             { $2=st; $3=bl
               if (p1 != "") { if ($8=="") $8=p1; else $8=$8";"p1 }
               printf "%s\t%s\n", $0, id }'
  else
    printf '%s' "$row" \
      | awk -F'\t' -v st="$st" -v bl="$bl" -v p1="$pollnote" 'BEGIN{OFS="\t"}
             { $2=st; $3=bl
               if (p1 != "") { if ($8=="") $8=p1; else $8=$8";"p1 }
               print }'
  fi
}

# ---------- обёртка для xargs: читает строки, пишет результаты ----------
worker() {
  local target="$1" res
  res=$(check_one "$target")
  printf '%s\n' "$res" >> "$RESULTS_DIR/parts.log"
  # при включённых зондах построчный вывод делает ВТОРАЯ фаза (после зондов),
  # чтобы не показывать промежуточный статус по спискам
  if [[ $QUIET -eq 0 && $PROBE -eq 0 ]]; then
    local st
    st=$(printf '%s' "$res" | cut -f2)
    case "$st" in
      BLOCKED) printf '%s%s%s %s\n' "$C_RED" "[BLOCKED]" "$C_RST" "$target" ;;
      CLEAN)   printf '%s%s%s %s\n' "$C_GRN" "[CLEAN]  " "$C_RST" "$target" ;;
      UNSTABLE) printf '%s%s%s %s\n' "$C_YEL" "[UNSTABLE]" "$C_RST" "$target" ;;
      *)       printf '%s%s%s %s\n' "$C_YEL" "[ERROR]  " "$C_RST" "$target" ;;
    esac
  fi
  sleep "$DELAY"
}
export -f worker check_one parse_json poll_target blocked_of id_of run_probe probe_verdict 2>/dev/null || true
export API_BASE PROBE_API RETRIES TIMEOUT DELAY VERIFY PROBE PROBE_TIMEOUT QUIET HAVE_JQ HAVE_PY
export C_RED C_GRN C_YEL C_RST
export RESULTS_DIR

RESULTS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/check-ips.XXXXXX")
trap 'rm -rf "$RESULTS_DIR"' EXIT
: > "$RESULTS_DIR/parts.log"

if [[ $PROBE -eq 1 ]]; then
  echo "${C_CYN}Этап 1 — списки (параллельно $JOBS); этап 2 — зонды ТСПУ (последовательно). Всего: $TOTAL...${C_RST}"
else
  echo "${C_CYN}Проверяю $TOTAL адресов (параллельность: $JOBS, повторы: $RETRIES, опросов на адрес: $VERIFY)...${C_RST}"
fi
if [[ -n "$DB_UPDATE" ]]; then
  echo "${C_DIM}База cheburcheck: обновлена $DB_UPDATE (~${DB_AGE_H} ч назад), доменов: ${DB_DOMAINS:-?}, IPv4: ${DB_V4:-?}${C_RST}"
  if [[ "$DB_AGE_H" != "?" && "$DB_AGE_H" -gt 24 ]]; then
    echo "${C_YEL}ВНИМАНИЕ: списки не обновлялись более суток — результаты могут быть устаревшими.${C_RST}"
  fi
fi

# xargs -P: параллельно, по одной строке
printf '%s\n' "$TARGETS" \
  | xargs -P "$JOBS" -I{} -n1 bash -c 'worker "$@"' _ {}

# ---------- сбор и сортировка результатов ----------
# parts.log мог прийти не по порядку — восстановим порядок входного списка.
# При зондах здесь же выполняется ВТОРАЯ (последовательная) фаза проверки.
: > "$TSV"
i=0
while IFS= read -r t; do
  i=$((i + 1))
  line=$(awk -F'\t' -v t="$t" '$1 == t { print; exit }' "$RESULTS_DIR/parts.log")
  if [[ -z "$line" ]]; then
    row=$(printf '%s\tERROR\t\t\t\t\t\tmissing_result' "$t")
    id=""
  else
    row=$(printf '%s\n' "$line" | cut -f1-8)
    id=$(printf '%s\n' "$line" | cut -f9)
  fi
  if [[ $PROBE -eq 1 && "$id" != "" ]]; then
    # прогресс только в интерактивном TTY и с очисткой строки, чтобы не слипалось
    if [[ $QUIET -eq 0 && -t 1 ]]; then
      printf '%s[зонды %d/%d] %s…%s\033[K\r' "$C_DIM" "$i" "$TOTAL" "$t" "$C_RST"
    fi
    row=$(apply_probe "$row" "$id")
    if [[ $QUIET -eq 0 ]]; then
      [[ -t 1 ]] && printf '\033[K\r'
      st=$(printf '%s' "$row" | cut -f2)
      case "$st" in
        BLOCKED) printf '%s%s%s %s\n' "$C_RED" "[BLOCKED]" "$C_RST" "$t" ;;
        CLEAN)   printf '%s%s%s %s\n' "$C_GRN" "[CLEAN]  " "$C_RST" "$t" ;;
        UNSTABLE) printf '%s%s%s %s\n' "$C_YEL" "[UNSTABLE]" "$C_RST" "$t" ;;
        *)       printf '%s%s%s %s\n' "$C_YEL" "[ERROR]  " "$C_RST" "$t" ;;
      esac
    fi
  fi
  printf '%s\n' "$row" >> "$TSV"
done <<< "$TARGETS"

cut -f1,2 "$TSV" | awk -F'\t' '$2=="BLOCKED"{print $1}' > "$BLOCKED_F"
cut -f1,2 "$TSV" | awk -F'\t' '$2=="CLEAN"{print $1}'   > "$CLEAN_F"
cut -f1,2 "$TSV" | awk -F'\t' '$2=="ERROR"{print $1}'   > "$ERRORS_F"
cut -f1,2 "$TSV" | awk -F'\t' '$2=="UNSTABLE"{print $1}' > "$UNSTABLE_F"
# нестабильные (были оба исхода) также попадают в blocked.txt как «требует внимания»
cat "$UNSTABLE_F" >> "$BLOCKED_F"

if [[ $CSV -eq 1 ]]; then
  tail -n +1 "$TSV" | tsv_to_csv >> "$CSV_FILE"
fi

# ---------- итог ----------
n_blk=$(wc -l < "$BLOCKED_F" | tr -d ' ')
n_cln=$(wc -l < "$CLEAN_F"   | tr -d ' ')
n_err=$(wc -l < "$ERRORS_F"  | tr -d ' ')
n_uns=$(wc -l < "$UNSTABLE_F" | tr -d ' ')

echo
echo "${C_CYN}═══ ИТОГ ═══${C_RST}"
printf '  %sзаблокировано:%s %s\n' "$C_RED" "$C_RST" "$((n_blk - n_uns))"
[[ "$n_uns" -gt 0 ]] && printf '  %sнестабильно:%s   %s (проверить повторно)\n' "$C_YEL" "$C_RST" "$n_uns"
printf '  %sчисто:%s       %s\n'   "$C_GRN" "$C_RST" "$n_cln"
printf '  %sошибки:%s      %s\n'   "$C_YEL" "$C_RST" "$n_err"
echo
echo "Отчёт: $TSV"
[[ $CSV -eq 1 ]] && echo "CSV:   $CSV_FILE"
echo "Блок:  $BLOCKED_F"
echo "Чисто: $CLEAN_F"
[[ "$n_uns" -gt 0 ]] && echo "UNSTABLE: $UNSTABLE_F"
[[ "$n_err" -gt 0 ]] && echo "Ошибки (можно перепроверить): $ERRORS_F"

# код выхода: 1 = есть заблокированные, нестабильные или ошибки (удобно для CI)
[[ "$n_blk" -gt 0 || "$n_uns" -gt 0 || "$n_err" -gt 0 ]] && exit 1
exit 0
