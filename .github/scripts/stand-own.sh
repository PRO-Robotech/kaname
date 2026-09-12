#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

# stand-own.sh — АВТОНОМНЫЙ стенд службы: своя база и свой внутренний УЦ, и больше
# ничего. Ни края платформы, ни её сервисов, ни внешнего поставщика удостоверений.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЗАЧЕМ ОН ЕСТЬ
#
# Служба вынесена отдельным продуктом, и «поднимается сама» перестало быть
# следствием чего-либо: до этого скрипта подъём службы В ЭТОМ репозитории не
# проверялся ни одним прогоном — её поднимал только зонтичный чарт платформы, то
# есть вердикт о самостоятельности выносился по ЧУЖОМУ дереву.
#
# ─────────────────────────────────────────────────────────────────────────────
# ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ
#
#   0  — стенд поднят (для `up`) либо все свойства сошлись (для `assert`);
#   1  — НАХОДКА: служба отказалась стартовать по своей проверке посадки, либо
#        свойство не сошлось. Это вердикт о дереве;
#   75 — УСЛОВИЕ НЕ СОЗДАНО: нет docker, образ не скачался, порт занят, база не
#        поднялась. Вердикта о дереве нет НИ ОДНОГО, и подавать это красным значит
#        посылать читателя чинить то, чего не ломали.
#
# Различие несущее: отказ стража посадки — находка (ручку переименовали, требование
# добавили), а неподнявшийся Postgres — расписание. Перепутать их значит либо
# спрятать дефект, либо объявить дефектом чужую сеть.
#
# ─────────────────────────────────────────────────────────────────────────────
# ПОЧЕМУ POSTGRES ПОДНИМАЕТСЯ `docker run`, А НЕ `services:` КОНВЕЙЕРА
#
# Боевая посадка требует `sslmode=require` (страж отказывает на `disable`), значит
# базе нужен TLS, значит ей нужен КЛЮЧ, а Postgres отказывается стартовать, если
# ключ не принадлежит его пользователю: `private key file must be owned by the
# database user or root`. Смена владельца файла из шага конвейера невозможна без
# полномочий, а `services:` не даёт ни точки для подготовки, ни тома под контролем.
# Поэтому владельца меняет одноразовый контейнер (он идёт от root), и только после
# этого поднимается база. Это не обход посадки, а её цена.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

RC_UNMET=75

PG_NAME="${KANAME_STAND_PG_NAME:-kaname-stand-pg}"
PG_PORT="${KANAME_STAND_PG_PORT:-15432}"
PG_IMAGE="${KANAME_STAND_PG_IMAGE:-postgres:16-alpine}"
PKI="${KANAME_STAND_PKI:-$ROOT/.stand/pki}"
RUNDIR="${KANAME_STAND_RUNDIR:-$ROOT/.stand/run}"
BIN="${KANAME_STAND_BIN:-$ROOT/.stand/bin}"
HOSTNAME_FOR_TLS="${KANAME_STAND_HOST:-localhost}"

# Ключ обёртки подписных ключей ПОСТОЯНЕН на всё время стенда и лежит файлом:
# служба ОТКАЗЫВАЕТСЯ стартовать, если уже записанные подписные ключи им не
# открываются («пересоздали стенд» и «потеряли все подписи» иначе неотличимы).
# Случайный на каждый запуск процесса ломал бы второй же старт.
WRAPKEY_FILE="$RUNDIR/wrapping.key"

say()  { printf '%s\n' "$*"; }
fail() { printf 'НАХОДКА: %s\n' "$*" >&2; }
unmet() { printf 'УСЛОВИЕ НЕ СОЗДАНО: %s\n' "$*" >&2; }

need_tool() {
  command -v "$1" >/dev/null 2>&1 && return 0
  unmet "инструмента нет: $1 — стенд не поднимался, вердикта о дереве нет"
  exit "$RC_UNMET"
}

# ─── PKI: внутренний УЦ стенда ───────────────────────────────────────────────
#
# Сертификат несёт SPIFFE-имя в SAN, потому что служба сужает круг тех, кто вправе
# говорить за пользователя, ИМЕНАМИ SAN, и пустой круг ей запрещён стражем старта.
# То есть без SPIFFE-имени стенд не поднялся бы — это требование продукта, а не
# украшение сертификата.
make_pki() {
  mkdir -p "$PKI" || { unmet "каталог $PKI не создаётся"; exit "$RC_UNMET"; }
  if [ -f "$PKI/srv.crt" ] && [ -f "$PKI/ca.crt" ]; then
    say "PKI уже есть: $PKI"
    return 0
  fi
  cat > "$PKI/openssl.cnf" <<EOF
[req]
distinguished_name=dn
[dn]
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[v3_srv]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:$HOSTNAME_FOR_TLS,DNS:kaname,IP:127.0.0.1,URI:spiffe://kaname.local/ns/kaname/sa/kaname
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=kaname-stand-ca' \
    -config "$PKI/openssl.cnf" -extensions v3_ca \
    -keyout "$PKI/ca.key" -out "$PKI/ca.crt" >/dev/null 2>&1 || {
      unmet "внутренний УЦ стенда не выпустился (openssl)"; exit "$RC_UNMET"; }
  openssl req -newkey rsa:2048 -nodes -subj '/CN=kaname' \
    -keyout "$PKI/srv.key" -out "$PKI/srv.csr" >/dev/null 2>&1
  openssl x509 -req -in "$PKI/srv.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
    -days 2 -extfile "$PKI/openssl.cnf" -extensions v3_srv -out "$PKI/srv.crt" >/dev/null 2>&1 || {
      unmet "сертификат службы не выпустился"; exit "$RC_UNMET"; }
  cp "$PKI/srv.crt" "$PKI/pg.crt"; cp "$PKI/srv.key" "$PKI/pg.key"
  say "PKI выпущен: $PKI (УЦ + сертификат службы с SPIFFE-именем в SAN)"
}

# ─── База: TLS обязателен, иначе страж посадки откажет ───────────────────────
start_pg() {
  need_tool docker
  docker rm -f "$PG_NAME" >/dev/null 2>&1
  # Смена владельца ключа — одноразовым контейнером: см. врезку в шапке.
  docker run --rm -v "$PKI:/k" "$PG_IMAGE" \
    sh -c 'chown 70:70 /k/pg.key /k/pg.crt && chmod 600 /k/pg.key && chmod 644 /k/pg.crt' \
    >/dev/null 2>&1 || { unmet "владельца ключа базы сменить не удалось (образ $PG_IMAGE не скачался?)"; exit "$RC_UNMET"; }
  docker run -d --name "$PG_NAME" \
    -e POSTGRES_PASSWORD=stand -e POSTGRES_USER=kaname -e POSTGRES_DB=kaname \
    -p "$PG_PORT:5432" \
    -v "$PKI/pg.crt:/tls/server.crt:ro" -v "$PKI/pg.key:/tls/server.key:ro" \
    "$PG_IMAGE" -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key \
    >/dev/null 2>&1 || { unmet "Postgres не запустился (порт $PG_PORT занят?)"; exit "$RC_UNMET"; }
  local i
  for i in $(seq 1 60); do
    if docker exec "$PG_NAME" pg_isready -U kaname >/dev/null 2>&1; then
      say "база поднята и принимает соединения (шифрование включено), попытка $i"
      return 0
    fi
    sleep 1
  done
  unmet "база не ответила pg_isready за 60 с"
  docker logs "$PG_NAME" 2>&1 | tail -20 >&2
  exit "$RC_UNMET"
}

# ─── Посадка процесса: объявляется ЗДЕСЬ, а не догадывается ──────────────────
#
# Каждая ручка ниже — требование СТРАЖА ПОСАДКИ службы: без неё процесс
# отказывается стартовать и называет причину. Значит перечень не «настройки
# стенда», а измеренная цена боевой посадки, и он обязан меняться вместе с
# требованиями, а не жить своей жизнью.
stand_env() {
  mkdir -p "$RUNDIR"
  [ -f "$WRAPKEY_FILE" ] || openssl rand -hex 32 > "$WRAPKEY_FILE"
  export KANAME_DB_HOST=127.0.0.1 KANAME_DB_PORT="$PG_PORT"
  export KANAME_DB_USER=kaname KANAME_DB_NAME=kaname KANAME_DB_PASSWORD=stand
  export KANAME_DB_SSLMODE=require
  export KANAME_JWKS_ENC_KEY="$(cat "$WRAPKEY_FILE")"
  export KANAME_HOOK_TOKEN=stand-hook-secret-0123456789
  export KANAME_AUTHN__DOMAIN=kaname.local
  export KANAME_AUTHN__TRUST_DOMAIN=kaname.local
  export KANAME_AUTHN__TRUSTED_FORWARDER_SANS='spiffe://kaname.local/ns/kaname/sa/kaname'
  export KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE=registry.kaname.local
  export KANAME_OWN_CEILINGS__ACCOUNTS_PER_IDENTITY=3
  export KANAME_OWN_CEILINGS__CREDENTIALS_PER_USER=5
  export KANAME_OWN_CEILINGS__CREDENTIALS_PER_SERVICE_ACCOUNT=5
  # ПОЛОСА ЛИЧНОСТИ — `external`, И ЭТО ЗАМЕР, А НЕ ВЫБОР УДОБСТВА.
  #
  # Полоса `own` (внешнего поставщика нет вовсе) объявлена и управляется, но
  # СТАРТОВАТЬ на ней служба сегодня ОТКАЗЫВАЕТСЯ, и страж называет пять причин
  # сразу: не провязано хранилище способов входа человека, не провязано хранилище
  # его сессии, 323 записи каталога требуют уровней доверия, которых полоса не
  # предъявляет, композиционный корень по-прежнему строит дорогу к ВНЕШНЕМУ
  # поставщику, а публикатор несёт зеркало его набора ключей. Это состояние
  # продукта, а не стенда: подъём на `own` заводится своей задачей.
  #
  # Адреса поставщика объявлены и НЕДОСТИЖИМЫ намеренно: страж требует, чтобы их
  # НАЗВАЛИ (выведенный из домена адрес выглядел бы настроенным, никуда не ведя),
  # но соединения при старте не делает. Поэтому стенд поднимается без поставщика,
  # а пути, которым он нужен, отвечают ЧЕСТНЫМ отказом — это и проверяется.
  export KANAME_AUTHN__IDENTITY_PROVIDER=external
  export KANAME_HYDRA_ADMIN_URL=https://127.0.0.1:14445
  export KANAME_HYDRA_JWKS_URL=https://127.0.0.1:14444/.well-known/jwks.json
  export KANAME_HYDRA_TOKEN_URL=https://127.0.0.1:14444/oauth2/token
  export KANAME_HYDRA_ADMIN_CA_FILE="$PKI/ca.crt"
  export KANAME_HYDRA_JWKS_CA_FILE="$PKI/ca.crt"
  export KANAME_HYDRA_TOKEN_CA_FILE="$PKI/ca.crt"
  # Собственные REST-фронты — предмет автономности: только они принадлежат службе.
  export KANAME_API_SERVER__REST_ENDPOINT=0.0.0.0:9098
  export KANAME_API_SERVER__INTERNAL_REST_ENDPOINT=0.0.0.0:9099
  # Читатель предъявленного удостоверения и своя чеканка идут ПАРОЙ: страж
  # отказывает, если включён только один (читатель сверяет подписи по СВОЕМУ
  # реестру, а без чеканки реестра нет вовсе).
  export KANAME_AUTHN__PRESENTED_CREDENTIAL__ENABLED=true
  export KANAME_AUTHN__PRESENTED_CREDENTIAL__AUDIENCE=https://kaname.local
  export KANAME_AUTHN__PRESENTED_CREDENTIAL__REVOCATION_CACHE_TTL=30s
  export KANAME_AUTHN__TOKEN_SIGNING__ENABLED=true
  export KANAME_AUTHN__TOKEN_SIGNING__ISSUER=https://kaname.local
  export KANAME_AUTHN__TOKEN_SIGNING__ALGORITHM=RS256
  export KANAME_AUTHN__TOKEN_SIGNING__ALLOWED_ALGORITHMS=RS256
  local l u
  for l in INTERNAL INTERNALREST HOOKS METRICS PUBLIC REST JWKSPROXY REGISTRYTOKEN; do
    eval "export KANAME_${l}_SERVER_MTLS_ENABLE=true \
      KANAME_${l}_SERVER_MTLS_CERTFILE=$PKI/srv.crt \
      KANAME_${l}_SERVER_MTLS_KEYFILE=$PKI/srv.key \
      KANAME_${l}_SERVER_MTLS_CLIENTCAFILES=$PKI/ca.crt \
      KANAME_${l}_SERVER_MTLS_CLIENTAUTHMODE=mutual"
  done
  for u in REST_UPSTREAM INTERNALREST_UPSTREAM; do
    eval "export KANAME_${u}_MTLS_ENABLE=true \
      KANAME_${u}_MTLS_CERTFILE=$PKI/srv.crt \
      KANAME_${u}_MTLS_KEYFILE=$PKI/srv.key \
      KANAME_${u}_MTLS_CAFILES=$PKI/ca.crt \
      KANAME_${u}_MTLS_SERVERNAME=$HOSTNAME_FOR_TLS"
  done
}

build_binaries() {
  need_tool go
  mkdir -p "$BIN"
  go build -o "$BIN/kaname" ./cmd/kaname || { fail "сборка kaname не прошла"; exit 1; }
  go build -o "$BIN/kaname-migrator" ./cmd/migrator || { fail "сборка накатчика не прошла"; exit 1; }
  say "собрано: kaname, kaname-migrator"
}

migrate() {
  local out rc
  out="$("$BIN/kaname-migrator" up 2>&1)"; rc=$?
  printf '%s\n' "$out" | tail -3
  if [ "$rc" -ne 0 ]; then
    # Накатчик грузит ПОЛНЫЙ конфиг службы, поэтому его отказ бывает и находкой
    # (требование стража добавили), и несозданным условием (база не отвечает).
    # Различает адресат жалобы: строка подключения — условие, всё прочее — находка.
    if printf '%s' "$out" | grep -qiE 'connect|dial|refused|sslmode|password'; then
      unmet "накатчик не дотянулся до базы"; exit "$RC_UNMET"
    fi
    fail "накатчик отказал: $(printf '%s' "$out" | tail -1)"; exit 1
  fi
  say "миграции накачены"
}

start_service() {
  mkdir -p "$RUNDIR"
  nohup "$BIN/kaname" > "$RUNDIR/kaname.log" 2>&1 &
  echo $! > "$RUNDIR/kaname.pid"
  local i alive
  for i in $(seq 1 60); do
    alive=0; kill -0 "$(cat "$RUNDIR/kaname.pid")" 2>/dev/null && alive=1
    if [ "$alive" -eq 0 ]; then
      # ОТКАЗ СТАРТА — НАХОДКА, а не расписание: страж посадки назвал причину, и
      # эта причина есть утверждение о дереве.
      fail "служба не поднялась; последняя строка журнала:"
      tail -3 "$RUNDIR/kaname.log" >&2
      exit 1
    fi
    if listeners_up; then
      say "служба поднята: все восемь слушателей отвечают, попытка $i"
      return 0
    fi
    sleep 1
  done
  fail "служба жива, но за 60 с подняла не все слушатели"
  listeners_report >&2
  exit 1
}

PORTS="9090 9091 9092 9095 9096 9097 9098 9099"

listeners_up() {
  local p
  for p in $PORTS; do
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || return 1
    exec 3<&- 2>/dev/null
  done
  return 0
}

listeners_report() {
  local p
  for p in $PORTS; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then exec 3<&-; printf '  :%s слушает\n' "$p"
    else printf '  :%s НЕ слушает\n' "$p"; fi
  done
}

down() {
  if [ -f "$RUNDIR/kaname.pid" ]; then
    kill "$(cat "$RUNDIR/kaname.pid")" 2>/dev/null
    rm -f "$RUNDIR/kaname.pid"
  fi
  command -v docker >/dev/null 2>&1 && docker rm -f "$PG_NAME" >/dev/null 2>&1
  say "стенд снесён"
}

case "${1:-}" in
  up)
    say "===== автономный стенд службы: подъём ====="
    need_tool openssl
    make_pki; start_pg; stand_env; build_binaries; migrate; start_service
    say "===== стенд поднят: своя база + свой УЦ, без платформы и без поставщика ====="
    listeners_report
    exit 0
    ;;
  env)
    # Печать посадки для соседнего шага: он читает её `eval`-ом, а не повторяет.
    stand_env
    env | grep -E '^KANAME_' | sort
    exit 0
    ;;
  down) down; exit 0 ;;
  *)
    printf 'использование: %s {up|env|down}\n' "$0" >&2
    exit 2
    ;;
esac
