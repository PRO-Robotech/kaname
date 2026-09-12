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

# Бюджет ожидания готовности службы — ЧИСЛОМ попыток по секунде. Ручка нужна
# самопроверке ниже: она доказывает исход «слушатель не появился», а шестьдесят
# секунд ожидания там были бы платой за уже известный ответ. Умолчание прежнее.
SERVICE_TRIES="${KANAME_STAND_SERVICE_TRIES:-60}"

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
  for i in $(seq 1 "$SERVICE_TRIES"); do
    alive=0; kill -0 "$(cat "$RUNDIR/kaname.pid")" 2>/dev/null && alive=1
    if [ "$alive" -eq 0 ]; then
      # ОТКАЗ СТАРТА — НАХОДКА, а не расписание: страж посадки назвал причину, и
      # эта причина есть утверждение о дереве.
      fail "служба не поднялась; последняя строка журнала:"
      tail -3 "$RUNDIR/kaname.log" >&2
      exit 1
    fi
    if listeners_up; then
      say "служба поднята: все $(ports_count) слушателей отвечают, попытка $i"
      return 0
    fi
    sleep 1
  done
  fail "служба жива, но за $SERVICE_TRIES с подняла не все слушатели"
  listeners_report >&2
  exit 1
}

# Порты собственных слушателей службы. Перечень — ручка, потому что самопроверка
# ниже подставляет свою пару: судить готовность на восьми боевых номерах значило бы
# мерить, свободны ли они на этой машине, а не различает ли скрипт исходы.
PORTS="${KANAME_STAND_PORTS:-9090 9091 9092 9095 9096 9097 9098 9099}"

# Счёт слушателей ВЫВОДИТСЯ из перечня: выписанное число разошлось бы с ним молча,
# и сообщение об успехе стало бы утверждать о стенде неправду.
ports_count() { set -- $PORTS; printf '%s' "$#"; }

# Закрывать fd 3 здесь НЕЧЕГО и НЕЛЬЗЯ, и второе важнее первого.
#
# Нечего: проба порта идёт в ПОДОБОЛОЧКЕ `( … )`, поэтому дескриптор закрывается
# вместе с ней, а в этой оболочке он не открывался ни разу.
#
# Нельзя: `exec` без команды применяет свои перенаправления к текущей оболочке
# НАВСЕГДА. Стоявший здесь `exec 3<&- 2>/dev/null` не закрывал дескриптор (его не
# было), а ГЛУШИЛ stderr всего скрипта — начиная с той секунды, когда ответил
# ПЕРВЫЙ слушатель. Дальше `fail`, `unmet`, `listeners_report >&2`, `tail … >&2` и
# `docker logs … >&2` уходили в пустоту.
#
# Цена измерена, и она ровно в том исходе, ради которого этот скрипт написан:
# «служба жива, но подняла не все слушатели» возвращало КОД 1 и НИ ОДНОГО СЛОВА о
# причине, а перечень портов с недостающим не печатался вовсе. Читатель получал
# находку о дереве без её предмета. Отказ до первого слушателя (страж посадки
# отверг старт) при этом печатался — там `|| return 1` срабатывал раньше, — поэтому
# дефект прятался ровно за той половиной, которая работала.
#
# Найдено самопроверкой этого файла (ось «слушатель не появился»): проба назвала
# код верным, а сообщение пустым. Чтением не находится — `2>/dev/null` на строке
# закрытия дескриптора выглядит подавлением жалобы самого закрытия.
listeners_up() {
  local p
  for p in $PORTS; do
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || return 1
  done
  return 0
}

listeners_report() {
  local p
  for p in $PORTS; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then printf '  :%s слушает\n' "$p"
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

# --- самопроверка: доказательство инъекцией в обе стороны ---------------------
#
# Живёт ФЛАГОМ этого же файла, а не соседним: отдельный файл в перечень шагов
# конвейера не попал бы сам, то есть не исполнялся бы никогда. Форма — та же, что
# у `gosec-gate.sh` и `classify-integration-outcome.sh`: подставной мир на пробу,
# ожидаемый код, законный близнец рядом с инъекцией, перепись в конце и код 2 на
# пустом обходе.
#
# ПРЕДМЕТ САМОПРОВЕРКИ — РАЗЛИЧЕНИЕ, А НЕ ПОДЪЁМ. Она не поднимает ни базы, ни
# службы и НЕ ТРЕБУЕТ docker: требуй она движка — молчала бы ровно на той машине,
# где её вердикт и нужен, то есть сама стала бы тем третьим исходом, который этот
# скрипт учит отличать. Подставной каталог инструментов существует затем, чтобы
# «средство есть» не зависело от того, стоит ли docker на машине: `need_tool`
# спрашивает НАЛИЧИЕ, и подложный файл отвечает на этот вопрос полностью.
#
# ПУТАНИЦА ЗДЕСЬ ДВУСТОРОННЯЯ, поэтому каждая проба утверждает КОД И ТЕКСТ сразу:
# 75, выданный за отказ стража посадки, ПРЯЧЕТ дефект — служба не поднялась, а
# прогон говорит «условие не создано» и никого не роняет; 1, выданный за чужую
# сеть, объявляет дефектом дерева расписание — и такое красное перестают читать.
# Отсюда запрет на слово-близнец: у исхода 75 в выводе не должно быть «НАХОДКА»,
# у исхода 1 — «УСЛОВИЕ НЕ СОЗДАНО». Кода без текста мало: перепутать классы можно
# и сохранив код.
if [ "${1:-}" = "--self-test" ]; then
    # Подставной слушатель — единственное, что самопроверке нужно извне. Требование
    # честное: тремя соседними самопроверками этого процесса python3 уже нужен, и
    # его отсутствие здесь — НЕ зелёное, а отсутствие доказательства.
    PY="$(command -v python3 2>/dev/null)"
    if [ -z "$PY" ]; then
        echo "ОТКАЗ: python3 недоступен — подставного слушателя не поднять." >&2
        echo "Ни одной пробы не исполнено, доказательства нет. Это не зелёное." >&2
        exit 2
    fi

    TMP="$(mktemp -d)"
    stop_fakes() {
        local f
        for f in "$TMP"/run-*/kaname.pid; do
            [ -f "$f" ] || continue
            kill "$(cat "$f")" 2>/dev/null
            rm -f "$f"
        done
        return 0
    }
    trap 'stop_fakes; rm -rf "$TMP"' EXIT

    # Порт освобождается АСИНХРОННО: следующая проба, взяв тот же номер слишком
    # рано, померила бы чужой — ещё живой — слушатель и позеленела бы не на своём.
    wait_port_free() {
        local port="$1" i
        for i in $(seq 1 100); do
            ( exec 3<>"/dev/tcp/127.0.0.1/$port" ) 2>/dev/null || return 0
            sleep 0.1
        done
        return 1
    }

    mkdir -p "$TMP/empty" "$TMP/toolbin" "$TMP/gobin-ok" "$TMP/gobin-fail" \
             "$TMP/mig-conn" "$TMP/mig-guard" "$TMP/mig-ok" "$TMP/build-bin" \
             "$TMP/svc-up" "$TMP/svc-guard" "$TMP/chain-ok" "$TMP/chain-guard"

    # Подложные средства подъёма: их НИКОГДА не исполняют, `need_tool` смотрит лишь
    # наличие. Поэтому ни один прогон самопроверки не трогает настоящий docker.
    printf '#!/bin/sh\nexit 0\n' > "$TMP/toolbin/docker"
    printf '#!/bin/sh\nexit 0\n' > "$TMP/toolbin/go"

    # Подложный `go`, который СОБИРАЕТ: понимает `build -o <путь>` и создаёт файл.
    cat > "$TMP/gobin-ok/go" <<'EOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift; fi
  shift
done
[ -n "$out" ] && { : > "$out"; chmod +x "$out"; }
exit 0
EOF
    # …и подложный `go`, который НЕ собирает. Один факт против близнеца выше.
    cat > "$TMP/gobin-fail/go" <<'EOF'
#!/bin/sh
echo 'internal/apps/kaname/api/x.go:12:5: undefined: Foo' >&2
exit 1
EOF

    # Накатчик, не дотянувшийся до базы: жалоба на СОЕДИНЕНИЕ.
    cat > "$TMP/mig-conn/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'dial tcp 127.0.0.1:15432: connect: connection refused' >&2
exit 1
EOF
    # Накатчик, отвергнутый ПРОВЕРКОЙ НАСТРОЕК: тот же ненулевой код, другой
    # адресат жалобы. Это и есть один факт, различающий 75 и 1 на этом месте.
    cat > "$TMP/mig-guard/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'config: authn.trusted-forwarder-sans must not be empty in production mode' >&2
exit 1
EOF
    cat > "$TMP/mig-ok/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'OK    0001_init.sql'
echo 'goose: no migrations to run'
exit 0
EOF
    cp "$TMP/mig-ok/kaname-migrator" "$TMP/chain-ok/kaname-migrator"
    cp "$TMP/mig-ok/kaname-migrator" "$TMP/chain-guard/kaname-migrator"

    # Подставная служба, ОТВЕРГНУТАЯ стражем посадки: называет причину и уходит.
    cat > "$TMP/svc-guard/kaname" <<'EOF'
#!/bin/sh
echo 'boot refused: authn.trusted-forwarder-sans (env KANAME_AUTHN__TRUSTED_FORWARDER_SANS) is empty' >&2
exit 1
EOF
    cp "$TMP/svc-guard/kaname" "$TMP/chain-guard/kaname"

    # Подставная служба, КОТОРАЯ ПОДНЯЛАСЬ: держит ровно те порты, что ей назвали.
    # Один и тот же файл служит и близнецом «все слушатели на месте», и инъекцией
    # «слушатель не появился» — различает их ТОЛЬКО перечень связываемых портов.
    cat > "$TMP/svc-up/kaname" <<PYEOF
#!$PY
import os
import socket
import time

ports = os.environ.get("SELFTEST_BIND_PORTS", "").split()
held = []
for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", int(port)))
    sock.listen(16)
    held.append(sock)
print("подставная служба слушает: " + " ".join(ports), flush=True)
while True:
    time.sleep(1)
PYEOF
    cp "$TMP/svc-up/kaname" "$TMP/chain-ok/kaname"

    chmod +x "$TMP/toolbin/docker" "$TMP/toolbin/go" "$TMP/gobin-ok/go" \
             "$TMP/gobin-fail/go" "$TMP/mig-conn/kaname-migrator" \
             "$TMP/mig-guard/kaname-migrator" "$TMP/mig-ok/kaname-migrator" \
             "$TMP/chain-ok/kaname-migrator" "$TMP/chain-guard/kaname-migrator" \
             "$TMP/svc-guard/kaname" "$TMP/chain-guard/kaname" \
             "$TMP/svc-up/kaname" "$TMP/chain-ok/kaname"

    # Порты берутся СВОБОДНЫМИ у ядра, а не выписываются: судить готовность на
    # восьми боевых номерах значило бы мерить, заняты ли они на этой машине.
    SELFTEST_FREE_PORTS="$("$PY" -c '
import socket
held = []
for _ in range(4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    held.append(sock)
print(" ".join(str(s.getsockname()[1]) for s in held))
')"
    read -r PORT_A PORT_B PORT_C PORT_D <<EOF
$SELFTEST_FREE_PORTS
EOF
    PAIR_SVC="$PORT_A $PORT_B"
    PAIR_CHAIN="$PORT_C $PORT_D"

    # ─── миры проб: каждый в СВОЁМ подоболочке, потому что различающие ветки
    # скрипта завершаются `exit`, и вызванные напрямую унесли бы саму самопроверку.
    world_docker_missing()  { ( PATH="$TMP/empty";   need_tool docker ); }
    world_docker_present()  { ( PATH="$TMP/toolbin"; need_tool docker ); }
    world_go_missing()      { ( PATH="$TMP/empty";   need_tool go ); }

    world_migrate_conn()    { ( BIN="$TMP/mig-conn";  migrate ); }
    world_migrate_guard()   { ( BIN="$TMP/mig-guard"; migrate ); }
    world_migrate_ok()      { ( BIN="$TMP/mig-ok";    migrate ); }

    world_build_no_go()     { ( PATH="$TMP/empty";               BIN="$TMP/build-bin"; build_binaries ); }
    world_build_fail()      { ( PATH="$TMP/gobin-fail:$PATH";    BIN="$TMP/build-bin"; build_binaries ); }
    world_build_ok()        { ( PATH="$TMP/gobin-ok:$PATH";      BIN="$TMP/build-bin"; build_binaries ); }

    world_service_up() {
        ( BIN="$TMP/svc-up"; RUNDIR="$TMP/run-svc"; PORTS="$PAIR_SVC"
          SERVICE_TRIES=20; export SELFTEST_BIND_PORTS="$PAIR_SVC"
          start_service )
    }
    world_service_partial() {
        ( BIN="$TMP/svc-up"; RUNDIR="$TMP/run-svc"; PORTS="$PAIR_SVC"
          SERVICE_TRIES=3;  export SELFTEST_BIND_PORTS="$PORT_A"
          start_service )
    }
    world_service_guard() {
        ( BIN="$TMP/svc-guard"; RUNDIR="$TMP/run-svc"; PORTS="$PAIR_SVC"
          SERVICE_TRIES=5;  export SELFTEST_BIND_PORTS=""
          start_service )
    }
    world_chain_up() {
        ( PATH="$TMP/toolbin:$PATH"; BIN="$TMP/chain-ok"; RUNDIR="$TMP/run-chain"
          PORTS="$PAIR_CHAIN"; SERVICE_TRIES=20
          export SELFTEST_BIND_PORTS="$PAIR_CHAIN"
          need_tool docker; need_tool go; migrate; start_service )
    }
    world_chain_guard() {
        ( PATH="$TMP/toolbin:$PATH"; BIN="$TMP/chain-guard"; RUNDIR="$TMP/run-chain"
          PORTS="$PAIR_CHAIN"; SERVICE_TRIES=5
          export SELFTEST_BIND_PORTS=""
          need_tool docker; need_tool go; migrate; start_service )
    }

    probes=0; failed=0; checks=0
    OUT="$TMP/out"

    # assert <ожидаемый-код> <имя> <мир> <обязательная|-> <обязательная|-> <запрещённая|->
    assert() {
        local want="$1" name="$2" world="$3" must_one="$4" must_two="$5" forbid="$6"
        local got=0 bad=""
        probes=$((probes + 1))
        : > "$OUT"
        "$world" > "$OUT" 2>&1 || got=$?
        checks=$((checks + 1))
        [ "$got" -eq "$want" ] || bad="ждали код $want, получили $got"
        local m
        for m in "$must_one" "$must_two"; do
            [ "$m" = "-" ] && continue
            checks=$((checks + 1))
            grep -qF -- "$m" "$OUT" || bad="${bad:+$bad; }вывод не называет «$m»"
        done
        if [ "$forbid" != "-" ]; then
            checks=$((checks + 1))
            if grep -qF -- "$forbid" "$OUT"; then
                bad="${bad:+$bad; }вывод несёт слово ДРУГОГО исхода «$forbid»"
            fi
        fi
        if [ -n "$bad" ]; then
            echo "  ПРОВАЛ $name — $bad" >&2
            sed 's/^/       | /' "$OUT" >&2
            failed=$((failed + 1))
            return 0
        fi
        echo "  ok   $name (код $got)"
    }

    echo "=== стенд: различение «условие не создано» (75) и «находка о дереве» (1) ==="

    echo "--- ось 1: средства подъёма нет — 75, и сообщение называет СРЕДСТВО"
    # (−) ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ первым: без него всё нижеследующее зеленело бы на
    # проверке, которая отвечает 75 всегда.
    assert 0  "(−) средство есть — 75 не выдаётся"                 world_docker_present "-" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) один факт против близнеца: того же средства на PATH нет.
    assert 75 "(+) docker недоступен — 75, названо средство"        world_docker_missing "инструмента нет: docker" "стенд не поднимался" "НАХОДКА"
    # (+) ДРУГОЕ средство обязано дать ДРУГОЕ имя: иначе «называет средство» было
    # бы неотличимо от постоянной строки.
    assert 75 "(+) иное средство — то же 75, но имя иное"           world_go_missing     "инструмента нет: go" "-" "НАХОДКА"

    echo "--- ось 2: накатчик отказал — адресат жалобы решает, условие это или находка"
    assert 0  "(−) накат прошёл — 0"                               world_migrate_ok     "миграции накачены" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    assert 75 "(+) жалоба на СОЕДИНЕНИЕ — 75, не дефект дерева"     world_migrate_conn   "накатчик не дотянулся до базы" "-" "НАХОДКА"
    assert 1  "(+) жалоба на НАСТРОЙКИ — 1, и причина названа"      world_migrate_guard  "накатчик отказал" "trusted-forwarder-sans" "УСЛОВИЕ НЕ СОЗДАНО"

    echo "--- ось 3: сборка — отсутствие средства и отказ сборки НЕ один исход"
    assert 0  "(−) сборка прошла — 0"                              world_build_ok       "собрано" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    assert 1  "(+) сборка отказала — 1, а не 75"                    world_build_fail     "сборка kaname не прошла" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    assert 75 "(+) средства сборки нет вовсе — 75, а не 1"          world_build_no_go    "инструмента нет: go" "-" "НАХОДКА"

    echo "--- ось 4: служба не поднялась — 1, и сказано ЧТО именно не сошлось"
    assert 0  "(−) все слушатели на месте — 0"                     world_service_up     "служба поднята" "все 2 слушателей отвечают" "УСЛОВИЕ НЕ СОЗДАНО"
    stop_fakes; wait_port_free "$PORT_A"; wait_port_free "$PORT_B"
    # (+) один факт против близнеца выше: тот же файл, те же порты, связан ТОЛЬКО
    # первый. Ожидание готовности не сходится — и это вердикт о дереве.
    assert 1  "(+) слушатель не появился — 1, назван недостающий"   world_service_partial "подняла не все слушатели" ":$PORT_B НЕ слушает" "УСЛОВИЕ НЕ СОЗДАНО"
    stop_fakes; wait_port_free "$PORT_A"
    # (+) другой факт: процесс ушёл сам, назвав причину. Она обязана доехать до
    # читателя дословно — «не смогли поднять» посылало бы его искать наугад.
    assert 1  "(+) страж посадки отказал — 1, причина дословно"     world_service_guard  "служба не поднялась" "KANAME_AUTHN__TRUSTED_FORWARDER_SANS" "УСЛОВИЕ НЕ СОЗДАНО"

    echo "--- ось 5: обратный контроль — в работающем мире 75 не выдаётся НИ ПРИ ЧЁМ"
    # Мир целиком: средства есть, накат прошёл, служба поднялась. Если бы 75 был
    # запасным исходом «что-то не вышло», он всплыл бы здесь.
    assert 0  "(−) средства есть и служба поднялась — 0, не 75"     world_chain_up       "миграции накачены" "служба поднята" "УСЛОВИЕ НЕ СОЗДАНО"
    stop_fakes; wait_port_free "$PORT_C"; wait_port_free "$PORT_D"
    # (+) тот же мир, один факт: служба отвергнута стражем. Средства на месте —
    # значит 75 здесь был бы маской настоящего отказа.
    assert 1  "(+) тот же мир, служба отвергнута — 1, а не 75"      world_chain_guard    "служба не поднялась" "KANAME_AUTHN__TRUSTED_FORWARDER_SANS" "УСЛОВИЕ НЕ СОЗДАНО"

    echo
    echo "stand-own --self-test: проб исполнено $probes, утверждений $checks, провалов $failed"
    [ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
    [ "$failed" -gt 0 ] && exit 1
    exit 0
fi

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
    printf 'использование: %s {up|env|down|--self-test}\n' "$0" >&2
    exit 2
    ;;
esac
