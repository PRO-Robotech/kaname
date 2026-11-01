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
# У НАКАТА КЛАСС НАЗЫВАЕТ САМ НАКАТ, тем же кодом 75: `cmd/migrator/main.go`
# судит цепочку отказа предикатом, которым решает, имеет ли смысл ждать базу.
# Этот скрипт код передаёт и текста отказа НЕ РАЗБИРАЕТ — разбор текста судил бы
# эхо ввода, потому что сообщения наката вкладывают в себя строку подключения.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЧЕГО ЭТОТ СТЕНД НЕ УТВЕРЖДАЕТ — И ГДЕ ЖИВЁТ ВТОРАЯ ПОЛОВИНА
#
# Он поднимает ПРОЦЕСС, а не ЧАРТ: helm и kind в нём нет, kubectl — лишь путь во
# внешний кластер (голый под, kaname#841). Вердикта об установке чарта он не даёт — ни зелёного,
# ни красного. Вторая половина предиката M11 («helm install + rollout-ready, не
# только helm template») живёт рядом: `.github/scripts/stand-chart.sh`.
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
# Бюджет ожидания готовности базы после возврата из свёртки (`db-unfold`) — тем же
# счётом попыток по секунде и по той же причине: самопроверке нужен короткий.
DB_READY_TRIES="${KANAME_STAND_DB_READY_TRIES:-60}"

# ─── СРОКИ КЕШЕЙ РУБЕЖА ПРЕДЪЯВИТЕЛЯ: посадка службы и волна свёртки базы ─────
#
# Рубеж предъявителя (`internal/presentedcred/reader.go`) держит два кеша, и оба
# окна НЕ скользящие: попадание запись не продлевает, окно начинается с ПРОМАХА
# (держит `TestKAN_REV_04_PresentationInsideTheWindowDoesNotExtendIt`). Волне
# свёртки базы (`failclosed-prepare` и `failclosed-judge` ниже) нужны оба кеша свежими на всё время её
# коллекции, поэтому она меряет тишину и окно этими величинами, а не литералом.
#
# REVOCATION_CACHE_TTL — ручка службы: ею же `stand_env` задаёт
# KANAME_AUTHN__PRESENTED_CREDENTIAL__REVOCATION_CACHE_TTL.
REVOCATION_CACHE_TTL=30s
# KEY_SET_TTL — срок снимка публикуемого набора ключей. Ручки у него нет: это
# константа читателя (`keySetTTL`), и строка ниже — её отражение для стенда.
# Расхождение роняет `TestStandKeySetTTLMirrorsTheReader`
# (`internal/presentedcred/standwave_test.go`), так что значение одно, хоть
# записано дважды. Форма — длительность Go (целые часы, минуты, секунды).
KEY_SET_TTL=30s
# Запас волны: тишина длиннее большего из сроков на столько, и столько же
# окна обязано остаться к началу коллекции.
WAVE_MARGIN_S=2

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

# Ключ БУТСТРАП-контура — тоже файл и тоже постоянен, и по той же причине: строка
# соответствия бутстрап-клиента заводится в базе ОДИН раз, открытой половиной
# этого ключа. Новый ключ на каждый запуск означал бы, что второй старт не
# признаёт запись первого, и отказ приходил бы не там, где причина.
BOOTSTRAP_KEY_FILE="$RUNDIR/bootstrap-sa.key"
SECOND_FACTOR_KEY_FILE="$RUNDIR/second-factor.key"

# ПРИЁМНИК ПИСЕМ СТЕНДА (`stand-mailbox.py`). С kaname#456 человек, чей адрес не
# подтверждён, дальше входа не проходит, а выдачи на него не действуют; посев
# заводит людей регистрацией и доводит их до подтверждённого адреса кодом из
# письма, которое служба сдала этому узлу. Узел — процесс машины на 127.0.0.1:
# служба идёт сетью машины, и лист у узла тот же, что у базы, — лист службы
# (`localhost` в SAN, тот же УЦ).
MAIL_SMTP_PORT="${KANAME_STAND_MAIL_SMTP_PORT:-14465}"
MAIL_HTTP_PORT="${KANAME_STAND_MAIL_HTTP_PORT:-18025}"

# SPIFFE-имя, которым стенд зовёт чеканку бутстрап-удостоверения. Это ТО ЖЕ имя,
# что стоит в SAN сертификата стенда (см. make_pki): круг вызывающих у чеканки
# задаётся ИМЕНАМИ, а не сетевым положением, поэтому «кто вправе» на этом стенде
# выражено ровно одним значением и оно здесь одно.
BOOTSTRAP_CALLER_SAN="${KANAME_STAND_BOOTSTRAP_SAN:-spiffe://kaname.local/ns/kaname/sa/kaname}"

# Имя края в SAN листа, которым посев стоит на месте края у полосы входа. Полоса
# разбирает из него короткое имя службы (`kacho-` снимается) и сравнивает с
# константой края — `api-gateway`. То же имя, что у стенда чарта.
EDGE_SA="kacho-api-gateway"
REGISTRY_WORLD="${KANAME_STAND_REGISTRY_WORLD:-0}"
case "$REGISTRY_WORLD" in 0|1) ;; *) printf 'KANAME_STAND_REGISTRY_WORLD: expected 0 or 1\n' >&2; exit 64 ;; esac

# Личность владельца ресурса, отдельно от края и бутстрапа (kaname#1033).
registry_world_prepare() {
  [ "$REGISTRY_WORLD" = 1 ] || return 0
  mkdir -p "$BIN/manifests" || return 75
  cp "$ROOT/tests/authz-fixtures/registry-own-stand-fixture.yaml" "$BIN/manifests/registry.yaml" || return 75
  if [ ! -f "$PKI/registry.crt" ] || [ ! -f "$PKI/registry.key" ]; then
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
      'extendedKeyUsage=clientAuth' 'subjectAltName=URI:spiffe://kaname.local/ns/kaname/sa/kacho-registry' > "$PKI/registry.ext"
    ( umask 077
      openssl req -newkey rsa:2048 -nodes -subj '/CN=kacho-registry' \
        -keyout "$PKI/registry.key" -out "$PKI/registry.csr" >/dev/null 2>&1 &&
      openssl x509 -req -in "$PKI/registry.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
        -days 2 -extfile "$PKI/registry.ext" -out "$PKI/registry.crt" >/dev/null 2>&1
    ) || { unmet "лист владельца registry не выпущен"; return 75; }
  fi
  openssl verify -CAfile "$PKI/ca.crt" -purpose sslclient "$PKI/registry.crt" >/dev/null 2>&1 || return 75
  openssl x509 -in "$PKI/registry.crt" -noout -ext subjectAltName | \
    grep -qx '    URI:spiffe://kaname.local/ns/kaname/sa/kacho-registry' || return 75
  cmp -s <(openssl x509 -in "$PKI/registry.crt" -pubkey -noout) \
    <(openssl pkey -in "$PKI/registry.key" -pubout 2>/dev/null) || return 75
}

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
  if [ -f "$PKI/srv.crt" ] && [ -f "$PKI/ca.crt" ] && [ -f "$PKI/edge.crt" ]; then
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
[v3_edge]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://kaname.local/ns/kaname/sa/$EDGE_SA
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
  # ЛИСТ КРАЯ — только клиентский: сервером край для службы не бывает. Под `own`
  # человек заводится ТОЛЬКО полосой входа, а она допускает ровно край по имени
  # службы из SAN проверенного листа (INSTALL.md §2, `:9100`). Края на этом
  # стенде нет, и его место у полосы занимает посев — так же, как у стенда
  # чарта (`stand-chart.sh`, «ПОСАДКА `own`»). Лист предъявляется ТОЛЬКО полосе.
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$EDGE_SA" \
    -keyout "$PKI/edge.key" -out "$PKI/edge.csr" >/dev/null 2>&1
  openssl x509 -req -in "$PKI/edge.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
    -days 2 -extfile "$PKI/openssl.cnf" -extensions v3_edge -out "$PKI/edge.crt" >/dev/null 2>&1 || {
      unmet "лист края не выпустился"; exit "$RC_UNMET"; }
  cp "$PKI/srv.crt" "$PKI/pg.crt"; cp "$PKI/srv.key" "$PKI/pg.key"
  say "PKI выпущен: $PKI (УЦ + сертификат службы с SPIFFE-именем в SAN + клиентский лист края)"
}

# ─── База: TLS обязателен, иначе страж посадки откажет ───────────────────────
start_pg() {
  need_tool docker
  # `-v`: снять и анонимный том образа (`VOLUME` базы), иначе он остаётся
  # сиротой на каждый подъём (kaname#710).
  docker rm -fv "$PG_NAME" >/dev/null 2>&1
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
  # КОНТУР БУТСТРАПА ВКЛЮЧЁН НА СТЕНДЕ, И БЕЗ НЕГО СТЕНД НЕ ПРОВЕРЯЕТ НИЧЕГО
  # СВЕРХ РУБЕЖА.
  #
  # Он единственный вход на дерево, где нет ни одной личности: всякая другая
  # выдача требует УЖЕ выданного удостоверения, а первого не выдаёт никто.
  # Отсюда и вид ключа — P-256 (PKCS#8): его открытой половиной заводится строка
  # соответствия бутстрап-клиента, и подписант службы чеканит удостоверение сам,
  # без внешнего поставщика.
  #
  # Круг вызывающих — ИМЕНА, а не сеть: страж пускает ровно перечисленные SPIFFE
  # SAN и на ПУСТОМ перечне отказывает всем, в любом режиме. Пустой перечень при
  # включённой чеканке роняет СТАРТ в боевой посадке, поэтому «включили и забыли
  # назвать круг» здесь не выражается.
  if [ ! -f "$BOOTSTRAP_KEY_FILE" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out "$BOOTSTRAP_KEY_FILE" >/dev/null 2>&1 || {
        unmet "ключ бутстрап-контура не выпустился (openssl)"; exit "$RC_UNMET"; }
  fi
  KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM="$(cat "$BOOTSTRAP_KEY_FILE")"
  export KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM
  export KANAME_BOOTSTRAP_TOKEN_AUDIENCE=https://kaname.local
  export KANAME_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS="$BOOTSTRAP_CALLER_SAN"
  export KANAME_DB_HOST=127.0.0.1 KANAME_DB_PORT="$PG_PORT"
  export KANAME_DB_USER=kaname KANAME_DB_NAME=kaname KANAME_DB_PASSWORD=stand
  export KANAME_DB_SSLMODE=require
  export KANAME_JWKS_ENC_KEY="$(cat "$WRAPKEY_FILE")"
  export KANAME_AUTHN__DOMAIN=kaname.local
  export KANAME_AUTHN__TRUST_DOMAIN=kaname.local
  # КРУГ ПЕРЕСЫЛАЮЩИХ ЛИЧНОСТЬ — имя службы И имя края (kaname#398), как у
  # стенда чарта посадки `own` (`stand-chart.sh`, накладка `own`). Глагол `Create`
  # интерактивного клиента фронтируется краем (`GatewayFrontedInternalRPCs`):
  # хоп собственного фронта его не проходит by construction, а пересланный
  # принципал принимается только от доверенного пересылающего. Посев церемонии
  # (`seed_ceremony.py`) заводит клиентов этим глаголом, стоя на месте края
  # листом края стенда (`edge.crt`). В боевом профиле этот круг и есть край;
  # стенд дописывает его к имени службы, а не заменяет. Без него пол
  # подтверждения глагола читает принципал как непроверенный и отвечает
  # `authz.step_up` (замер на стенде: 403, PreconditionFailure).
  export KANAME_AUTHN__TRUSTED_FORWARDER_SANS="spiffe://kaname.local/ns/kaname/sa/kaname,spiffe://kaname.local/ns/kaname/sa/$EDGE_SA"
  # ЛИЧНОСТЬ КРАЯ СТЕНДА (kaname#984): модулем признаётся только объявленная
  # пара, и посев, стоящий на месте края листом края, иначе краем не был бы.
  # Перечень же судит допуск внутреннего фронта (SEC-1017-1): имени службы в нём
  # нет и не заводится, поэтому внутреннему фронту прогонщик и утверждения стенда
  # предъявляют лист края (`run.sh --internal-front-client-*`, `stand-assert.py`).
  export KANAME_AUTHN__MODULE_IDENTITIES="kaname/$EDGE_SA=edge@internal"
  if [ "$REGISTRY_WORLD" = 1 ]; then
    export KANAME_AUTHN__MODULE_IDENTITIES="$KANAME_AUTHN__MODULE_IDENTITIES,kaname/kacho-registry=module-writer@internal"
    export KANAME_MANIFESTS__DIR="$BIN/manifests" KANAME_MANIFESTS__REQUIRED=true
  else
    unset KANAME_MANIFESTS__DIR KANAME_MANIFESTS__REQUIRED
  fi
  # Центр личности края — внутренний центр стенда (kaname#988): тот же файл,
  # что у пула клиентских центров слушателей ниже.
  export KANAME_AUTHN__CLIENT_ISSUERS="internal=$PKI/ca.crt"
  export KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE=registry.kaname.local
  export KANAME_OWN_CEILINGS__ACCOUNTS_PER_IDENTITY=3
  export KANAME_OWN_CEILINGS__CREDENTIALS_PER_USER=5
  export KANAME_OWN_CEILINGS__CREDENTIALS_PER_SERVICE_ACCOUNT=5
  export KANAME_OWN_CEILINGS__ACCESS_KEYS_PER_USER=5
  # ПОЛОСА ЛИЧНОСТИ ОДНА — СВОЙ ВХОД, И КЛЮЧА, КОТОРЫЙ ЕЁ ВЫБИРАЛ, НЕТ.
  #
  # Здесь стояло сперва `external`, затем `own` ключом посадки. Посадку
  # `external` снял фундамент (PRO-Robotech/corelib#30, kaname#424), а ключ
  # снят вместе с осью (kaname#363): загрузчик отвергает его переменную вслух,
  # при любом значении.
  #
  # Вход человека держит сама служба, и старт требует величин полосы
  # входа, обёртки секретов второго фактора, окна свежести и привязки ключей
  # доступа. Числа ниже — те же, что объявляет боевой профиль
  # (`deploy/values.prod.yaml`, блок `authn.login`): стенд судит ту посадку,
  # которую поставка уносит клиенту, а не свою. Происхождение ключей доступа —
  # адрес консоли установки под её доменом, как у профиля: консоли на стенде
  # нет, и ключ, привязанный к этому адресу, не предъявит никто.
  #
  # Адресов поставщика здесь больше нет: их не читает никто.
  export KANAME_AUTHN__LOGIN__SESSION_TTL=24h
  export KANAME_AUTHN__LOGIN__COOKIE_DOMAIN=none
  export KANAME_AUTHN__LOGIN__ADDRESS_ATTEMPTS=5
  export KANAME_AUTHN__LOGIN__ADDRESS_WINDOW=15m
  export KANAME_AUTHN__LOGIN__SOURCE_ATTEMPTS=50
  export KANAME_AUTHN__LOGIN__SOURCE_WINDOW=15m
  export KANAME_AUTHN__LOGIN__PASSWORD_MIN_LENGTH=8
  export KANAME_AUTHN__LOGIN__BREACH_CHECK=disabled
  export KANAME_AUTHN__LOGIN__HASHER_FORMAT=argon2id
  export KANAME_AUTHN__LOGIN__HASHER_MEMORY=65536
  export KANAME_AUTHN__LOGIN__HASHER_ITERATIONS=3
  export KANAME_AUTHN__LOGIN__HASHER_PARALLELISM=4
  export KANAME_AUTHN__LOGIN__RECOVERY_CODE_TTL=5m
  # Пять величин подтверждения адреса (kaname#456, Р9): умолчаний у них нет, и
  # без любой из них старт под `own` отказывает, называя ключ. Числа — те же,
  # что в блоке `authn.login` боевого профиля.
  export KANAME_AUTHN__LOGIN__VERIFICATION_CODE_TTL=30m
  export KANAME_AUTHN__LOGIN__VERIFICATION_CODE_ATTEMPTS=5
  export KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_INTERVAL=60s
  export KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_LIMIT=5
  export KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_WINDOW=24h
  # Почтовая полоса службы — приёмник писем стенда: TLS с первого байта, лист
  # проверяется якорем стенда. Без узла письмо подтверждения не уходит никуда.
  export KANAME_INVITE_MAIL__RELAY="localhost:$MAIL_SMTP_PORT"
  export KANAME_INVITE_MAIL__FROM=kaname@kaname.local
  export KANAME_INVITE_MAIL__TLS_MODE=implicit
  export KANAME_INVITE_MAIL__CA_BUNDLE_FILE="$PKI/ca.crt"
  # Ёмкость проверяющего и резерв памяти страж сверяет с ПРЕДЕЛОМ ПАМЯТИ СРЕДЫ,
  # и предела он требует: без него старт отказывает. Предел накладывает
  # контейнер службы (`SERVICE_MEMORY` ниже), и сверку выносит сам страж.
  export KANAME_AUTHN__LOGIN__VERIFIER_CAPACITY=8
  export KANAME_AUTHN__LOGIN__MEMORY_RESERVE_BYTES=268435456
  export KANAME_AUTHN__REGISTRATION__ADMISSIONS_PER_WINDOW=3
  export KANAME_AUTHN__REGISTRATION__ADMISSION_WINDOW=1h
  export KANAME_AUTHN__SELF_SERVICE_FRESHNESS=15m
  export KANAME_AUTHN__ACCESS_KEYS__RP_ID=kaname.local
  export KANAME_AUTHN__ACCESS_KEYS__ORIGINS=https://console.kaname.local
  export KANAME_AUTHN__ACCESS_KEYS__ALGORITHMS=-7,-8,-257
  # Ключ обёртки секретов второго фактора ПОСТОЯНЕН по той же причине, что ключ
  # обёртки подписных ключей: записанное им другой ключ не откроет.
  [ -f "$SECOND_FACTOR_KEY_FILE" ] || openssl rand -hex 32 > "$SECOND_FACTOR_KEY_FILE"
  export KANAME_SECOND_FACTOR_ENC_KEY="$(cat "$SECOND_FACTOR_KEY_FILE")"
  # СЛУШАТЕЛЬ ПОЛОСЫ ВХОДА — дверь, которой посев заводит людей. Он допускает
  # РОВНО край по SAN проверенного клиентского листа, поэтому режим — `mutual`,
  # а лист края стенд выписывает сам (`make_pki`, `edge.crt`).
  export KANAME_API_SERVER__LOGIN_LANE_ENDPOINT=0.0.0.0:9100
  # Собственные REST-фронты — предмет автономности: только они принадлежат службе.
  export KANAME_API_SERVER__REST_ENDPOINT=0.0.0.0:9098
  export KANAME_API_SERVER__INTERNAL_REST_ENDPOINT=0.0.0.0:9099
  # Читатель предъявленного удостоверения и своя чеканка идут ПАРОЙ: страж
  # отказывает, если включён только один (читатель сверяет подписи по СВОЕМУ
  # реестру, а без чеканки реестра нет вовсе).
  export KANAME_AUTHN__PRESENTED_CREDENTIAL__ENABLED=true
  export KANAME_AUTHN__PRESENTED_CREDENTIAL__AUDIENCE=https://kaname.local
  # Срок — из ОДНОГО места (`REVOCATION_CACHE_TTL` в начале файла): по нему же
  # волна свёртки базы меряет свою тишину и своё окно.
  export KANAME_AUTHN__PRESENTED_CREDENTIAL__REVOCATION_CACHE_TTL="$REVOCATION_CACHE_TTL"
  export KANAME_AUTHN__TOKEN_SIGNING__ENABLED=true
  export KANAME_AUTHN__TOKEN_SIGNING__ISSUER=https://kaname.local
  export KANAME_AUTHN__TOKEN_SIGNING__ALGORITHM=RS256
  export KANAME_AUTHN__TOKEN_SIGNING__ALLOWED_ALGORITHMS=RS256
  # Срок ключа подписи — политика ротации: умолчания у него нет (#321), и
  # незаданный он отвергает пуск.
  export KANAME_AUTHN__TOKEN_SIGNING__KEY_LIFETIME=2160h
  # ПОЛОСА ОБМЕНА ПОДПИСАННОГО УТВЕРЖДЕНИЯ — БЕЗ НЕЁ ВЫДАННЫЙ КЛЮЧ НЕ ОБМЕНЯТЬ.
  #
  # `Issue` отдаёт приватный ключ ОДИН раз, и превратить его в предъявителя можно
  # только здесь: `POST /iam/v1/token` на поверхности выдачи. Выключенный
  # эндпоинт отвечает 404, то есть «ключ выдан и негоден» — состояние, по ответу
  # неотличимое от опечатки в пути.
  #
  # Адресат утверждения — ИДЕНТИФИКАТОР издателя, а не адрес эндпоинта, поэтому
  # перечень несёт `https://kaname.local`; второй элемент — адресат докерной
  # полосы, и страж старта требует, чтобы он был ВНУТРИ перечня.
  export KANAME_AUTHN__CLIENT_TOKEN__ENABLED=true
  export KANAME_AUTHN__CLIENT_TOKEN__ALLOWED_AUDIENCES='https://kaname.local,registry.kaname.local'
  export KANAME_AUTHN__CLIENT_TOKEN__DEFAULT_AUDIENCE='https://kaname.local'
  # СРОК ТОКЕНА И ПОТОЛОК ТЕЛА — ОБЪЯВЛЯЕТ ТОТ, КТО ПОДНИМАЕТ СЛУЖБУ (#112).
  #
  # Умолчаний у обеих величин больше нет: страж старта требует их названными,
  # потому что величина, которую подставляет построение, незаданной не бывает,
  # и ветвь стража при ней не исполнялась ни разу. Стенд — единственный профиль
  # дерева, включающий этот эндпоинт (чарт его не включает ни в одном
  # `values*.yaml`), значит объявить их обязан он, и оба числа здесь — решение с
  # производителем, а не «взяли побольше».
  #
  # Срок выводится из БЮДЖЕТА ШАГОВ, которые живут выданным токеном: посев
  # чеканит его и передаёт прогону, и токен обязан пережить остаток посева
  # плюс прогон коллекций — иначе истечение посреди прогона пришло бы отказом
  # доступа, неотличимым от дефекта дерева. Заданий на этом стенде два, и у
  # каждого сумма пределов его шагов — 25 минут: `stand` — посев 10 и прогон 15,
  # `stand-ceremony` — машинный посев 5, посев церемонии 5 и прогон 15 (его
  # предъявители людей выданы той же поверхностью и живут тот же срок). Сумма не
  # выходит за платформенный потолок `tokenpolicy.MaxTokenTTL` (30 минут), сверх
  # которого страж отказывает. Предикат: `grep -n 'timeout-minutes'
  # .github/workflows/e2e-newman.yml` у шагов посева и прогона обоих заданий.
  export KANAME_AUTHN__CLIENT_TOKEN__TOKEN_TTL=25m
  # Мир registry добавляет отдельный шаг посева (5 минут), всего 30 минут —
  # действующий потолок tokenpolicy, без ослабления проверки срока.
  if [ "$REGISTRY_WORLD" = 1 ]; then export KANAME_AUTHN__CLIENT_TOKEN__TOKEN_TTL=30m; fi
  # Потолок тела — тот же, что у соседней поверхности, несущей ОДИН токен
  # (`internal/handler/tokenintrospecthttp`, `maxTokenBytes = 16 << 10`): тело
  # обмена — форма с одним подписанным утверждением. Замер по посеву
  # (`sign_client_assertion`, P-256, вставленная в форму): 656 байт; утверждение
  # RSA-4096 уложилось бы примерно в 1.2 КиБ. Запас более чем десятикратный, и
  # потолок при этом остаётся потолком, а не «сколько пришлют».
  export KANAME_AUTHN__CLIENT_TOKEN__BODY_CEILING=16384
  # СРОКИ СОБСТВЕННОЙ ЦЕРЕМОНИИ (kaname#318) — тоже решение того, кто поднимает
  # службу: умолчаний нет, под `own` незаданный срок — отказ старта. Величины —
  # дословный перенос поведения сборки до ручек, равного потолкам фундамента
  # (tokenpolicy.MaxAuthorizationCodeTTL, tokenpolicy.MaxRefreshTokenFamilyTTL):
  # коллекции церемонии на стенде судят прежнее поведение.
  export KANAME_AUTHN__CEREMONY__CODE_TTL=60s
  export KANAME_AUTHN__CEREMONY__REFRESH_TTL=168h
  # ТЕМП ПОВЕРХНОСТИ ВЫДАЧИ (kaname#315) — числа §3 приёмки
  # ceremony-pace-is-named-by-number.md: у величин нет умолчаний, и страж старта
  # при включённом эндпоинте требует все четыре. Величины точки авторизации
  # (`authorize-*`) нужны собранной церемонии, а её собирает посадка `own`:
  # без них страж старта отказывает.
  export KANAME_AUTHN__CLIENT_TOKEN__IN_FLIGHT_CEILING=32
  export KANAME_AUTHN__CLIENT_TOKEN__EXCHANGES_PER_CLIENT_PER_SEC=5
  export KANAME_AUTHN__CLIENT_TOKEN__FAILED_PROOFS_PER_SOURCE=50
  export KANAME_AUTHN__CLIENT_TOKEN__FAILED_PROOF_WINDOW=15m
  export KANAME_AUTHN__CLIENT_TOKEN__AUTHORIZE_PER_SOURCE_PER_SEC=10
  export KANAME_AUTHN__CLIENT_TOKEN__AUTHORIZE_IN_FLIGHT_CEILING=32
  local l u
  for l in INTERNAL INTERNALREST METRICS PUBLIC REST JWKSPROXY REGISTRYTOKEN LOGINLANE; do
    eval "export KANAME_${l}_SERVER_MTLS_ENABLE=true \
      KANAME_${l}_SERVER_MTLS_CERTFILE=$PKI/srv.crt \
      KANAME_${l}_SERVER_MTLS_KEYFILE=$PKI/srv.key \
      KANAME_${l}_SERVER_MTLS_CLIENTCAFILES=$PKI/ca.crt \
      KANAME_${l}_SERVER_MTLS_CLIENTAUTHMODE=mutual"
  done
  # Слушатель выдачи при собранной церемонии ЗАПРАШИВАЕТ сертификат, но не
  # требует его (kaname#315, приёмка ceremony-pace-is-named-by-number.md Р7):
  # адрес источника для осей темпа берётся из заголовка края только у проверенного
  # листа края, а клиент докерной полосы листа не несёт. Режим `mutual` страж
  # старта отвергает — ровно то, что объявляет боевой профиль.
  export KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE=optional-mutual
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
  # Сборка — без cgo, той же формой, что у образа поставки (`Dockerfile`):
  # служба исполняется в контейнере (см. `start_service`), и бинарь, связанный с
  # библиотеками машины сборки, в нём бы не запустился.
  CGO_ENABLED=0 go build -o "$BIN/kaname" ./cmd/kaname || { fail "сборка kaname не прошла"; exit 1; }
  CGO_ENABLED=0 go build -o "$BIN/kaname-migrator" ./cmd/migrator || { fail "сборка накатчика не прошла"; exit 1; }
  say "собрано: kaname, kaname-migrator"
}

# КЛАСС ОТКАЗА НАКАТА НАЗЫВАЕТ САМ НАКАТ — СВОИМ КОДОМ ВЫХОДА.
#
# Здесь стоял поиск слов `connect|dial|refused|sslmode|password` в выводе
# накатчика, и он судил ЭХО ВВОДА, а не причину отказа: сообщения накатчика
# вкладывают в себя обеззараженную строку подключения, обеззараживание сохраняет
# запрос, а посадка стенда экспортирует `sslmode=require` всегда. Значит слово из
# образца стояло в выводе ГАРАНТИРОВАННО, и совпадение ничего не означало.
#
# Цена измерена и она в стороне ошибки: отказ «адрес базы не называет хоста» —
# тот, о котором накат прямо говорит, что ожидание не сойдётся НИКОГДА, —
# получал 75, а шаг конвейера переводит 75 в «прогон недействителен, это НЕ
# дефект кода». Неверная посадка не краснела НИ РАЗУ.
#
# Второго словаря здесь больше нет by construction: класс объявлен ровно там, где
# накат им же решает, имеет ли смысл ждать (`cmd/migrator/main.go`, `exitCodeFor`
# через `dbready.IsNotReady`), а этот шаг лишь передаёт названное. Вывод
# печатается читателю и в вердикт НЕ входит.
#
# Прежний комментарий на этом месте говорил ещё и то, что накатчик грузит полный
# конфиг службы, и потому отказ бывает находкой «требование стража добавили». Это
# завышало класс: полного стража накат НЕ ЗОВЁТ намеренно — в боевом режиме тот
# требует секретов, которых init-контейнер не несёт. Накат судит ровно ту
# величину, которую употребляет.
migrate() {
  # `local out rc` ОТДЕЛЬНОЙ строкой, а присваивание — следующей: у `local
  # out="$(…)"` код возврата принадлежит самому `local`, то есть равен нулю
  # всегда, и отказ накатчика исчез бы вместе с величиной.
  local out rc
  out="$(${MIGRATOR_RUN[@]+"${MIGRATOR_RUN[@]}"} "$BIN/kaname-migrator" up 2>&1)"; rc=$?
  printf '%s\n' "$out" | tail -3
  if [ "$rc" -eq 0 ]; then
    say "миграции накачены"
    return 0
  fi
  if [ "$rc" -eq "$RC_UNMET" ]; then
    unmet "накатчик не дотянулся до базы (он назвал это кодом $rc)"
    printf '%s\n' "$out" | tail -1 >&2
    exit "$RC_UNMET"
  fi
  fail "накатчик отказал (код $rc):"
  printf '%s\n' "$out" | tail -1 >&2
  exit 1
}

# СЛУЖБА ИСПОЛНЯЕТСЯ В КОНТЕЙНЕРЕ, И ПРИЧИНА ОДНА — ПРЕДЕЛ ПАМЯТИ.
#
# Под `own` страж полосы входа сверяет ёмкость проверяющего с пределом памяти
# среды и БЕЗ предела отказывает в старте (ID-PW-1 PWV-15.8). Предел он читает
# там, где его объявляет контейнер (`/sys/fs/cgroup/memory.max`), а процесс,
# запущенный прямо на машине, предела не видит. Поэтому тот же бинарь, собранный
# здесь, исполняется контейнером с пределом `SERVICE_MEMORY`: чарта, кластера и
# образа поставки по-прежнему нет. Предел — тот же, что у боевого профиля
# (`resources.limits.memory`), и та же арифметика стража: ёмкость 8 × память
# проверки на потолке + резерв.
#
# Образ — тот же, что у базы: он уже скачан, а статически собранному бинарю от
# образа не нужно ничего. Сеть — машины: слушатели службы отвечают на тех же
# адресах, что прежде, и утверждения с посевом их не меняют. Вызов клиента
# контейнера идёт на ПЕРЕДНЕМ плане под `nohup`: процесс клиента живёт ровно
# столько, сколько служба, и различение «страж отказал» от «слушатель не
# поднялся» остаётся прежним — по живости процесса и по портам.
# start_mailbox — приёмник писем стенда процессом машины. Не поднялся — условие
# не создано: вердикта о дереве нет.
start_mailbox() {
  need_tool python3
  mkdir -p "$RUNDIR"
  if [ -f "$RUNDIR/mailbox.pid" ]; then
    kill "$(cat "$RUNDIR/mailbox.pid")" 2>/dev/null
    rm -f "$RUNDIR/mailbox.pid"
  fi
  nohup python3 "$HERE/stand-mailbox.py" serve --host 127.0.0.1 \
    --smtp-port "$MAIL_SMTP_PORT" --http-port "$MAIL_HTTP_PORT" \
    --cert "$PKI/srv.crt" --key "$PKI/srv.key" > "$RUNDIR/mailbox.log" 2>&1 < /dev/null &
  echo $! > "$RUNDIR/mailbox.pid"
  local i
  for i in $(seq 1 20); do
    if python3 -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:$MAIL_HTTP_PORT/healthz', timeout=2)" 2>/dev/null; then
      say "приёмник писем стенда поднят: SMTP поверх TLS 127.0.0.1:$MAIL_SMTP_PORT, чтение 127.0.0.1:$MAIL_HTTP_PORT"
      return 0
    fi
    kill -0 "$(cat "$RUNDIR/mailbox.pid")" 2>/dev/null || break
    sleep 1
  done
  unmet "приёмник писем стенда не поднялся: $(tail -2 "$RUNDIR/mailbox.log" 2>/dev/null | tr '\n' ' ')"
  exit "$RC_UNMET"
}

SERVICE_NAME="${KANAME_STAND_SERVICE_NAME:-kaname-stand-svc}"
SERVICE_IMAGE="${KANAME_STAND_SERVICE_IMAGE:-$PG_IMAGE}"
SERVICE_MEMORY="${KANAME_STAND_SERVICE_MEMORY:-1280m}"

start_service() {
  mkdir -p "$RUNDIR"
  local envs=() v
  # Посадка уезжает в контейнер ИМЕНАМИ, а не значениями: `-e ИМЯ` берёт
  # величину из окружения, и ключи с переводом строки доезжают целыми. Ручки
  # самого стенда (`KANAME_STAND_*`) службе не принадлежат и не передаются.
  for v in $(compgen -e); do
    case "$v" in KANAME_STAND_*) ;; KANAME_*) envs+=(-e "$v") ;; esac
  done
  docker rm -fv "$SERVICE_NAME" >/dev/null 2>&1
  nohup docker run --rm --name "$SERVICE_NAME" --network host \
    --memory "$SERVICE_MEMORY" --memory-swap "$SERVICE_MEMORY" \
    --user "$(id -u):$(id -g)" -v "$BIN:$BIN:ro" -v "$PKI:$PKI:ro" "${envs[@]}" \
    --entrypoint "" "$SERVICE_IMAGE" "$BIN/kaname" > "$RUNDIR/kaname.log" 2>&1 &
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
#
# Слушателя хуков поставщика (`:9092`) в перечне нет: поставщика у службы нет, и
# слушателя тоже (kaname#360, kaname#363). Есть слушатель полосы входа (`:9100`).
PORTS="${KANAME_STAND_PORTS:-9090 9091 9095 9096 9097 9098 9099 9100}"

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
  if [ -f "$RUNDIR/mailbox.pid" ]; then
    kill "$(cat "$RUNDIR/mailbox.pid")" 2>/dev/null
    rm -f "$RUNDIR/mailbox.pid"
  fi
  # `-v` снимает анонимные тома контейнеров вместе с ними: без него каждый
  # подъём-снос оставлял том базы сиротой (kaname#710, ось 8 самопроверки).
  command -v docker >/dev/null 2>&1 && docker rm -fv "$SERVICE_NAME" "$PG_NAME" >/dev/null 2>&1
  say "стенд снесён"
}

# ─── СВЁРТКА БАЗЫ: условие волны отказа без вердикта (kaname#415) ────────────
#
# Коллекции `authz-failclosed` нужно условие, несовместимое с остальным прогоном:
# база стенда НЕДОСТИЖИМА, а служба ЖИВА. Свёртка останавливает контейнер базы и
# службу не трогает; возврат запускает его обратно и ждёт, пока база снова
# принимает соединения (служба переподключается сама — замер 2026-10-01: первый
# же запрос после возврата отвечает 200).
#
# Исходы — те же два класса, что у подъёма. Не вышло остановить или запустить —
# УСЛОВИЕ НЕ СОЗДАНО (75): волна без свёртки проверяла бы живую базу, и это не
# вердикт о дереве. Код клиента контейнера при этом не единственный свидетель:
# остановка сверяется с СОСТОЯНИЕМ контейнера, потому что «команда прошла» и
# «база недостижима» — разные факты.
fold_db() {
  need_tool docker
  local out running
  if ! out="$(docker stop "$PG_NAME" 2>&1)"; then
    unmet "базу стенда не свернуть: контейнер $PG_NAME не остановлен ($out)"
    exit "$RC_UNMET"
  fi
  running="$(docker inspect -f '{{.State.Running}}' "$PG_NAME" 2>/dev/null)"
  if [ "$running" != "false" ]; then
    unmet "базу стенда не свернуть: контейнер $PG_NAME по-прежнему исполняется (состояние «${running:-не прочитано}»)"
    exit "$RC_UNMET"
  fi
  say "база стенда свёрнута: контейнер $PG_NAME остановлен, служба оставлена жить"
}

unfold_db() {
  need_tool docker
  local out i
  if ! out="$(docker start "$PG_NAME" 2>&1)"; then
    unmet "базу стенда не вернуть: контейнер $PG_NAME не запущен ($out)"
    exit "$RC_UNMET"
  fi
  for i in $(seq 1 "$DB_READY_TRIES"); do
    if docker exec "$PG_NAME" pg_isready -U kaname >/dev/null 2>&1; then
      say "база стенда возвращена и принимает соединения, попытка $i"
      return 0
    fi
    sleep 1
  done
  unmet "база стенда не ответила pg_isready за $DB_READY_TRIES с после возврата"
  exit "$RC_UNMET"
}

# ─── ВОЛНА СВЁРТКИ БАЗЫ: условие создаётся, а не предполагается (kaname#558) ──
#
# Коллекция `authz-failclosed` утверждает 503 рубежа положения. Дойти до него
# запрос может, только пройдя рубеж предъявителя, а тот под свёрткой отвечает
# единым 401 (KAN-REV-03, KAN-DENY-01), как только ему понадобится база: при
# устаревшем снимке набора ключей либо вердикте об отзыве. Значит условие
# коллекции — ОБА кеша свежи на всё её время.
#
# Прежняя волна предъявляла удостоверения «для прогрева» сразу после соседних
# коллекций. Окна не скользящие, поэтому такое предъявление было ПОПАДАНИЕМ и
# окна не освежало: остаток окна был равномерен на [0, срок) и задавался
# расписанием соседей, а при остатке меньше длины коллекции снимок истекал
# посреди неё — и 401 продукта, верный по приёмке, выходил красным коллекции.
#
# Теперь условие СОЗДАЁТСЯ:
#   1. тишина без предъявлений длиной в больший из сроков плюс запас — после неё
#      обе записи истекли, и следующее предъявление обязано быть промахом;
#   2. прогрев — этот промах: окна начинаются с него, отметка t0 снята ДО него,
#      так что t0 + меньший срок — нижняя граница конца обоих окон;
#   3. свёртка базы;
#   4. страж ДО вызовов: если от t0 прошло столько, что запаса окна не осталось,
#      коллекция не гоняется, исход — УСЛОВИЕ НЕ СОЗДАНО (75);
#   5. коллекция; страж ПОСЛЕ: красное, полученное, когда окно уже могло
#      истечь, — тоже 75 с названной причиной, а не красное о дереве. Красное
#      внутри окна и зелёное отдаются как есть: утверждения коллекции не тронуты.
#
# Часы и пауза — функции, чтобы самопроверка судила этот же код подставным
# временем, не выжидая сроков.
now_s()   { date +%s; }
pause_s() { sleep "$1"; }

# dur_seconds <длительность> — секунды целым числом из формы `[Nh][Nm][Ns]`
# (подмножество длительности Go, которой написана посадка службы). Пустое и
# прочее — отказ: срок, которого не разобрать, волна не угадывает.
dur_seconds() {
  local d="$1" h=0 m=0 s=0
  [[ "$d" =~ ^(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?$ ]] && [ -n "$d" ] || return 1
  [ -n "${BASH_REMATCH[2]}" ] && h="${BASH_REMATCH[2]}"
  [ -n "${BASH_REMATCH[4]}" ] && m="${BASH_REMATCH[4]}"
  [ -n "${BASH_REMATCH[6]}" ] && s="${BASH_REMATCH[6]}"
  printf '%s' "$(( 10#$h * 3600 + 10#$m * 60 + 10#$s ))"
}

# present_own <env-файл> <фронт> <ключ окружения> — код ответа фронта на
# предъявление; предъявитель уходит через стандартный ввод, а не доводом.
present_own() {
  local env_file="$1" own="$2" key="$3" code
  code="$(jq -r --arg k "$key" '.values[] | select(.key == $k) | "Authorization: Bearer " + .value' "$env_file" \
    | curl -sS -o /dev/null -w '%{http_code}' -H @- \
        --cacert "$PKI/ca.crt" --cert "$PKI/srv.crt" --key "$PKI/srv.key" \
        "$own/iam/v1/accounts?pageSize=1")" || code="нет ответа"
  printf '%s' "$code"
}

# Волна — ДВЕ подкоманды вокруг прогона, а не одна, обёртывающая его: прогон
# коллекции остаётся командой прогонщика в теле шага, и перепись гоняемого
# (`newman-suite-debt.py`) читает его как прогон, а не как строку внутри довода.
# Между ними состояние — файл: отметка прогрева и окно.
WAVE_STATE="$RUNDIR/failclosed-wave.state"

# wave_ttls — печатает «тишина окно» в секундах из сроков посадки; срок,
# которого не разобрать, — НАХОДКА о дереве (1).
wave_ttls() {
  local key_s rev_s
  if ! key_s="$(dur_seconds "$KEY_SET_TTL")"; then
    fail "срок снимка набора ключей KEY_SET_TTL=«$KEY_SET_TTL» не разобран — тишину волны не отмерить"
    exit 1
  fi
  if ! rev_s="$(dur_seconds "$REVOCATION_CACHE_TTL")"; then
    fail "срок кеша отзыва REVOCATION_CACHE_TTL=«$REVOCATION_CACHE_TTL» не разобран — тишину волны не отмерить"
    exit 1
  fi
  printf '%s %s %s %s' "$(( (key_s > rev_s ? key_s : rev_s) + WAVE_MARGIN_S ))" \
    "$(( key_s < rev_s ? key_s : rev_s ))" "$key_s" "$rev_s"
}

# failclosed_prepare <env-файл> — тишина, прогрев промахом, свёртка, страж ДО
# вызовов. Исходы: 0 — условие создано, отметка записана; 75 — не создано.
failclosed_prepare() {
  local env_file="${1:-}"
  if [ -z "$env_file" ]; then
    printf 'использование: %s failclosed-prepare <env-файл>\n' "$0" >&2
    exit 2
  fi
  need_tool jq
  need_tool curl
  local ttls quiet window key_s rev_s own key code t0 t_ready
  ttls="$(wave_ttls)" || exit $?
  read -r quiet window key_s rev_s <<EOF
$ttls
EOF
  own="$(jq -r '.values[] | select(.key == "ownRestBaseUrl") | .value' "$env_file")"
  if [ -z "$own" ] || [ "$own" = "null" ]; then
    unmet "в окружении $env_file нет адреса собственного фронта — свёртка не начиналась, коллекция authz-failclosed НЕ гонялась, вердикта о дереве нет"
    exit "$RC_UNMET"
  fi
  rm -f "$WAVE_STATE"

  say "тишина $quiet с без предъявлений: снимок ключей $key_s с, кеш отзыва $rev_s с, запас $WAVE_MARGIN_S с — прогрев обязан быть промахом обоих кешей"
  pause_s "$quiet"
  t0="$(now_s)"
  for key in jwtBootstrap jwtAccountAdminA; do
    code="$(present_own "$env_file" "$own" "$key")"
    if [ "$code" != "200" ]; then
      unmet "предъявитель $key не принят фронтом при ЖИВОЙ базе (код $code) — свёртка не начиналась, коллекция authz-failclosed НЕ гонялась, вердикта о дереве нет"
      exit "$RC_UNMET"
    fi
    say "контроль до свёртки: $key принят фронтом (200) после тишины — окна обоих кешей начаты этим предъявлением"
  done
  db_fold_routed
  t_ready="$(now_s)"
  if [ $(( t_ready - t0 + WAVE_MARGIN_S )) -ge "$window" ]; then
    unmet "окно свежих кешей истекло до вызовов: от прогрева прошло $(( t_ready - t0 )) с из $window с, запас $WAVE_MARGIN_S с — коллекция authz-failclosed НЕ гонялась, вердикта о дереве нет"
    exit "$RC_UNMET"
  fi
  mkdir -p "$(dirname "$WAVE_STATE")"
  printf '%s %s\n' "$t0" "$window" > "$WAVE_STATE"
  say "окно свежих кешей $window с, к началу коллекции от прогрева прошло $(( t_ready - t0 )) с"
}

# failclosed_judge <код коллекции> — страж ПОСЛЕ вызовов. Красное, полученное,
# когда окно уже могло истечь, — 75 с названной причиной; иначе код коллекции
# как есть: зелёное и красное внутри окна — вердикт о дереве.
failclosed_judge() {
  local rc="${1:-}" t0 window t_end
  if ! [[ "$rc" =~ ^[0-9]+$ ]]; then
    printf 'использование: %s failclosed-judge <код коллекции>\n' "$0" >&2
    exit 2
  fi
  if ! read -r t0 window < "$WAVE_STATE" 2>/dev/null || [ -z "${window:-}" ]; then
    unmet "отметки прогрева нет ($WAVE_STATE) — подготовка волны не завершилась, исход коллекции (код $rc) не вердикт о дереве"
    exit "$RC_UNMET"
  fi
  t_end="$(now_s)"
  if [ "$rc" -ne 0 ] && [ $(( t_end - t0 )) -ge "$window" ]; then
    unmet "окно свежих кешей истекло посреди коллекции: от прогрева до её конца $(( t_end - t0 )) с при окне $window с — её красное (код $rc) может быть верным 401 рубежа предъявителя, вердикта о дереве нет"
    exit "$RC_UNMET"
  fi
  say "коллекция завершилась: от прогрева $(( t_end - t0 )) с из окна $window с (код $rc)"
  return "$rc"
}

# ─── ВНЕШНИЙ КЛАСТЕР — ПЕРВЫМ, ЛОКАЛЬНЫЙ DOCKER — ПО ОСНОВАНИЮ (kaname#841) ───
#
# Стенд поднимался `docker run` машины и тогда, когда внешний кластер был
# доступен: замер полосы kaname#829 — 7 подъёмов, 1,25 ч за сутки на машине
# разработчика. Норма — тяжёлое во внешнем кластере, локально лишь при его
# недоступности, и недоступность доказывается выводом проверки, а не догадкой.
#
# ВЫБОР ПУТИ (`route_decide`) — до первой записи куда бы то ни было:
#   кубконфиг    KANAME_STAND_KUBECONFIG, иначе KACHO_REMOTE_KUBECONFIG, иначе
#                первая строка личного файла `${XDG_CONFIG_HOME:-~/.config}/kacho/remote-kubeconfig`
#                (та же координата, что у тяжёлых прогонов воркспейса); окружение
#                KUBECONFIG и текущий контекст НЕ берутся — они могут смотреть на
#                kind или на кластер с выкаткой, и стенд ушёл бы туда молча;
#   контекст     ровно один контекст файла с суффиксом `-client`; явный —
#                KANAME_STAND_CONTEXT, и только с тем же суффиксом (иначе отказ 64:
#                ставить можно только в `-client`); current-context не читается;
#   кластер      доказывают УЗЛЫ, а не файл: узлов ≥ 1, все `<профиль>-client-…`,
#                ни одного `-infra-`; профиль — KANAME_STAND_PROFILE либо из имени
#                файла `<учётка>--<профиль>.yaml`;
#   право        `auth can-i create namespaces` отвечает `yes` за EXT_PROBE_S секунд.
# Не сошлось любое — путь локальный, и основание (шаг и вывод проверки, адреса
# скрыты) печатается и пишется строкой в `$RUNDIR/route.log`. Кластер доступен,
# а номера задачи нет — отказ 64: локально стенд при доступном кластере не идёт.
#
# ВНЕШНИЙ ПУТЬ — тот же ПРОЦЕСС, а не чарт: один под в пространстве
# `t<задача>-kaname-own` с тремя контейнерами, делящими сеть пода так же, как
# локальный путь делит сеть машины (`--network host`): база на 127.0.0.1:$PG_PORT,
# служба на своих портах, приёмник писем на своих. Посадка — та же `stand_env`,
# с путями файлов пода (`/stand/pki`); бинари собираются здесь же и доезжают в
# под потоком с проверкой отпечатка. Слушатели службы пробрасываются на
# 127.0.0.1 машины теми же номерами, поэтому утверждения, посев и прогон
# коллекций не меняются. Предел памяти службы — предел контейнера пода
# (`SERVICE_MEMORY`), его страж полосы входа и читает.
#
# СНЯТИЕ — `down` той же задачей: проброс, журнал службы в `$RUNDIR/kaname.log`,
# пространство (только помеченное этим стендом, чужое не трогается), затем
# перепись помеченных пространств задачи — исход числом, ненулевой остаток — 1.
# Подъём, не дошедший до конца, снимает созданное сам.
#
# СБОРКА И НАБОРЫ БЕЗ МАШИНЫ — `runner` (раздел «РАННЕР» ниже, kaname#940): машина
# заводит пространство и pod раннера, а подъём этим же путём, посев и наборы идут в pod.

EXT_PROBE_S="${KANAME_STAND_EXT_PROBE_S:-10}"
EXT_READY_TRIES="${KANAME_STAND_EXT_READY_TRIES:-300}"
EXT_TTL_HOURS="${KANAME_STAND_TTL_HOURS:-12}"
EXT_POD=kaname-own
EXT_MARK_LABEL="kaname.io/stand"
EXT_MARK=own
EXT_PKI=/stand/pki
EXT_BIN=/stand/bin
MAILBOX_IMAGE="${KANAME_STAND_MAILBOX_IMAGE:-python:3.12-alpine}"
ROUTE_FILE="$RUNDIR/route"
ROUTE_LOG="$RUNDIR/route.log"
FORWARD_PID="$RUNDIR/forward.pid"
FORWARD_LOG="$RUNDIR/forward.log"
FORWARD_ON="$RUNDIR/forward.on"
EXT_KCFG=""; EXT_CTX=""; EXT_PROF=""; EXT_TASK=""; EXT_NS=""
ROUTE=local; WHY=""; PROOF=""
# Префикс исполнения наката: пустой — накатчик машины; внешний путь подставляет exec пода.
MIGRATOR_RUN=()

refuse() { printf 'ОТКАЗ: %s\n' "$*" >&2; }

# mask — адрес сервера и адреса узлов в выводе проверки не печатаются:
# репозиторий публичный, вывод прогона уходит в задачи.
mask() {
  sed -E 's#[a-zA-Z][a-zA-Z0-9+.-]*://[^ )]+#<кластер>#g; s#[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?#<адрес>#g'
}

# Три формы вызова кластера, все с явными файлом и контекстом: опрос (короткий
# предел — недоступность доказывается быстро), запись и чтение (предел запроса),
# поток (exec, проброс, журнал — предел ставит вызывающий).
kq() { timeout "$EXT_PROBE_S" kubectl --kubeconfig "$EXT_KCFG" --context "$EXT_CTX" --request-timeout="${EXT_PROBE_S}s" "$@"; }
kc() { kubectl --kubeconfig "$EXT_KCFG" --context "$EXT_CTX" --request-timeout=60s "$@"; }
ks() { kubectl --kubeconfig "$EXT_KCFG" --context "$EXT_CTX" "$@"; }

# ─── СТЕНД ИЗНУТРИ POD РАННЕРА (kaname#940) ─────────────────────────────────
#
# Наборы стенда гонит не машина, а pod раннера (`runner` ниже) в пространстве,
# которое машина завела и снимет сама. Подъём в нём — тот же внешний путь, но
# кластер уже доказан машиной (контекст -client, узлы профиля) ДО заведения
# пространства, а учётка pod пространств не заводит и не читает: роль у неё
# лишь в своём. Поэтому изнутри pod (KANAME_STAND_IN_POD=1):
#   маршрут     внешний, пространство — СВОЁ пространство учётки pod, и оно же
#               обязано быть названо KANAME_STAND_EXT_NS (иначе отказ 64: стенд
#               ставится лишь туда, где pod сам и живёт);
#   кубконфиг   файл в RUNDIR из учётки pod (сертификат кластера и ФАЙЛ токена —
#               сам токен в файл не переписывается), контекст `in-pod`;
#   пространство не заводится и не снимается: подъём убирает остаток прежнего
#               стенда в нём, снос — объекты стенда, перепись — под стенда в нём.
IN_POD="${KANAME_STAND_IN_POD:-}"
SA_DIR="${KANAME_STAND_SA_DIR:-/var/run/secrets/kubernetes.io/serviceaccount}"

# in_pod_route — маршрут изнутри pod раннера; код 64 — pod не раннера либо не в
# названном пространстве.
in_pod_route() {
  local own host
  if [ -z "${KUBERNETES_SERVICE_HOST:-}" ] || [ ! -r "$SA_DIR/namespace" ] || [ ! -r "$SA_DIR/token" ] || [ ! -r "$SA_DIR/ca.crt" ]; then
    refuse "KANAME_STAND_IN_POD — лишь изнутри pod раннера: учётки pod нет; с машины — stand-own.sh runner"
    return 64
  fi
  own="$(cat "$SA_DIR/namespace")"
  if [ -z "${KANAME_STAND_EXT_NS:-}" ] || [ "$own" != "$KANAME_STAND_EXT_NS" ]; then
    refuse "pod раннера в пространстве «$own», а стенд назван «${KANAME_STAND_EXT_NS:-}» — стенд ставится лишь в своё пространство"
    return 64
  fi
  host="$KUBERNETES_SERVICE_HOST"
  case "$host" in *:*) host="[$host]" ;; esac
  mkdir -p "$RUNDIR"
  EXT_KCFG="$RUNDIR/in-pod.kubeconfig"; EXT_CTX=in-pod
  cat > "$EXT_KCFG" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: in-pod
    cluster: {server: "https://$host:${KUBERNETES_SERVICE_PORT:-443}", certificate-authority: "$SA_DIR/ca.crt"}
users:
  - name: in-pod
    user: {tokenFile: "$SA_DIR/token"}
contexts:
  - name: in-pod
    context: {cluster: in-pod, user: in-pod, namespace: "$own"}
current-context: in-pod
EOF
  PROOF="pod раннера в своём пространстве $own: учётка pod, роль лишь в нём; кластер доказан машиной до заведения пространства"
  ROUTE=external
}

# ext_clear_objects — объекты стенда в пространстве (не само пространство).
ext_clear_objects() {
  kc -n "$EXT_NS" delete pod "$EXT_POD" --ignore-not-found --wait=true >/dev/null 2>&1 || return 1
  kc -n "$EXT_NS" delete secret kaname-own-env kaname-own-pki --ignore-not-found >/dev/null 2>&1 || return 1
  kc -n "$EXT_NS" delete configmap kaname-own-mailbox --ignore-not-found >/dev/null 2>&1 || return 1
}

ext_kubeconfig() {
  local f="${KANAME_STAND_KUBECONFIG:-${KACHO_REMOTE_KUBECONFIG:-}}"
  local personal="${XDG_CONFIG_HOME:-${HOME:-}/.config}/kacho/remote-kubeconfig"
  if [ -z "$f" ] && [ -r "$personal" ]; then
    f="$(head -n 1 "$personal")"
    f="${f/#\~/${HOME:-}}"
  fi
  if [ -z "$f" ]; then
    WHY="кубконфиг внешнего кластера не назван (KANAME_STAND_KUBECONFIG, KACHO_REMOTE_KUBECONFIG, личный файл kacho/remote-kubeconfig)"
    return 1
  fi
  [ -r "$f" ] || { WHY="названный кубконфиг внешнего кластера не читается"; return 1; }
  EXT_KCFG="$f"
}

# ext_context — код 64: явный контекст не `-client` (ошибка вызова, не
# недоступность); 1 — контекст не выбран, путь локальный с основанием.
ext_context() {
  local ctxs n
  if [ -n "${KANAME_STAND_CONTEXT:-}" ]; then
    case "$KANAME_STAND_CONTEXT" in
      *-client) ;;
      *) refuse "KANAME_STAND_CONTEXT — только контекст -client (ставить стенд можно только в него)"; return 64 ;;
    esac
  fi
  ctxs="$(kubectl --kubeconfig "$EXT_KCFG" config get-contexts -o name 2>/dev/null)" || {
    WHY="контексты кубконфига не прочитаны"; return 1; }
  if [ -n "${KANAME_STAND_CONTEXT:-}" ]; then
    grep -qxF -- "$KANAME_STAND_CONTEXT" <<< "$ctxs" || { WHY="названного контекста -client в кубконфиге нет"; return 1; }
    EXT_CTX="$KANAME_STAND_CONTEXT"
    return 0
  fi
  n="$(grep -c -- '-client$' <<< "$ctxs")"
  [ "$n" -eq 1 ] || { WHY="контекстов -client в кубконфиге $n, нужен ровно один"; return 1; }
  EXT_CTX="$(grep -- '-client$' <<< "$ctxs")"
}

ext_profile() {
  local from_file=""
  [[ "${EXT_KCFG##*/}" =~ --([A-Za-z0-9]+)\.ya?ml$ ]] && from_file="${BASH_REMATCH[1]}"
  EXT_PROF="${KANAME_STAND_PROFILE:-$from_file}"
  [ -n "$EXT_PROF" ] || { WHY="профиль кластера не назван (KANAME_STAND_PROFILE либо имя файла <учётка>--<профиль>.yaml)"; return 1; }
  if [ -n "$from_file" ] && [ "$from_file" != "$EXT_PROF" ]; then
    WHY="профиль KANAME_STAND_PROFILE расходится с именем кубконфига — файл мог быть подменён"
    return 1
  fi
}

# ext_nodes_guard — кластер доказывают узлы: файл профиля могут заменить.
ext_nodes_guard() {
  local out rc n all=0 good=0 infra=0
  out="$(kq get nodes -o name 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    WHY="узлы внешнего кластера не прочитаны"
    PROOF="kubectl get nodes: код $rc, $(printf '%s\n' "$out" | head -n 1 | mask | cut -c1-300)"
    return 1
  fi
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    n="${n#node/}"; all=$((all + 1))
    case "$n" in
      *-infra-*) infra=$((infra + 1)) ;;
      "$EXT_PROF"-client-*) good=$((good + 1)) ;;
    esac
  done <<< "$out"
  if [ "$all" -eq 0 ] || [ "$infra" -gt 0 ] || [ "$good" -ne "$all" ]; then
    WHY="узлы не кластера профиля: всего $all, с префиксом <профиль>-client- $good, с -infra- $infra — кубконфиг мог быть подменён"
    return 1
  fi
  EXT_NODES="$good"
}

# route_decide — ROUTE=external|local, основание в WHY и PROOF. Код 64 — ошибка
# вызова; иначе 0 при любом пути.
route_decide() {
  local out rc
  ROUTE=local; WHY=""; PROOF=""
  if [ -n "$IN_POD" ]; then in_pod_route; return $?; fi
  ext_kubeconfig || return 0
  command -v kubectl >/dev/null 2>&1 || { WHY="kubectl на машине нет — внешний кластер не спросить"; return 0; }
  ext_context; rc=$?
  [ "$rc" -eq 64 ] && return 64
  [ "$rc" -eq 0 ] || return 0
  ext_profile || return 0
  out="$(kq auth can-i create namespaces 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] || [ "$(printf '%s\n' "$out" | grep -v '^Warning:' | tail -n 1)" != yes ]; then
    WHY="внешний кластер не ответил либо заводить пространства не вправе"
    PROOF="kubectl auth can-i create namespaces: код $rc, $(printf '%s\n' "$out" | grep -v '^Warning:' | head -n 1 | mask | cut -c1-300)"
    return 0
  fi
  ext_nodes_guard || return 0
  PROOF="контекст -client отвечает, заводить пространства вправе, узлов профиля $EXT_NODES"
  ROUTE=external
}

# ext_name_ns — t<задача>-kaname-own; задача — KANAME_STAND_TASK либо ведущие
# цифры имени ветки. Код 64 — назвать пространство нечем.
ext_name_ns() {
  local task="${KANAME_STAND_TASK:-}" br
  if [ -z "$task" ]; then
    br="$(git -C "$ROOT" branch --show-current 2>/dev/null)"
    [[ "$br" =~ ^(issue-)?([0-9]+)([-_/].*)?$ ]] && task="${BASH_REMATCH[2]}"
  fi
  if ! [[ "$task" =~ ^[0-9]+$ ]]; then
    refuse "внешний кластер доступен, а номера задачи нет: пространство t<задача>-kaname-own назвать нечем — KANAME_STAND_TASK=<номер> либо ветка <номер>…; локально стенд при доступном кластере не идёт"
    return 64
  fi
  EXT_TASK="$task"
  EXT_NS="${KANAME_STAND_EXT_NS:-t$task-kaname-own}"
  if [ "${#EXT_NS}" -gt 40 ] || ! [[ "$EXT_NS" =~ ^t$task-[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    refuse "имя пространства «$EXT_NS» не по правилу t$task-<коротко> (не длиннее 40 знаков)"
    return 64
  fi
  if ! [[ "$EXT_TTL_HOURS" =~ ^[0-9]+$ ]] || [ "$EXT_TTL_HOURS" -lt 1 ] || [ "$EXT_TTL_HOURS" -gt 12 ]; then
    refuse "KANAME_STAND_TTL_HOURS — целое от 1 до 12, получено «$EXT_TTL_HOURS»"
    return 64
  fi
}

record_route() {
  mkdir -p "$RUNDIR"
  if [ "$ROUTE" = external ]; then
    say "маршрут стенда: внешний кластер, пространство $EXT_NS (основание: $PROOF)"
    printf '%s\t%s\t%s\t%s\t%s\n' external "$EXT_NS" "$EXT_TASK" "$EXT_CTX" "$EXT_KCFG" > "$ROUTE_FILE"
  else
    say "маршрут стенда: локальный docker (основание: $WHY${PROOF:+; $PROOF})"
    printf 'local\n' > "$ROUTE_FILE"
  fi
  printf '%s route=%s ns=%s why=%s proof=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$ROUTE" "${EXT_NS:--}" "${WHY:--}" "${PROOF:--}" >> "$ROUTE_LOG"
}

# route_load — 0, если идущий стенд поднят внешним путём (координаты — из файла
# маршрута подъёма, а не заново: снимать надо то, что подняли).
route_load() {
  local kind
  [ -f "$ROUTE_FILE" ] || return 1
  IFS=$'\t' read -r kind EXT_NS EXT_TASK EXT_CTX EXT_KCFG < "$ROUTE_FILE" || return 1
  [ "$kind" = external ] && [ -n "$EXT_NS" ]
}

# ext_mark <пространство> — метка стенда; код 3 — пространства нет, 75 — не прочитано.
ext_mark() {
  local out rc
  out="$(kc get namespace "$1" -o "jsonpath={.metadata.labels.kaname\.io/stand}" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    case "$out" in *NotFound*|*"not found"*) return 3 ;; esac
    unmet "пространство $1 не прочитано: $(printf '%s\n' "$out" | head -n 1 | mask | cut -c1-300)"
    return 75
  fi
  printf '%s' "$out"
}

# ext_claim_ns — своё пространство: заводится с метками и сроком ОДНОЙ записью
# (`create`, не `apply`: существующее чужое не перепомечается); уже заведённое
# этим стендом переиспользуется, предыдущий под снимается.
ext_claim_ns() {
  local mark rc expires
  if [ -n "$IN_POD" ]; then
    ext_clear_objects || { unmet "остаток прежнего стенда в пространстве $EXT_NS не снят"; return 75; }
    say "пространство $EXT_NS — раннера (заведено машиной): стенд ставится в нём"
    return 0
  fi
  mark="$(ext_mark "$EXT_NS")"; rc=$?
  if [ "$rc" -eq 0 ]; then
    if [ "$mark" != "$EXT_MARK" ]; then
      unmet "пространство $EXT_NS есть и заведено не этим стендом — не трогаю"
      return 75
    fi
    say "пространство $EXT_NS заведено этим стендом раньше — переподнимаю в нём"
    kc -n "$EXT_NS" delete pod "$EXT_POD" --ignore-not-found --wait=true >/dev/null 2>&1
    kc -n "$EXT_NS" delete secret kaname-own-env kaname-own-pki --ignore-not-found >/dev/null 2>&1
    kc -n "$EXT_NS" delete configmap kaname-own-mailbox --ignore-not-found >/dev/null 2>&1
    return 0
  fi
  [ "$rc" -eq 3 ] || return 75
  expires="$(date -u -d "+$EXT_TTL_HOURS hours" +%Y-%m-%dT%H:%M:%SZ)"
  kc create -f - >/dev/null 2>&1 <<EOF || { unmet "пространство $EXT_NS не заведено"; return 75; }
apiVersion: v1
kind: Namespace
metadata:
  name: $EXT_NS
  labels:
    kacho.io/task: "$EXT_TASK"
    kacho.io/stand: test
    kacho.io/repo: kaname
    kacho.io/kind: stand-own
    $EXT_MARK_LABEL: $EXT_MARK
    # Учётка раннера заводит поды в этом пространстве: привилегированного пода,
    # тома узла и сети узла среда в нём не допустит, что бы ни прислали.
    pod-security.kubernetes.io/enforce: baseline
  annotations:
    kacho.io/expires: "$expires"
EOF
  say "пространство $EXT_NS заведено (метка задачи $EXT_TASK, срок $expires)"
}

# k8s_memory — предел контейнера той же величиной, что `docker --memory`.
k8s_memory() {
  [[ "$1" =~ ^([0-9]+)([mMgG])$ ]] || return 1
  case "${BASH_REMATCH[2]}" in m|M) printf '%sMi' "${BASH_REMATCH[1]}" ;; *) printf '%sGi' "${BASH_REMATCH[1]}" ;; esac
}

# ext_put_config — посадка службы Secret-ом: каждая переменная — свой файл,
# поэтому ключи с переводом строки доезжают целыми. Пути файлов — пода.
ext_put_config() {
  local d v rc=0
  d="$(mktemp -d)" || { unmet "временный каталог посадки не создан"; return 75; }
  ( PKI="$EXT_PKI"; BIN="$EXT_BIN"; stand_env
    for v in $(compgen -e); do
      case "$v" in KANAME_STAND_*) ;; KANAME_*) printf '%s' "${!v}" > "$d/$v" ;; esac
    done ) || rc=1
  if [ "$rc" -eq 0 ]; then
    kc -n "$EXT_NS" create secret generic kaname-own-env --from-file="$d" >/dev/null 2>&1 || rc=1
  fi
  rm -rf "$d"
  [ "$rc" -eq 0 ] || { unmet "посадка службы не доехала в пространство $EXT_NS"; return 75; }
  kc -n "$EXT_NS" create secret generic kaname-own-pki \
    --from-file=ca.crt="$PKI/ca.crt" --from-file=srv.crt="$PKI/srv.crt" --from-file=srv.key="$PKI/srv.key" \
    --from-file=pg.crt="$PKI/pg.crt" --from-file=pg.key="$PKI/pg.key" >/dev/null 2>&1 || {
      unmet "листы стенда не доехали в пространство $EXT_NS"; return 75; }
  kc -n "$EXT_NS" create configmap kaname-own-mailbox --from-file=stand-mailbox.py="$HERE/stand-mailbox.py" >/dev/null 2>&1 || {
    unmet "приёмник писем не доехал в пространство $EXT_NS"; return 75; }
}

# ext_put_pod — под стенда. Посадка безопасности пода — ограниченная: не root,
# без повышения прав и без возможностей, профиль seccomp среды.
#
# База исполняется под надзирающей оболочкой: свёртка (`db-fold`) кладёт файл
# `/ctl/fold` и останавливает postgres, и оболочка не поднимает его, пока файл
# лежит; данные — в томе пода, поэтому возврат находит ту же базу. Так у
# свёртки та же семантика, что `docker stop`/`docker start` локального пути.
ext_put_pod() {
  local mem
  mem="$(k8s_memory "$SERVICE_MEMORY")" || { refuse "SERVICE_MEMORY «$SERVICE_MEMORY» — число с m или g"; return 64; }
  kc create -f - >/dev/null 2>&1 <<EOF || { unmet "под стенда не заведён в пространстве $EXT_NS"; return 75; }
apiVersion: v1
kind: Pod
metadata:
  name: $EXT_POD
  namespace: $EXT_NS
  labels: {app: $EXT_POD}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 70
    runAsGroup: 70
    fsGroup: 70
    seccompProfile: {type: RuntimeDefault}
  volumes:
    - {name: pki, secret: {secretName: kaname-own-pki, defaultMode: 288}}  # 0440: ключ базы — не шире группы
    - {name: bin, emptyDir: {}}
    - {name: pgdata, emptyDir: {}}
    - {name: ctl, emptyDir: {}}
    - {name: mailbox, configMap: {name: kaname-own-mailbox}}
  containers:
    - name: pg
      image: "$PG_IMAGE"
      command:
        - sh
        - -c
        - >-
          while :; do if [ -e /ctl/fold ]; then sleep 1; continue; fi;
          docker-entrypoint.sh postgres -c port=$PG_PORT -c listen_addresses=127.0.0.1
          -c ssl=on -c ssl_cert_file=$EXT_PKI/pg.crt -c ssl_key_file=$EXT_PKI/pg.key; sleep 1; done
      env:
        - {name: POSTGRES_USER, value: kaname}
        - {name: POSTGRES_PASSWORD, value: stand}
        - {name: POSTGRES_DB, value: kaname}
        - {name: PGDATA, value: /var/lib/postgresql/data/pgdata}
      resources: {requests: {cpu: 100m, memory: 256Mi}, limits: {memory: 512Mi}}
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: pki, mountPath: $EXT_PKI, readOnly: true}
        - {name: pgdata, mountPath: /var/lib/postgresql/data}
        - {name: ctl, mountPath: /ctl}
    - name: svc
      image: "$SERVICE_IMAGE"
      command: [sh, -c, "while [ ! -e $EXT_BIN/.start ]; do sleep 1; done; exec $EXT_BIN/kaname"]
      envFrom: [{secretRef: {name: kaname-own-env}}]
      resources: {requests: {cpu: 200m, memory: $mem}, limits: {memory: $mem}}
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: pki, mountPath: $EXT_PKI, readOnly: true}
        - {name: bin, mountPath: $EXT_BIN}
    - name: mail
      image: "$MAILBOX_IMAGE"
      command: [python3, /mbx/stand-mailbox.py, serve, --host, 127.0.0.1,
                --smtp-port, "$MAIL_SMTP_PORT", --http-port, "$MAIL_HTTP_PORT",
                --cert, $EXT_PKI/srv.crt, --key, $EXT_PKI/srv.key]
      resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {memory: 128Mi}}
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: pki, mountPath: $EXT_PKI, readOnly: true}
        - {name: mailbox, mountPath: /mbx, readOnly: true}
EOF
  say "под стенда заведён: база, служба (предел памяти $mem), приёмник писем"
}

# ext_wait_running — под исполняется, все контейнеры запущены. Не встал за
# EXT_READY_TRIES секунд, образ не скачался — условие не создано (75).
ext_wait_running() {
  local i phase ready why
  for i in $(seq 1 "$EXT_READY_TRIES"); do
    phase="$(kc -n "$EXT_NS" get pod "$EXT_POD" -o 'jsonpath={.status.phase}' 2>/dev/null)"
    ready="$(kc -n "$EXT_NS" get pod "$EXT_POD" -o 'jsonpath={.status.containerStatuses[*].ready}' 2>/dev/null)"
    why="$(kc -n "$EXT_NS" get pod "$EXT_POD" -o 'jsonpath={.status.containerStatuses[*].state.waiting.reason}' 2>/dev/null)"
    if [ "$phase" = Running ] && [ "$ready" = "true true true" ]; then
      say "под стенда исполняется: три контейнера запущены, попытка $i"
      return 0
    fi
    case "$phase $why" in
      Failed*|*ErrImagePull*|*ImagePullBackOff*|*InvalidImageName*|*CreateContainerConfigError*)
        unmet "под стенда не встал: фаза «${phase:-нет}», причина «${why:-нет}»"
        return 75 ;;
    esac
    sleep 1
  done
  unmet "под стенда не встал за $EXT_READY_TRIES с: фаза «${phase:-нет}», причина «${why:-нет}»"
  return 75
}

# ext_upload — бинари доезжают потоком и сверяются отпечатком: под исполняет
# ровно то, что собрано здесь.
ext_upload() {
  local f want got
  for f in kaname kaname-migrator; do
    # shellcheck disable=SC2016  # $1 и $2 раскрывает оболочка пода
    ks -n "$EXT_NS" exec -i "$EXT_POD" -c svc -- sh -c \
      'cat > "$1/.part" && chmod 0755 "$1/.part" && mv "$1/.part" "$1/$2"' sh "$EXT_BIN" "$f" \
      < "$BIN/$f" >/dev/null 2>&1 || { unmet "бинарь $f не доехал в под"; return 75; }
    want="$(sha256sum "$BIN/$f" | cut -d' ' -f1)"
    got="$(ks -n "$EXT_NS" exec "$EXT_POD" -c svc -- sha256sum "$EXT_BIN/$f" 2>/dev/null | cut -d' ' -f1)"
    [ -n "$want" ] && [ "$want" = "$got" ] || { unmet "отпечаток бинаря $f в поде не совпал с собранным"; return 75; }
  done
  say "бинари доехали в под, отпечатки совпали: kaname, kaname-migrator"
  if [ "$REGISTRY_WORLD" = 1 ]; then
    ks -n "$EXT_NS" exec -i "$EXT_POD" -c svc -- sh -c \
      'mkdir -p "$1/manifests" && cat > "$1/manifests/registry.yaml"' sh "$EXT_BIN" \
      < "$BIN/manifests/registry.yaml" || return 75
    want="$(sha256sum "$BIN/manifests/registry.yaml" | cut -d' ' -f1)"
    got="$(ks -n "$EXT_NS" exec "$EXT_POD" -c svc -- sha256sum "$EXT_BIN/manifests/registry.yaml" | cut -d' ' -f1)"
    [ -n "$want" ] && [ "$want" = "$got" ] || { unmet "манифест registry не совпал с доставленным"; return 75; }
    say "манифест registry доставлен, отпечаток совпал: $want"
  fi
}

ext_pg_isready() {
  ks -n "$EXT_NS" exec "$EXT_POD" -c pg -- pg_isready -h 127.0.0.1 -p "$PG_PORT" -U kaname >/dev/null 2>&1
}

ext_pg_ready() {
  local i
  for i in $(seq 1 "$DB_READY_TRIES"); do
    if ext_pg_isready; then
      say "база пода поднята и принимает соединения (шифрование включено), попытка $i"
      return 0
    fi
    sleep 1
  done
  unmet "база пода не ответила pg_isready за $DB_READY_TRIES с"
  kc -n "$EXT_NS" logs "$EXT_POD" -c pg --tail=20 2>&1 | mask >&2
  return 75
}

# ext_migrate — тот же `migrate`: класс отказа называет накат своим кодом, а
# kubectl exec отдаёт код процесса пода. Свой отказ kubectl (под недостижим) —
# не накат, поэтому достижимость проверяется до него.
ext_migrate() {
  ks -n "$EXT_NS" exec "$EXT_POD" -c svc -- true >/dev/null 2>&1 || {
    unmet "контейнер службы пода недостижим для exec — накат не начинался"; return 75; }
  ( BIN="$EXT_BIN"; MIGRATOR_RUN=(ks -n "$EXT_NS" exec "$EXT_POD" -c svc --); migrate )
}

ext_save_log() {
  mkdir -p "$RUNDIR"
  kc -n "$EXT_NS" logs "$EXT_POD" -c svc > "$RUNDIR/kaname.log.part" 2>/dev/null \
    && mv -f "$RUNDIR/kaname.log.part" "$RUNDIR/kaname.log"
  rm -f "$RUNDIR/kaname.log.part"
}

# listening_in <таблица сокетов> <порт> — порт в состоянии LISTEN (0A).
listening_in() {
  local hex
  hex="$(printf '%04X' "$2")"
  grep -Eq "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A " <<< "$1"
}

ext_tcp_table() { ks -n "$EXT_NS" exec "$EXT_POD" -c svc -- cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; }

ext_listeners_up() {
  local tcp p
  tcp="$(ext_tcp_table)"
  for p in $PORTS; do listening_in "$tcp" "$p" || return 1; done
}

ext_listeners_report() {
  local tcp p
  tcp="$(ext_tcp_table)"
  for p in $PORTS; do
    if listening_in "$tcp" "$p"; then printf '  :%s слушает\n' "$p"; else printf '  :%s НЕ слушает\n' "$p"; fi
  done
}

# ext_start_service — отказ старта (контейнер службы завершился) — НАХОДКА, как
# у локального пути; готовность — по таблице сокетов пода.
ext_start_service() {
  local i code
  ks -n "$EXT_NS" exec "$EXT_POD" -c svc -- touch "$EXT_BIN/.start" >/dev/null 2>&1 || {
    unmet "службу пода не запустить: exec отказал"; return 75; }
  for i in $(seq 1 "$SERVICE_TRIES"); do
    code="$(kc -n "$EXT_NS" get pod "$EXT_POD" -o 'jsonpath={.status.containerStatuses[?(@.name=="svc")].state.terminated.exitCode}' 2>/dev/null)"
    if [ -n "$code" ]; then
      ext_save_log
      fail "служба не поднялась (код $code); последняя строка журнала:"
      tail -3 "$RUNDIR/kaname.log" >&2
      return 1
    fi
    if ext_listeners_up; then
      say "служба поднята: все $(ports_count) слушателей отвечают в поде, попытка $i"
      return 0
    fi
    sleep 1
  done
  fail "служба жива, но за $SERVICE_TRIES с подняла не все слушатели"
  ext_listeners_report >&2
  return 1
}

# ext_unforward — сначала снимается отметка (держатели перестают перезапускать),
# затем каждый держатель — группой: держатель и его kubectl. Номера групп — из
# файла, который пишет только ext_forward; чужих процессов он не называет.
ext_unforward() {
  local pg
  rm -f "$FORWARD_ON"
  if [ -f "$FORWARD_PID" ]; then
    while read -r pg; do
      [ -n "$pg" ] && kill -- "-$pg" 2>/dev/null
    done < "$FORWARD_PID"
    rm -f "$FORWARD_PID"
  fi
}

# ext_forward_keep ПОРТ — держатель проброса одного порта: пока стоит отметка
# FORWARD_ON, вышедший kubectl поднимается заново.
#
# ПОЧЕМУ ПО ПОРТУ И С ПЕРЕЗАПУСКОМ (kaname#869). Проброс был один на все порты, а
# проверка службы (`stand-assert.py`, «рукопожатие без сертификата») НАМЕРЕННО
# рвёт соединение отказом взаимного TLS. Сброс одного потока завершает весь
# `kubectl port-forward`, и все следующие запросы на любой порт получали «код
# None, тело ''» — находки о стенде, а не о службе (2 прогона из 3). Теперь отказ
# рукопожатия гасит проброс ТОЛЬКО своего порта, и держатель его поднимает;
# окно перезапуска покрывает ожидание слушателя у самой проверки.
# shellcheck disable=SC2329  # зовётся телом держателя в своей сессии (ext_forward)
ext_forward_keep() {
  local p="$1"
  while [ -f "$FORWARD_ON" ]; do
    kubectl --kubeconfig "$EXT_KCFG" --context "$EXT_CTX" -n "$EXT_NS" port-forward \
      --address 127.0.0.1 "pod/$EXT_POD" "$p" >> "$FORWARD_LOG" 2>&1 < /dev/null
    [ -f "$FORWARD_ON" ] || break
    printf 'проброс :%s завершился — поднимаю заново\n' "$p" >> "$FORWARD_LOG"
    sleep 0.5
  done
}

# ext_forward — слушатели службы и чтение писем на 127.0.0.1 машины теми же
# номерами, каждый порт — своим держателем (ext_forward_keep). Готовность пода уже
# доказана таблицей сокетов: проброс принимает соединение и без слушателя за ним,
# поэтому здесь судится только сам проброс.
ext_forward() {
  local i p up
  ext_unforward
  : > "$FORWARD_LOG"
  : > "$FORWARD_PID"
  touch "$FORWARD_ON"
  for p in $PORTS $MAIL_HTTP_PORT; do
    # Своя сессия — своя группа процессов: снятие гасит держателя вместе с его
    # kubectl одним сигналом группе.
    # shellcheck disable=SC2016  # тело держателя раскрывает свои аргументы само
    setsid bash -c "$(declare -f ext_forward_keep)"'; FORWARD_ON="$1" FORWARD_LOG="$2" EXT_KCFG="$3" EXT_CTX="$4" EXT_NS="$5" EXT_POD="$6" ext_forward_keep "$7"' \
      _ "$FORWARD_ON" "$FORWARD_LOG" "$EXT_KCFG" "$EXT_CTX" "$EXT_NS" "$EXT_POD" "$p" < /dev/null > /dev/null 2>&1 &
    echo $! >> "$FORWARD_PID"
  done
  for i in $(seq 1 30); do
    up=1
    for p in $PORTS $MAIL_HTTP_PORT; do
      (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || { up=0; break; }
    done
    if [ "$up" -eq 1 ]; then
      say "проброс поднят: держателей по порту $(wc -l < "$FORWARD_PID"), слушатели службы и чтение писем на 127.0.0.1 машины, попытка $i"
      return 0
    fi
    sleep 1
  done
  unmet "проброс слушателей пода на машину не поднялся: $(tail -n 2 "$FORWARD_LOG" 2>/dev/null | mask | tr '\n' ' ')"
  return 75
}

# ext_teardown_ns — снимается только помеченное этим стендом.
ext_teardown_ns() {
  local mark rc
  if [ -n "$IN_POD" ]; then
    ext_clear_objects || { unmet "объекты стенда в пространстве $EXT_NS не сняты — их снимет снос пространства машиной"; return 75; }
    say "объекты стенда в пространстве $EXT_NS сняты; пространство снимает раннер машины"
    return 0
  fi
  mark="$(ext_mark "$EXT_NS")"; rc=$?
  if [ "$rc" -eq 3 ]; then say "пространства $EXT_NS нет — снимать нечего"; return 0; fi
  [ "$rc" -eq 0 ] || return 75
  if [ "$mark" != "$EXT_MARK" ]; then
    unmet "пространство $EXT_NS заведено не этим стендом — не снимаю"
    return 75
  fi
  kc delete namespace "$EXT_NS" --wait=true --timeout=300s >/dev/null 2>&1 || {
    unmet "пространство $EXT_NS не снято за 300 с — его срок поймает перепись"; return 75; }
  say "пространство $EXT_NS снято"
}

ext_down() {
  ext_unforward
  ext_save_log
  ext_teardown_ns
}

# ext_census — перепись помеченных пространств задачи; остаток — число, не ноль — 1.
ext_census() {
  local out rc n
  if [ -n "$IN_POD" ]; then
    out="$(kc -n "$EXT_NS" get pod "$EXT_POD" --ignore-not-found -o name 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
      unmet "перепись пода стенда не прочитана: $(printf '%s\n' "$out" | head -n 1 | mask | cut -c1-300)"
      return 75
    fi
    n="$(grep -c '^pod/' <<< "$out")"
    say "перепись: подов стенда own в пространстве раннера $EXT_NS: $n"
    [ "$n" -eq 0 ]
    return
  fi
  out="$(kc get namespaces -l "kacho.io/repo=kaname,$EXT_MARK_LABEL=$EXT_MARK,kacho.io/task=$EXT_TASK" -o name 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    unmet "перепись пространств не прочитана: $(printf '%s\n' "$out" | head -n 1 | mask | cut -c1-300)"
    return 75
  fi
  n="$(grep -c '^namespace/' <<< "$out")"
  say "перепись: стендов own задачи $EXT_TASK во внешнем кластере: $n"
  [ "$n" -eq 0 ]
}

# ext_abort — подъём не дошёл до конца: журнал службы сохраняется, созданное
# снимается тем же вызовом.
# shellcheck disable=SC2329  # зовётся ловушкой EXIT в ext_up
ext_abort() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ]; then
    say "подъём во внешнем кластере не завершён (код $rc) — снимаю созданное"
    ext_down || true
  fi
  exit "$rc"
}

ext_up() {
  local rc
  ext_claim_ns || return $?
  trap ext_abort EXIT
  ext_put_config || exit $?
  ext_put_pod || exit $?
  ext_wait_running || exit $?
  ext_upload || exit $?
  ext_pg_ready || exit $?
  ext_migrate; rc=$?
  [ "$rc" -eq 0 ] || exit "$rc"
  ext_start_service || exit $?
  ext_forward || exit $?
  trap - EXIT
}

up_local() {
  make_pki; registry_world_prepare || return $?
  start_pg; start_mailbox; stand_env; build_binaries; migrate; start_service
  say "===== стенд поднят: своя база + свой УЦ, без платформы и без поставщика ====="
  listeners_report
}

up_external() {
  need_tool kubectl
  make_pki; registry_world_prepare || return $?
  build_binaries; ext_up
  say "===== стенд поднят во внешнем кластере ($EXT_NS): своя база + свой УЦ, без платформы и без поставщика ====="
  ext_listeners_report
}

stand_up() {
  local rc=0
  say "===== автономный стенд службы: подъём ====="
  need_tool openssl
  route_decide || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  if [ "$ROUTE" = external ]; then
    ext_name_ns || return $?
  fi
  record_route
  if [ "$ROUTE" = external ]; then up_external; else up_local; fi
}

stand_down() {
  local rc=0
  if route_load; then
    ext_down || rc=$?
    ext_census || rc=$(( rc == 0 ? 1 : rc ))
    [ "$rc" -eq 0 ] && rm -f "$ROUTE_FILE"
    return "$rc"
  fi
  down
}

db_fold_routed() { if route_load; then ext_fold; else fold_db; fi; }
db_unfold_routed() { if route_load; then ext_unfold; else unfold_db; fi; }

# Свёртка внешнего пути: исходы те же, что у `fold_db` — не вышло остановить
# либо база всё ещё принимает соединения — 75.
ext_fold() {
  # shellcheck disable=SC2016  # $PGDATA — окружение контейнера базы
  ks -n "$EXT_NS" exec "$EXT_POD" -c pg -- sh -c 'touch /ctl/fold && pg_ctl -D "$PGDATA" stop -m fast' >/dev/null 2>&1 || {
    unmet "базу стенда не свернуть: postgres пода не остановлен"; exit "$RC_UNMET"; }
  if ext_pg_isready; then
    unmet "базу стенда не свернуть: база пода по-прежнему принимает соединения"
    exit "$RC_UNMET"
  fi
  say "база стенда свёрнута: postgres пода остановлен, служба оставлена жить"
}

ext_unfold() {
  local i
  ks -n "$EXT_NS" exec "$EXT_POD" -c pg -- rm -f /ctl/fold >/dev/null 2>&1 || {
    unmet "базу стенда не вернуть: отметка свёртки в поде не снята"; exit "$RC_UNMET"; }
  for i in $(seq 1 "$DB_READY_TRIES"); do
    if ext_pg_isready; then
      say "база стенда возвращена и принимает соединения, попытка $i"
      return 0
    fi
    sleep 1
  done
  unmet "база стенда не ответила pg_isready за $DB_READY_TRIES с после возврата"
  exit "$RC_UNMET"
}

# ─── РАННЕР: НАБОРЫ В POD СВОЕГО ПРОСТРАНСТВА ВНЕШНЕГО КЛАСТЕРА (kaname#940) ──
#
# Решение владельца 2026-10-22 (kacho-workspace#1301) дословно: «запиши в рул что бы
# не использовал мою локальную тачку. использовать только в одном случае если доступа
# к кластеру нету». Внешний путь выше ставит стенд во внешний кластер, но собирает
# бинари и гонит наборы ПРОЦЕССОМ МАШИНЫ. `runner` уносит туда и это, по образцу
# раннера платформы (PRO-Robotech/kacho#3346); на машине — kubectl, git, tar и gzip:
#
#   stand-own.sh runner [--out КАТАЛОГ] [--ship ФАЙЛ]… -- КОМАНДА…
#
#   пространство  t<задача>-kaname-own (KANAME_STAND_EXT_NS, KANAME_STAND_TASK — как у
#                 внешнего пути) заводит машина тем же ext_claim_ns ПОСЛЕ доказательства
#                 кластера (route_decide: контекст -client, узлы профиля, право завести
#                 пространство); уже существующее — отказ 1: прогон заводит своё и его же
#                 снимает; кластер недоступен — 125, локального подъёма раннер не делает;
#   pod и учётка  `kaname-runner`; роль — ТОЛЬКО в своём пространстве: поды (завести,
#                 снять, прочитать), exec и проброс, журнал, секреты и карты конфигурации
#                 стенда, события. Форму судит runner_judge ДО записи в кластер; пространство
#                 несёт посадку pod `baseline` — привилегированного пода учётка не заведёт;
#   образ         golang версии `toolchain` из go.mod ревизии (ту же ставит конвейеру
#                 setup-go; тот же образ — у Job тяжёлых прогонов); поверх — apt (python3, pyyaml, cryptography, venv, pip, jq,
#                 openssl), node мажорной версии KANAME_STAND_RUNNER_NODE (умолчание 20 —
#                 её несёт ранер конвейера, дерево версии node не объявляет) выпуском с
#                 суммой из SHASUMS256 того же выпуска, kubectl — клиент машины потоком
#                 либо версия сервера кластера с суммой; не поставлено — 125 с именем;
#   исходники     `git archive` головы рабочей копии потоком в /src, дерево — репозиторием
#                 git (наборы читают состав индексом); правка вне коммита — отказ 64 до
#                 первой записи; --ship — файлы машины в /work/ship (исполнитель шагов
#                 задания конвейера и т. п.), отпечаток каждого сверяется;
#   стенд         команда поднимает его сама тем же stand-own.sh: pod несёт
#                 KANAME_STAND_IN_POD=1 (раздел «СТЕНД ИЗНУТРИ POD РАННЕРА» выше);
#   трекер        удостоверений площадки в pod НЕТ: `gh` pod — лишь чтение публичного
#                 REST (`gh api repos/… [--jq …]`), прочее — отказ с объяснением;
#   отчёты        команда пишет их в /work/out; машина забирает RUNNER_GLOBS (без venv,
#                 без ключей стенда, без невычищенных отчётов newman) в --out со сверкой:
#                 перечень «размер сумма путь» собран в pod до передачи, каждый путь
#                 сверен на машине; неполная доставка — повтор ЛИШЬ недоставленного, пока
#                 попытка прибавляет файлы (поток exec рвётся на одном и том же месте:
#                 95 из 121 трижды подряд, kaname#1026); KANAME_STAND_RUNNER_FETCH_TRIES
#                 попыток подряд без прибавки — конец, перечень недоставленного;
#   код           код КОМАНДЫ; 125 — команда не исполнялась (кластер недоступен, образ не
#                 встал, инструменты не поставились, pod исчез); 76 — команда исполнилась,
#                 а её отчёты не доставлены целиком (в выводе — доставлено из скольких, код
#                 команды, последняя строка отказа забора); оба — «не выполнилось», а не красное;
#   снятие        пространство снимается ВСЕГДА (успех, падение, сигнал; SIGKILL — сроком
#                 kacho.io/expires), затем перепись пространств задачи; ненулевой остаток
#                 при коде 0 команды — код 1.
# Срок pod — KANAME_STAND_RUNNER_DEADLINE (с, умолчание 10800), готовности — 600 с.
# ГРАНИЦА: инструменты ставятся из сети на каждом прогоне (apt, node, npm) — минуты;
# образ раннера с ними — отдельный предмет.
# Вид раннера — признак механизма для маршрута слота воркспейса (heavy-slot.sh читает строку).
# shellcheck disable=SC2034  # читается снаружи, текстом файла
STAND_RUNNER_KINDS="own"
RUNNER_POD=kaname-runner
RUNNER_DEADLINE="${KANAME_STAND_RUNNER_DEADLINE:-10800}"
RUNNER_NODE="${KANAME_STAND_RUNNER_NODE:-20}"
RUNNER_UNMET=125
RUNNER_FETCH_SHORT=76
RUNNER_FETCH_N=0 RUNNER_FETCH_M="?" RUNNER_FETCH_WHY=""
# Корень и рабочий каталог pod — переменными ради самопроверки забора: она исполняет те
# же тексты на каталогах-фикстурах.
RUNNER_ROOT=/
RUNNER_WORK=/work
RUNNER_GLOBS='work/out/*.json work/out/*.md work/out/step-*.log work/out/artifacts src/tests/newman/out-public src/.stand/log-public'
RUNNER_OUT="" RUNNER_LOGS="" RUNNER_UP=0
RUNNER_SHIP=()

# Текст pod: `gh` без удостоверения — чтение публичного REST. Тихий успех на иной
# форме спрятал бы, что трекер не спрошен: прочее — код 4 с объяснением.
read -r -d '' RUNNER_GH_SH <<'POD'
#!/usr/bin/env bash
set -uo pipefail
if [ "${1:-}" = api ] && [[ "${2:-}" =~ ^repos/[A-Za-z0-9_./-]+$ ]] && [[ "$2" != *..* ]]; then
  path="$2"; shift 2; expr=.
  if [ $# -eq 2 ] && [ "$1" = --jq ]; then expr="$2"; shift 2; fi
  if [ $# -eq 0 ]; then
    # Ответ, прочитанный машиной (`gh api` её учёткой) и доставленный файлом `--ship
    # gh-read.json` ({путь: тело}): удостоверение в pod не попадает, лимит анонимного
    # REST на общий адрес кластера не тратится. Пути нет в файле — публичное чтение.
    cache=/work/ship/gh-read.json
    if [ -f "$cache" ] && jq -e --arg p "$path" 'has($p)' "$cache" > /dev/null 2>&1; then
      jq -r --arg p "$path" ".[\$p] | $expr" "$cache"
      exit
    fi
    body="$(curl -fsS --retry 3 --max-time 60 -H 'Accept: application/vnd.github+json' "https://api.github.com/$path")" || exit 1
    jq -r "$expr" <<< "$body"
    exit
  fi
fi
echo "gh раннера: «$*» — лишь «gh api repos/… [--jq …]» чтением публичного REST без удостоверения" >&2
exit 4
POD

# Текст pod. Ждёт исходники (/work/.go), ставит инструменты, исполняет команду в /src,
# пишет атомарный итог «стадия код» в /work/.rc и ждёт забора отчётов (/work/.fetched).
read -r -d '' RUNNER_POD_SH <<'POD'
set -uo pipefail
unset KUBECONFIG
say() { printf '=== kaname-runner: %s\n' "$*"; }
# Срок ожидания забора — 600 с от последнего признака забора, а не от кода: пока жив tar
# текущей попытки (/work/.fetching.pid), pod не выходит и поток не рвётся посередине.
fetched() {
  local last now p
  last="$(date +%s)"
  while [ ! -e /work/.fetched ]; do
    now="$(date +%s)"
    p="$(cat /work/.fetching.pid 2>/dev/null)"
    [ -z "$p" ] || [ ! -e "/proc/$p" ] || last="$now"
    [ $((now - last)) -lt 600 ] || { say "отчёты не забраны за 600 с после последней попытки забора — pod выходит"; return 0; }
    sleep 2
  done
}
# Одна атомарная запись связывает код со стадией: «setup 125» не выдаёт себя за
# исполненную команду с кодом 125, даже если pod станет недоступен при заборе отчётов.
finish() { printf '%s %s\n' "$1" "$2" > /work/.rc.tmp && mv /work/.rc.tmp /work/.rc; fetched; exit "$2"; }
unmet() { say "УСЛОВИЕ НЕ СОЗДАНО: $* — команда НЕ исполнялась (125)"; finish setup 125; }
mkdir -p "$HOME" /work/out /work/ship /work/bin
for _ in $(seq 1 300); do [ -e /work/.go ] && break; sleep 2; done
[ -e /work/.go ] || { say "исходники не доставлены за 600 с"; exit 125; }
case "$(uname -m)" in x86_64) ka=amd64 na=x64 ;; aarch64) ka=arm64 na=arm64 ;; *) unmet "архитектура $(uname -m)" ;; esac
export DEBIAN_FRONTEND=noninteractive
say "инструменты: apt"
{ apt-get update -q && apt-get install -y -q --no-install-recommends ca-certificates curl git jq openssl tar gzip xz-utils procps \
    python3 python3-yaml python3-venv python3-pip python3-cryptography; } > /work/apt.log 2>&1 || { tail -n 5 /work/apt.log; unmet "apt-get"; }
if [ -x /work/bin/kubectl ] && /work/bin/kubectl version --client > /dev/null 2>&1; then
  install -m 0755 /work/bin/kubectl /usr/local/bin/kubectl || unmet "kubectl машины не поставлен"
  say "инструменты: kubectl — клиент машины ($(kubectl version --client 2>/dev/null | head -n 1))"
else
  say "инструменты: kubectl $RUNNER_KUBECTL — загрузкой"
  ku="https://dl.k8s.io/release/$RUNNER_KUBECTL/bin/linux/$ka/kubectl"
  { curl -fsSL --retry 3 --speed-limit 200000 --speed-time 60 -o /usr/local/bin/kubectl "$ku" &&
    echo "$(curl -fsSL --retry 3 --max-time 60 "$ku.sha256")  /usr/local/bin/kubectl" | sha256sum -c --quiet - &&
    chmod +x /usr/local/bin/kubectl; } || unmet "kubectl $RUNNER_KUBECTL не получен либо сумма не сошлась"
fi
nb="https://nodejs.org/dist/latest-v$RUNNER_NODE.x"
sums="$(curl -fsSL --retry 3 --max-time 60 "$nb/SHASUMS256.txt")" || unmet "node $RUNNER_NODE: перечень сумм выпуска не получен"
line="$(grep -E "^[0-9a-f]{64}  node-v[0-9]+\.[0-9]+\.[0-9]+-linux-$na\.tar\.xz\$" <<< "$sums")"
[ "$(grep -c . <<< "$line")" -eq 1 ] || unmet "node $RUNNER_NODE: в перечне сумм не ровно один выпуск linux-$na"
nf="${line##* }"
{ curl -fsSL --retry 3 --speed-limit 50000 --speed-time 60 -o "/work/$nf" "$nb/$nf" &&
  ( cd /work && sha256sum -c --quiet --strict - <<< "$line" ) &&
  tar -xJ -C /usr/local --strip-components=1 -f "/work/$nf" && rm -f "/work/$nf"; } ||
  unmet "node $RUNNER_NODE: выпуск $nf не получен, сумма не сошлась либо он не распакован"
say "инструменты: node $(node --version), npm $(npm --version)"
[ "$(go env GOVERSION)" = "go$RUNNER_GO" ] || unmet "go образа $(go env GOVERSION), а дерево требует go$RUNNER_GO"
say "инструменты: $(go version)"
{ printf '%s\n' "$RUNNER_GH_SH" > /usr/local/bin/gh && chmod 0755 /usr/local/bin/gh; } || unmet "gh раннера не поставлен"
say "инструменты: gh — чтение публичного REST без удостоверения"
say "исходники $RUNNER_SHA — репозиторием git (наборы читают состав индексом)"
( cd /src && git init -q && git remote add origin "https://github.com/$RUNNER_REPO.git" && git add -A &&
  git -c user.name=kaname-runner -c user.email=kaname-runner@kaname.invalid commit -q -m "kaname-runner: исходники $RUNNER_SHA" ) > /work/git.log 2>&1 ||
  { tail -n 5 /work/git.log; unmet "дерево исходников не стало репозиторием git"; }
cd /src || unmet "каталог исходников /src"
say "команда: $RUNNER_CMD"
bash -c "$RUNNER_CMD"; rc=$?
say "команда завершилась кодом $rc"
finish command "$rc"
POD

# Текст pod: перечень отчётов «размер сумма путь» — то, что машина обязана получить.
# Собирается ДО передачи из файлов по шаблонам (раскрывает оболочка pod); тот же состав
# (NUL-разделённый) — вход tar следующего шага. Аргументы: КОРЕНЬ РАБОЧИЙ ШАБЛОН…
read -r -d '' RUNNER_MANIFEST_SH <<'POD'
set -uo pipefail
src="$1" work="$2"; shift 2
cd "$src" || exit 1
shopt -s globstar nullglob
pats=("$@"); set --
# Шаблон без подстановочных знаков nullglob не убирает: несуществующий путь (каталог
# отчёта шага, который не дошёл до выкладывания) — не отчёт, и find на нём вышел бы
# кодом 1, а забор — 125 при коде команды 0 (kaname#940).
for g in "${pats[@]}"; do for p in $g; do [ -e "$p" ] || [ -L "$p" ] || continue; set -- "$@" "$p"; done; done
{ [ $# -eq 0 ] || find "$@" -type f -print0; } | sort -zu > "$work/.fetch.files0" || exit 1
: > "$work/.manifest" || exit 1
while IFS= read -r -d '' f; do
  case "$f" in *$'\n'*) printf 'путь отчёта с переводом строки — перечнем не выразим: %q\n' "$f" >&2; exit 1 ;; esac
  printf '%s %s %s\n' "$(stat -c %s -- "$f")" "$(sha256sum < "$f" | cut -d' ' -f1)" "$f" >> "$work/.manifest" || exit 1
done < "$work/.fetch.files0"
cat "$work/.manifest"
POD

# Текст pod: поток tar состава перечня. Третий аргумент — номера его путей (с 1, через
# запятую), которые машине ещё не доставлены; пусто — все. Номера, а не пути: доводы exec
# идут адресом запроса к API, и путь в них — лишняя длина и лишний разбор. Номер
# процесса — признак «забор идёт».
read -r -d '' RUNNER_TAR_SH <<'POD'
cd "$1" || exit 1
echo $$ > "$2/.fetching.pid"
[ -n "${3:-}" ] || exec tar -c --null --verbatim-files-from -T "$2/.fetch.files0"
declare -A want=(); IFS=, read -r -a ix <<< "$3"
for k in "${ix[@]}"; do [[ "$k" =~ ^[1-9][0-9]*$ ]] || exit 1; want[$k]=1; done
i=0
while IFS= read -r -d '' p; do i=$((i + 1)); [ -z "${want[$i]:-}" ] || printf '%s\0' "$p"; done < "$2/.fetch.files0" > "$2/.fetch.again0" || exit 1
exec tar -c --null --verbatim-files-from -T "$2/.fetch.again0"
POD

runner_warn() { printf 'раннер: %s\n' "$*" >&2; }

# runner_go РЕВИЗИЯ — версия go из go.mod ревизии: `toolchain goX.Y.Z`, иначе `go X.Y.Z`.
runner_go() {
  local mod v
  mod="$(git -C "$ROOT" show "$1:go.mod" 2>/dev/null)" || { runner_warn "go.mod ревизии $1 не прочитан"; return 1; }
  v="$(sed -n 's/^toolchain go\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p' <<< "$mod")"
  [ -n "$v" ] || v="$(sed -n 's/^go \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p' <<< "$mod")"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { runner_warn "go.mod ревизии $1 не называет версию go X.Y.Z (toolchain либо go)"; return 1; }
  printf '%s\n' "$v"
}

# Тот же образ, что у Job тяжёлых прогонов внешнего кластера (golang версии toolchain).
runner_image() { printf 'docker.io/library/golang:%s' "$1"; }

# runner_exec ПРОСТРАНСТВО АРГУМЕНТЫ… — исполнить в pod раннера. Самопроверка подменяет её.
runner_exec() { local ns="$1"; shift; ks -n "$ns" exec "$RUNNER_POD" -c run -- "$@"; }

# runner_fetch ПРОСТРАНСТВО КАТАЛОГ — отчёты из pod со сверкой полноты. Перечень собран в
# pod до передачи; после каждой попытки каждый его путь сверяется по размеру и сумме.
# Неполная доставка — повтор ЛИШЬ недоставленного: поток exec рвётся на одном и том же месте,
# и повтор всего состава упирался в тот же обрыв (95 из 121 трижды, kaname#1026). Попытки идут,
# пока прибавляют файлы; KANAME_STAND_RUNNER_FETCH_TRIES (умолчание 3) подряд без прибавки —
# код 1 и перечень недоставленного. Исход печатается всегда: «доставлено N из M»; для
# вызывающего — RUNNER_FETCH_N, RUNNER_FETCH_M и RUNNER_FETCH_WHY (последняя строка отказа).
runner_fetch() {
  local ns="$1" out="$2" tries="${KANAME_STAND_RUNNER_FETCH_TRIES:-3}" man line path f size sum try=0 idle=0 prev k n=0 m=0 prc xrc
  local -a globs lost=() again=() st
  RUNNER_FETCH_N=0 RUNNER_FETCH_M="?" RUNNER_FETCH_WHY=""
  [[ "$tries" =~ ^[1-9][0-9]?$ ]] || { RUNNER_FETCH_WHY="KANAME_STAND_RUNNER_FETCH_TRIES=«$tries» — не число 1..99"; runner_warn "$RUNNER_FETCH_WHY"; return 1; }
  man="$out/.manifest"
  read -r -a globs <<< "$RUNNER_GLOBS"
  runner_exec "$ns" bash -c "$RUNNER_MANIFEST_SH" manifest "$RUNNER_ROOT" "$RUNNER_WORK" "${globs[@]}" > "$man" ||
    { RUNNER_FETCH_WHY="перечень отчётов в pod не собран — доставку сверить не с чем"; runner_warn "$RUNNER_FETCH_WHY"; return 1; }
  while IFS= read -r line; do
    [[ "$line" =~ ^[0-9]+\ [0-9a-f]{64}\ .+$ ]] || { RUNNER_FETCH_WHY="перечень pod не в форме «размер сумма путь»: «$line»"; runner_warn "$RUNNER_FETCH_WHY"; return 1; }
    path="${line#* * }"
    case "/$path/" in //*|*/../*) RUNNER_FETCH_WHY="путь перечня pod вне каталога отчётов: «$path»"; runner_warn "$RUNNER_FETCH_WHY"; return 1 ;; esac
    m=$((m + 1))
  done < "$man"
  RUNNER_FETCH_M="$m"
  : > "$out/.fetched.list"
  if [ "$m" -eq 0 ]; then
    say "отчёты раннера: в pod файлов по шаблонам $RUNNER_GLOBS — 0, доставлено 0 из 0"
    return 0
  fi
  while :; do
    try=$((try + 1)); prev="$n"
    # Недоставленное прежней попытки (в первой — ничего) снимается: обрыв оставляет обрезок.
    for path in "${lost[@]}"; do rm -f -- "$out/$path"; done
    runner_exec "$ns" bash -c "$RUNNER_TAR_SH" fetch "$RUNNER_ROOT" "$RUNNER_WORK" "$(IFS=,; printf '%s' "${again[*]}")" | tar -x -C "$out" 2> "$out/.fetch.err"
    st=("${PIPESTATUS[@]}"); prc="${st[0]}"; xrc="${st[1]}"
    n=0; k=0; lost=(); again=(); : > "$out/.fetched.list"
    while IFS= read -r line; do
      k=$((k + 1)); read -r size sum _ <<< "$line"; path="${line#* * }"; f="$out/$path"
      if [ -f "$f" ] && [ ! -L "$f" ] && [ "$(stat -c %s -- "$f")" = "$size" ] && [ "$(sha256sum < "$f" | cut -d' ' -f1)" = "$sum" ]; then
        n=$((n + 1)); printf '%s\n' "$path" >> "$out/.fetched.list"
      else
        lost+=("$path"); again+=("$k")
      fi
    done < "$man"
    RUNNER_FETCH_N="$n"
    if [ "$n" -eq "$m" ]; then
      say "отчёты раннера: доставлено $n из $m (размер и сумма каждого сверены с перечнем pod; попыток $try) в $out"
      return 0
    fi
    if [ "$n" -gt "$prev" ]; then idle=0; else idle=$((idle + 1)); fi
    RUNNER_FETCH_WHY="$(tail -n 1 "$out/.fetch.err")"
    runner_warn "отчёты: попытка $try — доставлено $n из $m (код tar в pod $prc, на машине $xrc: ${RUNNER_FETCH_WHY:-—})$([ "$idle" -lt "$tries" ] && printf ' — повтор недоставленного (%s)' "${#lost[@]}")"
    [ "$idle" -lt "$tries" ] || break
  done
  runner_warn "ОТЧЁТЫ ДОСТАВЛЕНЫ НЕПОЛНО: $n из $m после $try попыток, из них $tries подряд без прибавки; недоставлено либо расходится с перечнем pod (${#lost[@]}):"
  printf '  %s\n' "${lost[@]}" >&2
  return 1
}

# runner_objects ПРОСТРАНСТВО ОБРАЗ РЕВИЗИЯ ЗАДАЧА KUBECTL GO КОМАНДА РЕПОЗИТОРИЙ — учётка,
# роль, привязка и pod раннера (список JSON для kubectl apply). Всё — в ПРОСТРАНСТВЕ.
runner_objects() {
  jq -n --arg ns "$1" --arg image "$2" --arg sha "$3" --arg task "$4" --arg kver "$5" --arg go "$6" \
    --arg cmd "$7" --arg repo "$8" --arg node "$RUNNER_NODE" --arg sh "$RUNNER_POD_SH" --arg gh "$RUNNER_GH_SH" \
    --arg name "$RUNNER_POD" --argjson deadline "$RUNNER_DEADLINE" '
    def meta: {name: $name, namespace: $ns, labels: {"kaname.io/stand": "runner", "app.kubernetes.io/name": $name}};
    def env($n; $v): {name: $n, value: $v};
    {apiVersion: "v1", kind: "List", items: [
      {apiVersion: "v1", kind: "ServiceAccount", metadata: meta},
      {apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", metadata: meta, rules: [
        {apiGroups: [""], resources: ["pods"], verbs: ["get", "list", "watch", "create", "delete"]},
        {apiGroups: [""], resources: ["pods/exec", "pods/portforward"], verbs: ["get", "create"]},
        {apiGroups: [""], resources: ["pods/log"], verbs: ["get"]},
        {apiGroups: [""], resources: ["secrets", "configmaps"], verbs: ["get", "create", "delete"]},
        {apiGroups: [""], resources: ["events"], verbs: ["get", "list", "watch"]}]},
      {apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: meta,
        roleRef: {apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: $name},
        subjects: [{kind: "ServiceAccount", name: $name, namespace: $ns}]},
      {apiVersion: "v1", kind: "Pod", metadata: meta, spec: {
        serviceAccountName: $name, restartPolicy: "Never", activeDeadlineSeconds: $deadline,
        enableServiceLinks: false, terminationGracePeriodSeconds: 10,
        containers: [{name: "run", image: $image, command: ["bash", "-c", $sh], workingDir: "/src",
          env: [env("RUNNER_SHA"; $sha), env("RUNNER_CMD"; $cmd), env("RUNNER_KUBECTL"; $kver),
                env("RUNNER_GO"; $go), env("RUNNER_NODE"; $node), env("RUNNER_REPO"; $repo), env("RUNNER_GH_SH"; $gh),
                env("KANAME_STAND_IN_POD"; "1"), env("KANAME_STAND_EXT_NS"; $ns), env("KANAME_STAND_TASK"; $task),
                env("HOME"; "/work/home"), env("GOTOOLCHAIN"; "local")],
          resources: {requests: {cpu: "1", memory: "2Gi"}, limits: {memory: "6Gi"}},
          securityContext: {allowPrivilegeEscalation: false},
          volumeMounts: [{name: "src", mountPath: "/src"}, {name: "work", mountPath: "/work"}]}],
        volumes: [{name: "src", emptyDir: {}}, {name: "work", emptyDir: {}}]}}]}'
}

# runner_judge ПРОСТРАНСТВО — суд формы объектов раннера (stdin — их список): то, что
# держит кластер от раннера. Печатает находки RUNNER-FORM; код 1 — есть находки.
# Его зовут runner_main до записи и самопроверка (на настоящем выводе runner_objects и на
# близнецах с одним дефектом).
runner_judge() {
  python3 -c '
import json, sys
ns = sys.argv[1]
items = json.load(sys.stdin)["items"]
bad = []
# Что учётке раннера нужно в своём пространстве — и ни глагола сверх: поды стенда она
# заводит и снимает, в них исполняет и пробрасывает, читает журнал; секреты и карту
# конфигурации стенда заводит и снимает; события читает для объяснения отказа.
ALLOWED = {"pods": {"get", "list", "watch", "create", "delete"},
           "pods/exec": {"get", "create"}, "pods/portforward": {"get", "create"},
           "pods/log": {"get"}, "secrets": {"get", "create", "delete"},
           "configmaps": {"get", "create", "delete"}, "events": {"get", "list", "watch"}}
kinds = sorted(i.get("kind", "") for i in items)
if kinds != ["Pod", "Role", "RoleBinding", "ServiceAccount"]:
    bad.append("виды объектов %s, ждали Pod, Role, RoleBinding, ServiceAccount" % kinds)
for i in items:
    if i.get("metadata", {}).get("namespace") != ns:
        bad.append("%s/%s вне своего пространства %s" % (i.get("kind"), i.get("metadata", {}).get("name"), ns))
sas = [i["metadata"].get("name") for i in items if i.get("kind") == "ServiceAccount"]
roles = [i["metadata"].get("name") for i in items if i.get("kind") == "Role"]
rules = 0
for i in items:
    k = i.get("kind")
    if k == "RoleBinding":
        ref = i.get("roleRef", {})
        if ref.get("kind") != "Role":
            bad.append("привязка к %s, а не к роли пространства" % ref.get("kind"))
        elif ref.get("name") not in roles:
            bad.append("привязка к роли %s, а не к роли раннера %s" % (ref.get("name"), roles))
        for s in i.get("subjects", []):
            if s.get("kind") != "ServiceAccount" or s.get("namespace") != ns:
                bad.append("субъект привязки вне учётки своего пространства: %s" % s)
            elif s.get("name") not in sas:
                bad.append("субъект привязки — учётка %s, а не учётка раннера %s" % (s.get("name"), sas))
    if k == "Role":
        for r in i.get("rules", []):
            rules += 1
            if r.get("apiGroups") != [""] or r.get("nonResourceURLs"):
                bad.append("правило роли вне основной группы API: %s" % r)
                continue
            for res in r.get("resources", []):
                if res not in ALLOWED:
                    bad.append("роль даёт %s на %s — вне нужного стенду" % (sorted(r.get("verbs", [])), res))
                    continue
                extra = set(r.get("verbs", [])) - ALLOWED[res]
                if extra:
                    bad.append("роль даёт %s на %s сверх нужного" % (sorted(extra), res))
            if "*" in r.get("resources", []) or "*" in r.get("verbs", []):
                bad.append("роль со звездой: %s" % r)
    if k == "Pod":
        sp = i.get("spec", {})
        if sp.get("serviceAccountName") not in sas:
            bad.append("pod под учёткой %s, а не учёткой раннера %s" % (sp.get("serviceAccountName"), sas))
        if "nodeName" in sp:
            bad.append("pod прибит к узлу %s мимо планировщика" % sp["nodeName"])
        for h in ("hostNetwork", "hostPID", "hostIPC"):
            if sp.get(h):
                bad.append("pod: %s" % h)
        for v in sp.get("volumes", []):
            if "hostPath" in v:
                bad.append("pod: том hostPath %s" % v.get("name"))
        for c in sp.get("containers", []) + sp.get("initContainers", []):
            sc = c.get("securityContext") or {}
            if sc.get("privileged") or (sc.get("capabilities") or {}).get("add"):
                bad.append("контейнер %s: privileged либо добавленные возможности" % c.get("name"))
            if sc.get("allowPrivilegeEscalation") is not False:
                bad.append("контейнер %s: повышение прав не запрещено" % c.get("name"))
            if "memory" not in ((c.get("resources") or {}).get("limits") or {}):
                bad.append("контейнер %s без предела памяти" % c.get("name"))
for b in bad:
    print("RUNNER-FORM\t" + b)
if not bad:
    print("RUNNER-FORM-OK\tобъектов %d, правил роли %d, всё в пространстве %s" % (len(items), rules, ns))
sys.exit(1 if bad else 0)
' "$1"
}

runner_explain() {
  runner_warn "pod раннера: $(kc -n "$EXT_NS" get pod "$RUNNER_POD" -o 'jsonpath={.status.phase} {range .status.containerStatuses[*]}{.state}{end}' 2>/dev/null | mask | cut -c1-400)"
  kc -n "$EXT_NS" get events --field-selector "involvedObject.name=$RUNNER_POD" --sort-by=.lastTimestamp 2>/dev/null | tail -n 5 | mask >&2
}

# runner_on_exit — снятие ВСЕГДА: журнал, пространство, перепись задачи.
# shellcheck disable=SC2329  # зовётся ловушкой EXIT в runner_main
runner_on_exit() {
  local rc=$? left=0
  trap - EXIT INT TERM
  if [ -n "$RUNNER_LOGS" ]; then kill "$RUNNER_LOGS" 2>/dev/null; wait "$RUNNER_LOGS" 2>/dev/null; fi
  if [ "$RUNNER_UP" = 1 ]; then
    ext_teardown_ns || { runner_warn "СНЯТИЕ $EXT_NS НЕ ПРОШЛО — остаток снимет срок kacho.io/expires либо stand-own.sh down"; [ "$rc" -ne 0 ] || rc=1; }
    ext_census || { left=1; [ "$rc" -ne 0 ] || rc=1; }
  fi
  say "раннер: код $rc$([ "$left" = 1 ] && printf ' — остаток пространств задачи не ноль (выше)')"
  exit "$rc"
}

# shellcheck disable=SC2329  # зовётся ловушками INT и TERM в runner_main
runner_on_signal() {
  trap - INT TERM
  runner_warn "прогон на $EXT_NS прерван сигналом $1"
  exit "$2"
}

# runner_main [--out КАТАЛОГ] [--ship ФАЙЛ]… -- КОМАНДА… — раздел выше. Код — код
# команды; 125 — не исполнялась; 76 — исполнилась, отчёты доставлены неполно; 64 — вызов
# неверен; 1 — пространство уже есть.
runner_main() {
  local sha url repo gov kver image objs mark mrc rc="" stage="" outcome phase miss=0 fetch=0 t f base want got
  local -A seen=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --out)  [ -n "${2:-}" ] || { refuse "runner: --out без каталога"; return 64; }
              RUNNER_OUT="$2"; shift 2 ;;
      --ship) if [ ! -f "${2:-}" ] || [ -L "${2:-}" ]; then refuse "runner: --ship «${2:-}» — не обычный файл"; return 64; fi
              base="$(basename -- "$2")"
              [ -z "${seen[$base]:-}" ] || { refuse "runner: --ship — два файла с именем «$base»"; return 64; }
              seen[$base]=1; RUNNER_SHIP+=("$2"); shift 2 ;;
      --) shift; break ;;
      *) refuse "runner: неизвестный довод «$1» (команда — после --)"; return 64 ;;
    esac
  done
  [ $# -gt 0 ] || { refuse "runner: команда не названа — stand-own.sh runner [--out КАТАЛОГ] [--ship ФАЙЛ]… -- КОМАНДА…"; return 64; }
  for t in kubectl jq python3 git gzip tar; do
    command -v "$t" >/dev/null 2>&1 || { unmet "инструмента нет: $t — раннер не запускался"; return "$RUNNER_UNMET"; }
  done
  [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ] ||
    { refuse "runner: в рабочей копии правки вне коммита — pod исполняет коммит (git archive HEAD): закоммить их"; return 64; }
  sha="$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || { refuse "runner: голова рабочей копии не разрешается"; return 64; }
  url="$(git -C "$ROOT" remote get-url origin 2>/dev/null)"
  [[ "$url" =~ github\.com[:/]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$ ]] || { refuse "runner: origin копии не репозиторий площадки — репозиторий pod назвать нечем"; return 64; }
  repo="${BASH_REMATCH[1]%.git}"
  route_decide || return $?
  if [ "$ROUTE" != external ]; then
    unmet "внешний кластер недоступен ($WHY${PROOF:+; $PROOF}) — pod раннеру ставить негде; при недоступном кластере стенд — stand-own.sh up на машине"
    return "$RUNNER_UNMET"
  fi
  ext_name_ns || return $?
  mark="$(ext_mark "$EXT_NS")"; mrc=$?
  case "$mrc" in
    3) ;;
    0) refuse "пространство $EXT_NS уже есть (метка стенда «$mark») — прогон раннера заводит своё и его же снимает: снять прежнее (stand-own.sh down) либо назвать другое"; return 1 ;;
    *) return "$RUNNER_UNMET" ;;
  esac
  gov="$(runner_go "$sha")" || return "$RUNNER_UNMET"
  kver="$(kq version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // empty' 2>/dev/null)"
  [[ "$kver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { unmet "версия сервера кластера не прочитана — kubectl pod не выбрать"; return "$RUNNER_UNMET"; }
  image="$(runner_image "$gov")"
  objs="$(runner_objects "$EXT_NS" "$image" "$sha" "$EXT_TASK" "$kver" "$gov" "$(printf '%q ' "$@")" "$repo")" ||
    { unmet "объекты раннера не построены"; return "$RUNNER_UNMET"; }
  runner_judge "$EXT_NS" <<< "$objs" >&2 || { unmet "форма объектов раннера не прошла суд (выше)"; return "$RUNNER_UNMET"; }
  RUNNER_OUT="${RUNNER_OUT:-$ROOT/.stand/runner-out/$EXT_NS}"
  mkdir -p "$RUNNER_OUT" || { unmet "каталог отчётов $RUNNER_OUT не заведён"; return "$RUNNER_UNMET"; }
  [ -z "$(ls -A "$RUNNER_OUT")" ] || { refuse "runner: каталог отчётов $RUNNER_OUT не пуст — отчёты прежнего прогона смешались бы с этими"; return 64; }

  trap 'runner_on_exit' EXIT
  trap 'runner_on_signal INT 130' INT
  trap 'runner_on_signal TERM 143' TERM
  RUNNER_UP=1
  ext_claim_ns || exit "$RUNNER_UNMET"
  ext_nodes_guard || { unmet "узлы перед записью объектов раннера: $WHY"; exit "$RUNNER_UNMET"; }
  kc apply -f - <<< "$objs" > /dev/null || { unmet "объекты раннера не применены"; exit "$RUNNER_UNMET"; }
  say "раннер: образ $image, kubectl $kver, node $RUNNER_NODE, исходники $sha, пространство $EXT_NS"
  ks -n "$EXT_NS" wait --for=condition=Ready "pod/$RUNNER_POD" --timeout=600s > /dev/null ||
    { runner_explain; unmet "pod раннера не готов за 600 с"; exit "$RUNNER_UNMET"; }
  # Сжатием: поток идёт через API-сервер.
  git -C "$ROOT" archive --format=tar "$sha" | gzip -1 | ks -n "$EXT_NS" exec -i "$RUNNER_POD" -c run -- tar -xz -C /src ||
    { unmet "исходники ревизии $sha в pod не доставлены"; exit "$RUNNER_UNMET"; }
  for f in "${RUNNER_SHIP[@]}"; do
    base="$(basename -- "$f")"
    # shellcheck disable=SC2016  # $1 раскрывает оболочка pod
    ks -n "$EXT_NS" exec -i "$RUNNER_POD" -c run -- sh -c 'mkdir -p /work/ship && cat > "/work/ship/$1"' sh "$base" < "$f" ||
      { unmet "файл $base в pod не доставлен"; exit "$RUNNER_UNMET"; }
    want="$(sha256sum < "$f" | cut -d' ' -f1)"
    got="$(ks -n "$EXT_NS" exec "$RUNNER_POD" -c run -- sha256sum "/work/ship/$base" 2>/dev/null | cut -d' ' -f1)"
    [ "$want" = "$got" ] || { unmet "отпечаток файла $base в pod не совпал с машинным"; exit "$RUNNER_UNMET"; }
    say "раннер: /work/ship/$base доставлен, отпечаток сошёлся"
  done
  # kubectl машины — тем же потоком, лишь при той же архитектуре узла.
  if [ "$(ks -n "$EXT_NS" exec "$RUNNER_POD" -c run -- uname -m 2>/dev/null)" = "$(uname -m)" ]; then
    gzip -1 < "$(type -P kubectl)" | ks -n "$EXT_NS" exec -i "$RUNNER_POD" -c run -- sh -c 'mkdir -p /work/bin && gzip -dc > /work/bin/kubectl && chmod 0755 /work/bin/kubectl' ||
      runner_warn "kubectl машины в pod не доставлен — pod загрузит версию сервера"
  fi
  ks -n "$EXT_NS" exec "$RUNNER_POD" -c run -- touch /work/.go || { unmet "pod не принял сигнал старта"; exit "$RUNNER_UNMET"; }
  ks -n "$EXT_NS" logs -f "pod/$RUNNER_POD" -c run & RUNNER_LOGS=$!
  while :; do
    outcome="$(ks -n "$EXT_NS" exec "$RUNNER_POD" -c run -- cat /work/.rc 2>/dev/null)"
    if [[ "$outcome" =~ ^(setup|command)\ (0|[1-9][0-9]{0,2})$ ]] && [ "${BASH_REMATCH[2]}" -le 255 ]; then
      stage="${BASH_REMATCH[1]}"; rc="${BASH_REMATCH[2]}"; break
    fi
    rc=""; stage=""
    phase="$(kc -n "$EXT_NS" get pod "$RUNNER_POD" -o 'jsonpath={.status.phase}' 2>/dev/null)"
    case "$phase" in
      Running|Pending) miss=0 ;;
      "") miss=$((miss + 1)); [ "$miss" -lt 30 ] || { runner_warn "состояние pod не читается 30 опросов подряд"; break; } ;;
      *) runner_warn "pod раннера вышел из работы (фаза «$phase») до кода команды"; break ;;
    esac
    sleep 10
  done
  runner_fetch "$EXT_NS" "$RUNNER_OUT" || fetch=1
  ks -n "$EXT_NS" exec "$RUNNER_POD" -c run -- touch /work/.fetched > /dev/null 2>&1
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$RUNNER_LOGS" 2>/dev/null || break; sleep 1; done
  kill "$RUNNER_LOGS" 2>/dev/null; wait "$RUNNER_LOGS" 2>/dev/null; RUNNER_LOGS=""
  [ -n "$rc" ] || { runner_explain; unmet "кода команды из pod нет — команда не исполнилась до конца"; exit "$RUNNER_UNMET"; }
  # Стадия прочитана вместе с кодом ДО забора: численный код 125 сам по себе ничего
  # не говорит об исполнении. Setup остаётся 125 при любом исходе доставки.
  [ "$stage" = command ] || { unmet "подготовка pod завершилась кодом $rc до команды"; exit "$RUNNER_UNMET"; }
  # Команда исполнилась, отчёты неполны: исход команды назван, но вердикт по отчётам не
  # читается — «не выполнилось» своим кодом, а не 125 «команда не исполнялась».
  [ "$fetch" -eq 0 ] || {
    runner_warn "НЕ ВЫПОЛНИЛОСЬ: отчёты доставлены неполно — доставлено $RUNNER_FETCH_N из $RUNNER_FETCH_M при коде команды $rc; отказ забора: «${RUNNER_FETCH_WHY:-—}»; вердикт по отчётам не читается — код $RUNNER_FETCH_SHORT"
    exit "$RUNNER_FETCH_SHORT"; }
  say "раннер: команда в pod завершилась кодом $rc, отчёты — $RUNNER_OUT"
  exit "$rc"
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
if [ "${1:-}" = "--registry-self-test" ]; then
  registry_tmp="$(mktemp -d)" || exit 75
  trap 'rm -rf "$registry_tmp"' EXIT
  PKI="$registry_tmp/pki"; BIN="$registry_tmp/bin"; RUNDIR="$registry_tmp/run"
  WRAPKEY_FILE="$RUNDIR/wrapping.key"; BOOTSTRAP_KEY_FILE="$RUNDIR/bootstrap-sa.key"
  SECOND_FACTOR_KEY_FILE="$RUNDIR/second-factor.key"
  REGISTRY_WORLD=1
  make_pki
  registry_world_prepare || exit 1
  stand_env
  [ "$KANAME_AUTHN__MODULE_IDENTITIES" = "kaname/$EDGE_SA=edge@internal,kaname/kacho-registry=module-writer@internal" ] || exit 1
  [ "$KANAME_MANIFESTS__DIR" = "$BIN/manifests" ] && [ "$KANAME_MANIFESTS__REQUIRED" = true ] || exit 1
  cmp "$ROOT/tests/authz-fixtures/registry-own-stand-fixture.yaml" "$BIN/manifests/registry.yaml" || exit 1
  cp "$PKI/edge.crt" "$PKI/registry.crt"
  if registry_world_prepare; then fail "чужой лист принят владельцем registry"; exit 1; fi
  REGISTRY_WORLD=0
  stand_env
  [ "$KANAME_AUTHN__MODULE_IDENTITIES" = "kaname/$EDGE_SA=edge@internal" ] || exit 1
  [ -z "${KANAME_MANIFESTS__DIR:-}${KANAME_MANIFESTS__REQUIRED:-}" ] || exit 1
  say 'registry profile self-test: passed=5 failed=0'
  exit 0
fi

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
    # Окружение pod раннера самопроверку не уводит: шаг задания `stand` в pod наследует
    # KANAME_STAND_IN_POD, KANAME_STAND_EXT_NS, KANAME_STAND_TASK и адрес API кластера, и
    # миры маршрута судили бы pod, а не свою настройку (11 провалов, kaname#940). Мир,
    # которому они нужны, ставит их сам.
    IN_POD=""; SA_DIR="$TMP/sa-none"
    unset KANAME_STAND_IN_POD KANAME_STAND_EXT_NS KANAME_STAND_TASK KANAME_STAND_SA_DIR KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT
    # Маршрут идущего стенда машины самопроверку не уводит: файла маршрута у неё нет.
    ROUTE_FILE="$TMP/route-none"
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
             "$TMP/mig-unmet" "$TMP/mig-echo" "$TMP/mig-conn" "$TMP/mig-config" \
             "$TMP/mig-ok" "$TMP/mig-ok-noisy" "$TMP/build-bin" \
             "$TMP/svc-up" "$TMP/svc-guard" "$TMP/chain-ok" "$TMP/chain-guard"

    # Подложные средства подъёма: их НИКОГДА не исполняют, `need_tool` смотрит лишь
    # наличие. Поэтому ни один прогон самопроверки не трогает настоящий docker.
    printf '#!/bin/sh\nexit 0\n' > "$TMP/toolbin/go"
    # Подложный клиент контейнера. `need_tool` спрашивает лишь его наличие, а
    # `start_service` зовёт `docker run … <образ> <бинарь>`: подложный исполняет
    # ПОСЛЕДНИЙ довод — подставную службу мира — на переднем плане, как настоящий
    # клиент держит контейнер. Так миры судят ту же ветку запуска, что подъём, и
    # движка контейнеров не требуют. Прочие подкоманды (`rm -f`) — пустой успех.
    cat > "$TMP/toolbin/docker" <<'EOF'
#!/bin/sh
[ "$1" = run ] || exit 0
for a in "$@"; do last="$a"; done
exec "$last"
EOF

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

    # ─── ПОДСТАВНЫЕ НАКАТЧИКИ: КОД ПРОТИВ ПРОЗЫ ─────────────────────────────
    #
    # Класс различает САМ накатчик и называет его КОДОМ ВЫХОДА (75 — база
    # недостижима, о миграциях не известно ничего; иной ненулевой — находка о
    # дереве). Поэтому проза в этих четырёх подставных умышленно ПЕРЕКРЁЩЕНА с
    # кодом: пара несёт слова прежнего образца при коде находки, пара — код
    # несозданного условия без единого такого слова. Различить их поиском слов
    # нельзя НИ ПРИ КАКОМ образце — на этом и держится проба.
    #
    # Прежний читатель искал в выводе `connect|dial|refused|sslmode|password` и
    # зеленел на ЭХЕ ВВОДА: обеззараженная строка подключения сохраняет запрос, а
    # посадка стенда экспортирует `sslmode=require` всегда.

    # База НЕДОСТИЖИМА: код 75, и ни одного слова прежнего образца в тексте.
    cat > "$TMP/mig-unmet/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'Error: database not ready after 2m0s: the database system is starting up (SQLSTATE 57P03)' >&2
exit 75
EOF
    # НЕВЕРНАЯ ПОСАДКА: адрес базы не называет хоста, ожидание не сойдётся НИКОГДА.
    # Текст — дословный вывод продукта (`cmd/migrator/main.go`, обеззараживание
    # `config.RedactDSN`): именно он несёт `sslmode` из ЭХА ВВОДА при коде находки.
    cat > "$TMP/mig-echo/kaname-migrator" <<'EOF'
#!/bin/sh
cat >&2 <<'MSG'
Error: database address "postgres://kaname:xxxxx@:5432/kaname?sslmode=require" names no host: it is not set, and waiting for the database would never converge; set --dsn, ENV KACHO_MIGRATOR_DSN, or the chart's db.host
MSG
exit 1
EOF
    # ПЕРЕКРЁСТНАЯ ИНЪЕКЦИЯ, самая резкая: проза ТА ЖЕ, что у недостижимой базы,
    # код — находки. Читатель, судящий текст, ответил бы здесь 75 и спрятал бы
    # дефект; судящий код обязан ответить 1.
    cat > "$TMP/mig-conn/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'Error: database connection check failed: dial tcp 127.0.0.1:15432: connect: connection refused' >&2
exit 1
EOF
    # Отказ, к базе не относящийся вовсе: строка подключения не собралась.
    cat > "$TMP/mig-config/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'Error: dsn unset (--dsn / KACHO_MIGRATOR_DSN) and service config produced an empty DSN' >&2
exit 1
EOF
    cat > "$TMP/mig-ok/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'OK    0001_init.sql'
echo 'goose: no migrations to run'
exit 0
EOF
    # УСПЕХ, чей вывод НЕСЁТ слова прежнего образца: уведомления сервера
    # доезжают до оператора дословно, и имя столбца с паролем — законная строка
    # в них. Третий вход задачи: эхо есть, отказа нет. Исход обязан быть успехом.
    cat > "$TMP/mig-ok-noisy/kaname-migrator" <<'EOF'
#!/bin/sh
echo 'kaname NOTICE: column "password_hash" already exists, skipping' >&2
echo 'OK    20260101000000_init.sql'
echo 'goose: successfully migrated database'
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
             "$TMP/gobin-fail/go" "$TMP/mig-unmet/kaname-migrator" \
             "$TMP/mig-echo/kaname-migrator" "$TMP/mig-conn/kaname-migrator" \
             "$TMP/mig-config/kaname-migrator" "$TMP/mig-ok/kaname-migrator" \
             "$TMP/mig-ok-noisy/kaname-migrator" \
             "$TMP/chain-ok/kaname-migrator" "$TMP/chain-guard/kaname-migrator" \
             "$TMP/svc-guard/kaname" "$TMP/chain-guard/kaname" \
             "$TMP/svc-up/kaname" "$TMP/chain-ok/kaname"

    # ─── ПОДЛОЖНЫЕ КЛИЕНТЫ КОНТЕЙНЕРА ДЛЯ СВЁРТКИ БАЗЫ ──────────────────────
    #
    # Свёртка и возврат базы зовут `docker stop|start|inspect|exec`. Подложный
    # клиент держит СОСТОЯНИЕ контейнера в файле (`SELFTEST_PG_STATE`): `stop`
    # пишет `false`, `start` — `true`, `inspect` печатает записанное, а
    # `pg_isready` отвечает успехом ровно у исполняющегося. Четыре мира отличаются
    # от него ОДНИМ фактом каждый: остановить не вышло · остановка не подействовала
    # · база не поднимается · клиента нет вовсе.
    mkdir -p "$TMP/pg-ok" "$TMP/pg-stop-fails" "$TMP/pg-stays" "$TMP/pg-never-ready"
    cat > "$TMP/pg-ok/docker" <<'EOF'
#!/bin/sh
case "$1" in
  stop)    echo false > "$SELFTEST_PG_STATE" ;;
  start)   echo true > "$SELFTEST_PG_STATE" ;;
  inspect) cat "$SELFTEST_PG_STATE" ;;
  exec)    [ "$(cat "$SELFTEST_PG_STATE")" = true ] ;;
esac
EOF
    cat > "$TMP/pg-stop-fails/docker" <<'EOF'
#!/bin/sh
case "$1" in
  stop)    echo 'Error response from daemon: No such container' >&2; exit 1 ;;
  inspect) cat "$SELFTEST_PG_STATE" ;;
esac
EOF
    cat > "$TMP/pg-stays/docker" <<'EOF'
#!/bin/sh
case "$1" in
  stop)    exit 0 ;;
  inspect) echo true ;;
esac
EOF
    cat > "$TMP/pg-never-ready/docker" <<'EOF'
#!/bin/sh
case "$1" in
  start)   echo true > "$SELFTEST_PG_STATE" ;;
  inspect) cat "$SELFTEST_PG_STATE" ;;
  exec)    exit 1 ;;
esac
EOF
    chmod +x "$TMP/pg-ok/docker" "$TMP/pg-stop-fails/docker" "$TMP/pg-stays/docker" \
             "$TMP/pg-never-ready/docker"

    # ─── ПОДСТАВНОЙ МИР ВОЛНЫ СВЁРТКИ: время — файл, а не ожидание ────────────
    #
    # Часы волны (`now_s`) читают файл, пауза (`pause_s`) его сдвигает, подложный
    # `curl` печатает в вывод, В КАКОЙ МОМЕНТ было предъявление, и отвечает кодом
    # мира. Так проба утверждает ПОРЯДОК «тишина, затем прогрев» по самим
    # часам, а не по тексту объявления. Подложный клиент контейнера `pg-slow`
    # останавливает базу, сдвигая часы за окно, — мир «окно истекло до вызовов».
    mkdir -p "$TMP/wave" "$TMP/pg-slow"
    printf '{"values":[]}\n' > "$TMP/wave-env.json"
    cat > "$TMP/wave/jq" <<'EOF'
#!/bin/sh
echo selftest-value
EOF
    cat > "$TMP/wave/curl" <<'EOF'
#!/bin/sh
cat >/dev/null
echo "предъявлено фронту в $(cat "$SELFTEST_CLOCK")" >&2
printf '%s' "${SELFTEST_CURL_CODE:-200}"
EOF
    cat > "$TMP/pg-slow/docker" <<'EOF'
#!/bin/sh
case "$1" in
  stop)    echo false > "$SELFTEST_PG_STATE"
           echo $(( $(cat "$SELFTEST_CLOCK") + 40 )) > "$SELFTEST_CLOCK" ;;
  inspect) cat "$SELFTEST_PG_STATE" ;;
esac
EOF
    chmod +x "$TMP/wave/jq" "$TMP/wave/curl" "$TMP/pg-slow/docker"

    # ─── ПОДЛОЖНЫЙ КЛИЕНТ КОНТЕЙНЕРА С ТОМАМИ: СНОС НЕ ОСТАВЛЯЕТ ТОМОВ (kaname#710) ─
    #
    # Образ Postgres объявляет `VOLUME /var/lib/postgresql/data`: каждый контейнер
    # базы, запущенный без `--rm`, получает АНОНИМНЫЙ том, и `docker rm -f` без
    # `-v` оставляет его сиротой (замер 2026-10-12: `rm -f` — томов +1, `rm -fv` —
    # +0). Подложный клиент держит это свойство в каталоге `SELFTEST_VOL_DIR`:
    # `run` без `--rm` заводит НОВЫЙ том и привязывает его к имени контейнера
    # (повторный подъём под тем же именем — другой том), `run --rm` не заводит
    # (движок снимает анонимные тома такого контейнера сам), `rm` снимает том
    # ТОЛЬКО при флаге `v`. Прочие подкоманды (`exec` для pg_isready) — успех.
    mkdir -p "$TMP/vol"
    cat > "$TMP/vol/docker" <<'EOF'
#!/bin/sh
cmd="$1"; shift
case "$cmd" in
  run)
    rm_flag=0; name=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --rm) rm_flag=1 ;;
        --name) name="$2"; shift ;;
      esac
      shift
    done
    if [ "$rm_flag" -eq 0 ] && [ -n "$name" ]; then
      mkdir -p "$SELFTEST_VOL_DIR/live"
      vol="vol-$(date +%s%N)"
      : > "$SELFTEST_VOL_DIR/$vol"
      echo "$vol" > "$SELFTEST_VOL_DIR/live/$name"
    fi
    exit 0 ;;
  rm)
    vflag=0
    while [ $# -gt 0 ]; do
      case "$1" in
        -*v*) vflag=1 ;;
        -*) ;;
        *) live="$SELFTEST_VOL_DIR/live/$1"
           if [ -f "$live" ]; then
             [ "$vflag" -eq 1 ] && rm -f "$SELFTEST_VOL_DIR/$(cat "$live")"
             rm -f "$live"
           fi ;;
      esac
      shift
    done
    exit 0 ;;
  *) exit 0 ;;
esac
EOF
    chmod +x "$TMP/vol/docker"

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

    world_migrate_unmet()   { ( BIN="$TMP/mig-unmet";    migrate ); }
    world_migrate_echo()    { ( BIN="$TMP/mig-echo";     migrate ); }
    world_migrate_conn()    { ( BIN="$TMP/mig-conn";     migrate ); }
    world_migrate_config()  { ( BIN="$TMP/mig-config";   migrate ); }
    world_migrate_ok()      { ( BIN="$TMP/mig-ok";       migrate ); }
    world_migrate_ok_noisy(){ ( BIN="$TMP/mig-ok-noisy"; migrate ); }

    world_build_no_go()     { ( PATH="$TMP/empty";               BIN="$TMP/build-bin"; build_binaries ); }
    world_build_fail()      { ( PATH="$TMP/gobin-fail:$PATH";    BIN="$TMP/build-bin"; build_binaries ); }
    world_build_ok()        { ( PATH="$TMP/gobin-ok:$PATH";      BIN="$TMP/build-bin"; build_binaries ); }

    world_service_up() {
        ( PATH="$TMP/toolbin:$PATH"; BIN="$TMP/svc-up"; RUNDIR="$TMP/run-svc"; PORTS="$PAIR_SVC"
          SERVICE_TRIES=20; export SELFTEST_BIND_PORTS="$PAIR_SVC"
          start_service )
    }
    world_service_partial() {
        ( PATH="$TMP/toolbin:$PATH"; BIN="$TMP/svc-up"; RUNDIR="$TMP/run-svc"; PORTS="$PAIR_SVC"
          SERVICE_TRIES=3;  export SELFTEST_BIND_PORTS="$PORT_A"
          start_service )
    }
    world_service_guard() {
        ( PATH="$TMP/toolbin:$PATH"; BIN="$TMP/svc-guard"; RUNDIR="$TMP/run-svc"; PORTS="$PAIR_SVC"
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

    world_fold_ok() {
        ( PATH="$TMP/pg-ok:$PATH"; export SELFTEST_PG_STATE="$TMP/pg-state"
          echo true > "$SELFTEST_PG_STATE"; fold_db )
    }
    world_fold_stop_fails() {
        ( PATH="$TMP/pg-stop-fails:$PATH"; export SELFTEST_PG_STATE="$TMP/pg-state"
          echo true > "$SELFTEST_PG_STATE"; fold_db )
    }
    world_fold_stays() {
        ( PATH="$TMP/pg-stays:$PATH"; export SELFTEST_PG_STATE="$TMP/pg-state"
          echo true > "$SELFTEST_PG_STATE"; fold_db )
    }
    world_fold_no_docker() { ( PATH="$TMP/empty"; fold_db ); }
    world_unfold_ok() {
        ( PATH="$TMP/pg-ok:$PATH"; export SELFTEST_PG_STATE="$TMP/pg-state"
          echo false > "$SELFTEST_PG_STATE"; DB_READY_TRIES=3; unfold_db )
    }
    world_unfold_never_ready() {
        ( PATH="$TMP/pg-never-ready:$PATH"; export SELFTEST_PG_STATE="$TMP/pg-state"
          echo false > "$SELFTEST_PG_STATE"; DB_READY_TRIES=2; unfold_db )
    }

    # wave_world <код коллекции> <её длительность, с> [каталог клиента контейнера]
    # Часы стартуют с 1000: момент прогрева после тишины читается в выводе числом.
    wave_world() {
        local crc="$1" cdur="$2" dk="${3:-$TMP/pg-ok}"
        ( PATH="$TMP/wave:$dk:$PATH"
          export SELFTEST_PG_STATE="$TMP/pg-state" SELFTEST_CLOCK="$TMP/clock"
          echo true > "$SELFTEST_PG_STATE"; echo 1000 > "$SELFTEST_CLOCK"
          now_s()   { cat "$SELFTEST_CLOCK"; }
          pause_s() { echo $(( $(cat "$SELFTEST_CLOCK") + $1 )) > "$SELFTEST_CLOCK"; }
          WAVE_STATE="$TMP/wave.state"
          failclosed_prepare "$TMP/wave-env.json" || exit $?
          echo $(( $(cat "$SELFTEST_CLOCK") + cdur )) > "$SELFTEST_CLOCK"
          echo "коллекция исполнялась"
          failclosed_judge "$crc" )
    }
    world_wave_ok()            { wave_world 0 2; }
    world_wave_red_inside()    { wave_world 1 2; }
    world_wave_red_expired()   { wave_world 1 31; }
    world_wave_slow_fold()     { wave_world 0 2 "$TMP/pg-slow"; }
    world_wave_rev_longer()    { ( REVOCATION_CACHE_TTL=45s; wave_world 0 2 ); }
    world_wave_window_smaller(){ ( KEY_SET_TTL=1m; wave_world 1 31 ); }
    world_wave_warm_refused()  { ( export SELFTEST_CURL_CODE=401; wave_world 0 2 ); }
    world_wave_ttl_garbage()   { ( KEY_SET_TTL=30sec; wave_world 0 2 ); }
    world_wave_no_state()      { ( WAVE_STATE="$TMP/wave-absent.state"; failclosed_judge 1 ); }

    # vol_world <действие>: исполняет действие с подложным клиентом томов и
    # печатает перепись сирот. Сирота есть — код 1: снос оставил след.
    vol_world() {
        ( PATH="$TMP/vol:$PATH"; export SELFTEST_VOL_DIR="$TMP/vol-state"
          rm -rf "$SELFTEST_VOL_DIR"; mkdir -p "$SELFTEST_VOL_DIR"
          PKI="$TMP/vol-pki"; RUNDIR="$TMP/vol-run"; mkdir -p "$PKI" "$RUNDIR"
          "$1" >/dev/null 2>&1
          n=$(find "$SELFTEST_VOL_DIR" -maxdepth 1 -type f | wc -l)
          echo "томов-сирот после сноса: $n"
          [ "$n" -eq 0 ] )
    }
    vol_up_down()         { start_pg; down; }
    vol_up_up_down()      { start_pg; start_pg; down; }
    vol_bare_rm()         { start_pg; docker rm -f "$PG_NAME"; }
    world_vol_down()      { vol_world vol_up_down; }
    world_vol_reup_down() { vol_world vol_up_up_down; }
    world_vol_bare_rm()   { vol_world vol_bare_rm; }

    # ─── миры маршрута (kaname#841): внешний кластер — первым, docker — по основанию ──
    #
    # Подложный kubectl отвечает из каталога состояния `SELFTEST_KC`: контексты,
    # ответ права, узлы, пространства (файл на пространство, содержимое — метка
    # стенда), вывод `/proc/net/tcp` пода. Ни одна проба не говорит с кластером.
    mkdir -p "$TMP/kc" "$TMP/xdg-empty"
    cat > "$TMP/kc/kubectl" <<'EOF'
#!/usr/bin/env bash
S="$SELFTEST_KC"; args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --kubeconfig|--context|-n|--namespace|-c|-o|-l|--timeout) args+=("$1=$2"); shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- "${args[@]}"; line="$*"
printf '%s\n' "$line" >> "$S/calls"
case "$line" in
  *"config get-contexts"*) cat "$S/contexts" ;;
  *"auth can-i create namespaces"*)
    if [ -e "$S/cani-fail" ]; then
      echo "Unable to connect to the server: dial tcp 10.1.2.3:6443: i/o timeout (https://api.stand.example:6443)" >&2; exit 1
    fi
    echo yes ;;
  *"get nodes"*) cat "$S/nodes" ;;
  *"get namespace "*)
    ns="${line#*get namespace }"; ns="${ns%% *}"
    [ -f "$S/ns/$ns" ] || { echo "Error from server (NotFound): namespaces \"$ns\" not found" >&2; exit 1; }
    cat "$S/ns/$ns" ;;
  *"get namespaces"*)
    for f in "$S"/ns/*; do [ -f "$f" ] && [ "$(cat "$f")" = own ] && echo "namespace/${f##*/}"; done; exit 0 ;;
  *"delete namespace "*)
    ns="${line#*delete namespace }"; ns="${ns%% *}"; rm -f "$S/ns/$ns" ;;
  *"create -f -"*)
    # Заведение пространства запоминается его меткой стенда — перепись и снос видят его.
    body="$(cat)"
    if grep -q '^kind: Namespace' <<< "$body"; then
      ns="$(sed -n 's/^  name: //p' <<< "$body" | head -n 1)"
      sed -n 's/^    kaname.io\/stand: //p' <<< "$body" > "$S/ns/$ns"
    fi ;;
  *"version -o=json"*) echo '{"serverVersion": {"gitVersion": "v1.31.2"}}' ;;
  *"get pod kaname-own"*"--ignore-not-found"*) [ -f "$S/pod" ] && echo pod/kaname-own; exit 0 ;;
  *"delete pod kaname-own"*) rm -f "$S/pod" ;;
  *"get pod kaname-runner"*) cat "$S/phase" 2>/dev/null || echo Running ;;
  # Тот же атомарный итог «стадия код», что публикует finish() настоящего pod.
  *"exec "*"cat /work/.rc"*) [ -f "$S/rc" ] || exit 1; cat "$S/rc" ;;
  *"logs "*) echo "журнал службы из пода" ;;
  *"exec "*"/proc/net/tcp"*) cat "$S/proc-net-tcp" ;;
  # `exec -i` настоящего клиента передаёт приёмнику pod поток до конца. Подставной, вышедший
  # недочитав, ронял пишущую сторону конвейера сигналом SIGPIPE, и pipefail доставки
  # принимал это за отказ — исход зависел от того, кто первым успел (kaname#1025).
  *"exec -i "*)
    cat > /dev/null
    [ -e "$S/exec-in-fail" ] || exit 0
    echo "gzip: stdin: not in gzip format" >&2; echo "command terminated with exit code 2" >&2; exit 2 ;;
  *) exit 0 ;;
esac
EOF
    chmod +x "$TMP/kc/kubectl"

    # kc_reset — состояние подложного кластера с нуля: один контекст -client,
    # право есть, два узла профиля. Настройка мира меняет ОДИН факт.
    kc_reset() {
        export SELFTEST_KC="$TMP/kc-state"
        rm -rf "$SELFTEST_KC"; mkdir -p "$SELFTEST_KC/ns"
        printf 'u--prof-infra\nu--prof-client\n' > "$SELFTEST_KC/contexts"
        printf 'node/prof-client-aaa-1\nnode/prof-client-aaa-2\n' > "$SELFTEST_KC/nodes"
        : > "$SELFTEST_KC/calls"
        : > "$TMP/kc-u--prof.yaml"
    }
    # route_world [настройка] — подъём целиком до выбора пути; оба пути подменены
    # строкой, так что проба судит РЕШЕНИЕ и его запись, а не подъём.
    route_world() {
        ( PATH="$TMP/kc:$PATH"; kc_reset; "${1:-:}"
          export XDG_CONFIG_HOME="$TMP/xdg-empty"
          unset KACHO_REMOTE_KUBECONFIG KANAME_STAND_CONTEXT KANAME_STAND_PROFILE
          export KANAME_STAND_KUBECONFIG="${SELFTEST_KCFG-$TMP/kc-u--prof.yaml}" KANAME_STAND_TASK="${SELFTEST_TASK-841}"
          [ -n "${SELFTEST_CTX:-}" ] && export KANAME_STAND_CONTEXT="$SELFTEST_CTX"
          RUNDIR="$TMP/run-route"; rm -rf "$RUNDIR"; ROUTE_FILE="$RUNDIR/route"; ROUTE_LOG="$RUNDIR/route.log"
          up_external() { echo "ВНЕШНИЙ ПУТЬ: $EXT_NS"; }
          up_local()    { echo "ЛОКАЛЬНЫЙ ПУТЬ"; }
          rc=0; stand_up || rc=$?
          echo "--- журнал маршрута:"; cat "$ROUTE_LOG" 2>/dev/null
          exit "$rc" )
    }
    kc_cani_fail()   { : > "$SELFTEST_KC/cani-fail"; }
    kc_infra_node()  { echo "node/prof-infra-bbb-1" >> "$SELFTEST_KC/nodes"; }
    kc_two_clients() { echo "v--prof-client" >> "$SELFTEST_KC/contexts"; }
    world_route_available()   { route_world; }
    world_route_unnamed()     { ( SELFTEST_KCFG=""; route_world ); }
    world_route_silent()      { route_world kc_cani_fail; }
    world_route_infra_nodes() { route_world kc_infra_node; }
    world_route_two_clients() { route_world kc_two_clients; }
    world_route_bad_override(){ ( SELFTEST_CTX="u--prof-infra"; route_world ); }
    world_route_no_task()     { ( SELFTEST_TASK=""; ROOT="$TMP/empty"; route_world ); }

    # ext_world <действие> — снос и перепись пространства внешнего пути.
    ext_world() {
        ( PATH="$TMP/kc:$PATH"; kc_reset
          EXT_KCFG="$TMP/kc-u--prof.yaml"; EXT_CTX="u--prof-client"; EXT_TASK=841; EXT_NS="t841-kaname-own"
          RUNDIR="$TMP/run-ext"; rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"
          ROUTE_FILE="$RUNDIR/route"; FORWARD_PID="$RUNDIR/forward.pid"; FORWARD_ON="$RUNDIR/forward.on"
          "$1" )
    }
    ext_down_own()      { echo own > "$SELFTEST_KC/ns/$EXT_NS"; ext_down && ext_census; }
    ext_down_foreign()  { echo other > "$SELFTEST_KC/ns/$EXT_NS"; ext_down; }
    ext_claim_foreign() { echo other > "$SELFTEST_KC/ns/$EXT_NS"; ext_claim_ns; }
    ext_census_left()   { echo own > "$SELFTEST_KC/ns/$EXT_NS"; ext_census; }
    world_ext_down_own()      { ext_world ext_down_own; }
    world_ext_down_foreign()  { ext_world ext_down_foreign; }
    world_ext_claim_foreign() { ext_world ext_claim_foreign; }
    world_ext_census_left()   { ext_world ext_census_left; }

    # Слушатели пода — по таблице сокетов ядра, а не по пробросу: проброс
    # принимает соединение и тогда, когда в поде порт никто не слушает.
    tcp_world() {
        ( PATH="$TMP/kc:$PATH"; kc_reset
          EXT_KCFG="$TMP/kc-u--prof.yaml"; EXT_CTX="u--prof-client"; EXT_NS="t841-kaname-own"
          PORTS="9090 9091"
          printf '%s\n' "  sl  local_address rem_address   st" "$@" > "$SELFTEST_KC/proc-net-tcp"
          if ext_listeners_up; then echo "все слушатели пода на месте"; exit 0; fi
          ext_listeners_report; exit 1 )
    }
    world_tcp_both() { tcp_world "   0: 00000000:2382 00000000:0000 0A 0" "   1: 00000000:2383 00000000:0000 0A 0"; }
    world_tcp_one()  { tcp_world "   0: 00000000:2382 00000000:0000 0A 0" "   1: 0100007F:2383 0100007F:9C40 01 0"; }

    # ─── миры раннера (kaname#940): форма объектов, забор отчётов, стенд из pod ──
    #
    # runner_form_world [порча] — настоящий вывод runner_objects под судом runner_judge;
    # порча — jq-фильтр, меняющий ОДИН факт против законного близнеца.
    runner_form_world() {
        ( objs="$(runner_objects t841-kaname-own docker.io/library/golang:1.26.10 \
                    0123456789abcdef0123456789abcdef01234567 841 v1.31.2 1.26.10 'true ' PRO-Robotech/kaname)" || exit 9
          if [ -n "${1:-}" ]; then objs="$(jq "$1" <<< "$objs")" || exit 9; fi
          runner_judge t841-kaname-own <<< "$objs" )
    }
    RF_ROLE='(.items[] | select(.kind == "Role"))'
    RF_POD='(.items[] | select(.kind == "Pod"))'
    world_rf_ok()          { runner_form_world; }
    world_rf_clusterrole() { runner_form_world "$RF_ROLE.kind = \"ClusterRole\""; }
    world_rf_verb()        { runner_form_world "$RF_ROLE.rules[0].verbs += [\"update\"]"; }
    world_rf_star()        { runner_form_world "$RF_ROLE.rules[2].verbs += [\"*\"]"; }
    world_rf_namespaces()  { runner_form_world "$RF_ROLE.rules += [{apiGroups: [\"\"], resources: [\"namespaces\"], verbs: [\"get\"]}]"; }
    world_rf_rbac()        { runner_form_world "$RF_ROLE.rules += [{apiGroups: [\"rbac.authorization.k8s.io\"], resources: [\"roles\"], verbs: [\"create\"]}]"; }
    world_rf_binding()     { runner_form_world '(.items[] | select(.kind == "RoleBinding")).roleRef.name = "admin"'; }
    world_rf_sa()          { runner_form_world "$RF_POD.spec.serviceAccountName = \"default\""; }
    world_rf_hostpath()    { runner_form_world "$RF_POD.spec.volumes += [{name: \"h\", hostPath: {path: \"/\"}}]"; }
    world_rf_hostnet()     { runner_form_world "$RF_POD.spec.hostNetwork = true"; }
    world_rf_priv()        { runner_form_world "$RF_POD.spec.containers[0].securityContext.privileged = true"; }
    world_rf_escalate()    { runner_form_world "$RF_POD.spec.containers[0].securityContext = {}"; }
    world_rf_nolimit()     { runner_form_world "$RF_POD.spec.containers[0].resources.limits = {}"; }
    world_rf_foreign_ns()  { runner_form_world "$RF_POD.metadata.namespace = \"kacho\""; }

    # fetch_world [cut|absent] — забор из «pod»-каталога тем же текстом перечня и потока; cut
    # обрывает поток tar на 1000 байтах в каждой попытке; absent снимает каталоги отчётов,
    # названные шаблоном без подстановочных знаков (шаги выкладывания не дошли до них).
    # Каталога src/.stand/log-public нет ни в одном мире: несуществующий путь — не отчёт.
    fetch_world() {
        ( POD="$TMP/pod-root"; rm -rf "$POD"
          mkdir -p "$POD/work/out/artifacts/rep" "$POD/work/out/venv" "$POD/src/tests/newman/out-public" "$POD/src/.stand/run" "$POD/src/tests/newman/out"
          printf '{"job": "stand"}\n' > "$POD/work/out/result.json"
          seq 1 40000 > "$POD/work/out/artifacts/rep/big.json"
          echo '{"run": {}}' > "$POD/src/tests/newman/out-public/a.json"
          # Не по шаблонам: ключ стенда, venv, невычищенный отчёт newman — машине не уходят.
          echo key > "$POD/src/.stand/run/wrapping.key"
          echo '{}' > "$POD/work/out/venv/x.json"
          echo '{"token": "x"}' > "$POD/src/tests/newman/out/raw.json"
          if [ "${1:-}" = absent ]; then rm -rf "$POD/work/out/artifacts" "$POD/src/tests/newman/out-public"; fi
          RUNNER_ROOT="$POD"; RUNNER_WORK="$POD/work"; KANAME_STAND_RUNNER_FETCH_TRIES=2
          # Pod — тот же текст оболочкой здесь: runner_exec ПРОСТРАНСТВО bash -c ТЕКСТ ИМЯ ДОВОДЫ…
          runner_exec() { shift; "$@"; }
          if [ "${1:-}" = cut ]; then
              runner_exec() { shift; if [ "$4" = fetch ]; then "$@" | head -c 1000; return 0; fi; "$@"; }
          fi
          out="$TMP/fetch-out"; rm -rf "$out"; mkdir -p "$out"
          rc=0; runner_fetch t841-kaname-own "$out" || rc=$?
          for f in src/.stand/run/wrapping.key work/out/venv/x.json src/tests/newman/out/raw.json; do
              [ ! -e "$out/$f" ] || echo "ЗАБРАНО ЛИШНЕЕ: $f"
          done
          exit "$rc" )
    }
    world_fetch_whole() { fetch_world; }
    world_fetch_cut()   { fetch_world cut; }
    world_fetch_absent() { fetch_world absent; }

    # inpod_world [настройка] — подъём изнутри pod раннера до выбора пути; путь подменён
    # заведением пространства (оно в pod лишь чистит остаток) и строкой.
    inpod_world() {
        ( PATH="$TMP/kc:$PATH"; kc_reset
          SA="$TMP/sa"; rm -rf "$SA"; mkdir -p "$SA"
          echo t841-kaname-own > "$SA/namespace"; : > "$SA/token"; : > "$SA/ca.crt"
          export KUBERNETES_SERVICE_HOST=10.9.8.7 KUBERNETES_SERVICE_PORT=443 KANAME_STAND_EXT_NS=t841-kaname-own KANAME_STAND_TASK=841
          export XDG_CONFIG_HOME="$TMP/xdg-empty"; unset KANAME_STAND_KUBECONFIG KACHO_REMOTE_KUBECONFIG
          IN_POD=1; SA_DIR="$SA"
          RUNDIR="$TMP/run-inpod"; rm -rf "$RUNDIR"; ROUTE_FILE="$RUNDIR/route"; ROUTE_LOG="$RUNDIR/route.log"
          "${1:-:}"
          up_external() { ext_claim_ns && echo "ВНЕШНИЙ ПУТЬ: $EXT_NS"; }
          up_local()    { echo "ЛОКАЛЬНЫЙ ПУТЬ"; }
          rc=0; stand_up || rc=$?
          grep -E 'create namespaces|get nodes|create -f' "$SELFTEST_KC/calls" | head -n 1 | sed 's/^/ВЫЗОВ ВНЕ СВОЕГО ПРОСТРАНСТВА: /'
          grep -q 'delete pod kaname-own' "$SELFTEST_KC/calls" && grep -q 'context=in-pod' "$SELFTEST_KC/calls" &&
            grep -q 'tokenFile' "$RUNDIR/in-pod.kubeconfig" && echo "остаток снят учёткой pod, токен — файлом"
          exit "$rc" )
    }
    inpod_foreign() { echo t999-other > "$SA/namespace"; }
    inpod_no_sa()   { rm -f "$SA/token"; }
    world_inpod_own()     { inpod_world; }
    world_inpod_foreign() { inpod_world inpod_foreign; }
    world_inpod_no_sa()   { inpod_world inpod_no_sa; }

    # inpod_ext_world <действие> — снос и перепись изнутри pod: под стенда в пространстве.
    inpod_ext_world() {
        ( PATH="$TMP/kc:$PATH"; kc_reset
          IN_POD=1; EXT_KCFG="$TMP/kc-u--prof.yaml"; EXT_CTX=in-pod; EXT_TASK=841; EXT_NS="t841-kaname-own"
          RUNDIR="$TMP/run-inpod-ext"; rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"
          : > "$SELFTEST_KC/pod"
          rc=0; "$1" || rc=$?
          grep 'delete namespace' "$SELFTEST_KC/calls" | head -n 1 | sed 's/^/СНЯТО ПРОСТРАНСТВО: /'
          exit "$rc" )
    }
    inpod_down()        { ext_teardown_ns && ext_census; }
    inpod_census_left() { ext_census; }
    world_inpod_down()        { inpod_ext_world inpod_down; }
    world_inpod_census_left() { inpod_ext_world inpod_census_left; }

    # runner_world [настройка] — runner_main целиком на подложном кластере: копия — свой
    # репозиторий из одного коммита; код команды pod — файл rc мира, фаза — файл phase.
    runner_world() {
        ( PATH="$TMP/kc:$PATH"; kc_reset
          R="$TMP/rrepo"; rm -rf "$R"; mkdir -p "$R"
          { git -C "$R" init -q && printf 'module x\n\ngo 1.26.0\n\ntoolchain go1.26.10\n' > "$R/go.mod" && git -C "$R" add go.mod &&
            git -C "$R" -c user.name=t -c user.email=t@t.invalid commit -q -m t &&
            git -C "$R" remote add origin https://github.com/PRO-Robotech/kaname.git; } || exit 9
          ROOT="$R"; RUNDIR="$TMP/run-runner"; rm -rf "$RUNDIR"
          export XDG_CONFIG_HOME="$TMP/xdg-empty"; unset KACHO_REMOTE_KUBECONFIG KANAME_STAND_CONTEXT KANAME_STAND_PROFILE KANAME_STAND_EXT_NS
          IN_POD=""; export KANAME_STAND_KUBECONFIG="$TMP/kc-u--prof.yaml" KANAME_STAND_TASK=841
          printf 'command 0\n' > "$SELFTEST_KC/rc"
          "${1:-:}"
          rc=0
          # shellcheck disable=SC2086  # доводы мира — словами
          ( runner_main ${SELFTEST_RUNNER_ARGS--- true} ) || rc=$?
          grep -qE 'create -f|apply -f' "$SELFTEST_KC/calls" && echo "ЗАПИСЬ В КЛАСТЕР БЫЛА"
          exit "$rc" )
    }
    rw_rc3()       { printf 'command 3\n' > "$SELFTEST_KC/rc"; }
    rw_setup125()  { printf 'setup 125\n' > "$SELFTEST_KC/rc"; }
    rw_cmd125()    { printf 'command 125\n' > "$SELFTEST_KC/rc"; }
    rw_pod_gone()  { rm -f "$SELFTEST_KC/rc"; echo Failed > "$SELFTEST_KC/phase"; }
    rw_dirty()     { echo '// правка' >> "$R/go.mod"; }
    rw_unnamed()   { KANAME_STAND_KUBECONFIG=""; }
    # Исходники больше буфера канала: пишущая сторона доставки ещё пишет, когда приёмник
    # уже мог выйти, — подставной, не дочитавший поток, роняет доставку на каждом прогоне.
    rw_big_src()   { head -c 262144 /dev/urandom > "$R/blob" && git -C "$R" add blob &&
                     git -C "$R" -c user.name=t -c user.email=t@t.invalid commit -q -m blob; }
    rw_src_refused() { : > "$SELFTEST_KC/exec-in-fail"; }
    # Забор настоящим текстом перечня и потока над «pod»-каталогом: один отчёт, каталогов
    # шаблонов без подстановочных знаков нет — код команды доходит (kaname#940). Поток
    # обрывается на одном и том же байте каждой попытки, как у настоящего забора
    # (kaname#1026: 95 из 121 трижды подряд): cut — до первого отчёта, ни одна попытка не
    # добавляет файла — 76; part — за первым отчётом из четырёх, каждая попытка добавляет по одному —
    # все четыре доставлены, код команды доходит.
    rw_reports() {
        local pod="$TMP/runner-pod-root"; rm -rf "$pod"; mkdir -p "$pod/work/out"
        printf '{"job": "stand"}\n' > "$pod/work/out/result.json"
        RUNNER_ROOT="$pod"; RUNNER_WORK="$pod/work"; KANAME_STAND_RUNNER_FETCH_TRIES=2
        runner_exec() { shift; "$@"; }
    }
    rw_reports_cut() {
        rw_reports
        runner_exec() { shift; if [ "$4" = fetch ]; then "$@" | head -c 100; return 0; fi; "$@"; }
    }
    rw_reports_part() {
        local i
        rw_reports; printf 'command 3\n' > "$SELFTEST_KC/rc"
        for i in 1 2 3; do head -c 4096 < <(base64 -w 0 < /dev/urandom) > "$RUNNER_WORK/out/part-$i.json"; done
        runner_exec() { shift; if [ "$4" = fetch ]; then "$@" | head -c 6000; return 0; fi; "$@"; }
    }
    rw_reports_cut_pod_gone() { rw_reports_cut; rw_pod_gone; }
    # Один изменённый факт у близнецов: стадия атомарного итога при том же коде 125.
    rw_reports_setup125()     { rw_reports; rw_setup125; }
    rw_reports_cmd125()       { rw_reports; rw_cmd125; }
    rw_reports_cut_setup125() { rw_reports_cut; rw_setup125; }
    rw_reports_cut_cmd125()   { rw_reports_cut; rw_cmd125; }
    rw_ns_exists() { echo own > "$SELFTEST_KC/ns/t841-kaname-own"; }
    world_runner_ok()        { runner_world; }
    world_runner_rc3()       { runner_world rw_rc3; }
    world_runner_pod_gone()  { runner_world rw_pod_gone; }
    world_runner_dirty()     { runner_world rw_dirty; }
    world_runner_unnamed()   { runner_world rw_unnamed; }
    world_runner_big_src()   { runner_world rw_big_src; }
    world_runner_src_refused() { runner_world rw_src_refused; }
    world_runner_ns_exists() { runner_world rw_ns_exists; }
    world_runner_no_cmd()    { ( SELFTEST_RUNNER_ARGS=""; runner_world ); }
    world_runner_reports()     { runner_world rw_reports; }
    world_runner_reports_cut() { runner_world rw_reports_cut; }
    world_runner_reports_part() { runner_world rw_reports_part; }
    world_runner_reports_cut_pod_gone() { runner_world rw_reports_cut_pod_gone; }
    world_runner_reports_setup125()     { runner_world rw_reports_setup125; }
    world_runner_reports_cmd125()       { runner_world rw_reports_cmd125; }
    world_runner_reports_cut_setup125() { runner_world rw_reports_cut_setup125; }
    world_runner_reports_cut_cmd125()   { runner_world rw_reports_cut_cmd125; }

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

    echo "--- ось 2: накатчик отказал — класс называет ЕГО КОД, а не слова в выводе"
    assert 0  "(−) накат прошёл — 0"                               world_migrate_ok     "миграции накачены" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) код 75 при тексте БЕЗ единого слова прежнего образца: читатель, судящий
    # текст, назвал бы это находкой и послал бы чинить чужое расписание.
    assert 75 "(+) накатчик назвал базу недостижимой — 75"          world_migrate_unmet  "накатчик не дотянулся до базы" "-" "НАХОДКА"
    # (+) КЛАСС ЗАДАЧИ #22: код 1 при `sslmode` в эхе ввода. Прежний читатель
    # отвечал здесь 75, и неверная посадка не краснела ни разу.
    assert 1  "(+) эхо ввода несёт sslmode, а предмет — посадка — 1" world_migrate_echo   "накатчик отказал" "names no host" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) перекрёстная инъекция: проза ТА ЖЕ, что у недостижимой базы, код иной.
    assert 1  "(+) проза о соединении при коде находки — 1"         world_migrate_conn   "накатчик отказал" "connection refused" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) отказ, к базе не относящийся вовсе: причина обязана доехать дословно.
    assert 1  "(+) строка подключения не собралась — 1"             world_migrate_config "накатчик отказал" "dsn unset" "УСЛОВИЕ НЕ СОЗДАНО"
    # (−) третий вход: эхо прежнего образца в выводе ЕСТЬ, а отказа нет. Успех
    # обязан остаться успехом, и уведомление сервера обязано доехать до читателя.
    assert 0  "(−) эхо в выводе при коде 0 — 0, и текст доехал"     world_migrate_ok_noisy "миграции накачены" "password_hash" "УСЛОВИЕ НЕ СОЗДАНО"

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

    echo "--- ось 6: свёртка базы для волны отказа — несозданное условие не выдаётся за вердикт"
    # (−) ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ первым: контейнер остановлен и остановку видно.
    assert 0  "(−) свёртка: контейнер остановлен — 0"                world_fold_ok        "база стенда свёрнута" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) один факт против близнеца: остановить не вышло. Волна без свёртки
    # проверяла бы живую базу — это несозданное условие, а не находка.
    assert 75 "(+) свёртка: остановить не вышло — 75"                world_fold_stop_fails "базу стенда не свернуть" "No such container" "НАХОДКА"
    # (+) другой факт: остановка «прошла», а контейнер исполняется. Код клиента
    # здесь успешен, поэтому без сверки состояния свёртка была бы объявлена.
    assert 75 "(+) свёртка: контейнер продолжает исполняться — 75"   world_fold_stays     "по-прежнему исполняется" "-" "НАХОДКА"
    assert 75 "(+) свёртка без клиента контейнера — 75"              world_fold_no_docker "инструмента нет: docker" "-" "НАХОДКА"
    # (−) возврат: база снова принимает соединения.
    assert 0  "(−) возврат: база снова принимает соединения — 0"     world_unfold_ok      "база стенда возвращена" "-" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) один факт против близнеца: контейнер стартовал, база не отвечает.
    assert 75 "(+) возврат: база не ответила — 75"                   world_unfold_never_ready "не ответила pg_isready" "-" "НАХОДКА"

    echo "--- ось 7: волна свёртки СОЗДАЁТ условие свежих кешей, а истёкшее окно не выдаёт за вердикт"
    # (−) ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ первым. Прогрев — в 1032, то есть ПОСЛЕ тишины
    # 30 + 2 с по часам мира: без тишины он пришёлся бы на 1000.
    assert 0  "(−) волна: тишина, прогрев промахом, коллекция в окне — 0" world_wave_ok "предъявлено фронту в 1032" "коллекция исполнялась" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) красное ВНУТРИ окна — вердикт о дереве, и страж его не глотает.
    assert 1  "(+) волна: красное внутри окна — код коллекции"            world_wave_red_inside "коллекция исполнялась" "код 1" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) один факт против близнеца выше: коллекция кончилась за окном.
    assert 75 "(+) волна: красное за окном — 75, причина названа"        world_wave_red_expired "истекло посреди коллекции" "коллекция исполнялась" "НАХОДКА"
    # (+) окно истекло ещё до вызовов — коллекция не гоняется вовсе.
    assert 75 "(+) волна: окно истекло до вызовов — 75, коллекции нет"   world_wave_slow_fold "истекло до вызовов" "-" "коллекция исполнялась"
    # (+) тишина — функция ПОСАДКИ: другой срок кеша отзыва даёт другую тишину.
    assert 0  "(+) волна: срок отзыва 45 с — тишина 47 с"                world_wave_rev_longer "тишина 47 с" "предъявлено фронту в 1047" "УСЛОВИЕ НЕ СОЗДАНО"
    # (+) окно — МЕНЬШИЙ из сроков: снимок 60 с не продлевает окна отзыва 30 с.
    assert 75 "(+) волна: окно по меньшему сроку — 75"                    world_wave_window_smaller "истекло посреди коллекции" "при окне 30 с" "НАХОДКА"
    assert 75 "(+) волна: прогрев отвергнут — 75, коллекции нет"          world_wave_warm_refused "не принят фронтом" "код 401" "коллекция исполнялась"
    assert 1  "(+) волна: срок не разобран — 1, коллекции нет"            world_wave_ttl_garbage "не разобран" "KEY_SET_TTL" "коллекция исполнялась"
    # (+) суд без подготовки: отметки нет — красное коллекции не вердикт.
    assert 75 "(+) волна: суд без отметки прогрева — 75"                  world_wave_no_state "отметки прогрева нет" "код 1" "НАХОДКА"

    echo "--- ось 8: снос стенда не оставляет анонимных томов базы (kaname#710)"
    # (+) ЗАКОННЫЙ БЛИЗНЕЦ первым: голый `rm -f` подложный клиент обязан увидеть
    # сиротой, иначе ноль ниже был бы постоянной строкой, а не замером.
    assert 1  "(+) голый rm -f оставляет том — 1, перепись называет его" world_vol_bare_rm "томов-сирот после сноса: 1" "-" "томов-сирот после сноса: 0"
    # (−) подъём и снос: том базы снят вместе с контейнером.
    assert 0  "(−) up → down: томов-сирот 0"                           world_vol_down    "томов-сирот после сноса: 0" "-" "томов-сирот после сноса: 1"
    # (−) повторный подъём сносит прежний контейнер базы — тоже с его томом.
    assert 0  "(−) up → up → down: томов-сирот 0"                      world_vol_reup_down "томов-сирот после сноса: 0" "-" "томов-сирот после сноса: 1"

    echo "--- ось 9: внешний кластер доступен — стенд уходит туда; docker — только по записанному основанию (kaname#841)"
    # (−) ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ первым: кластер отвечает — внешний путь, локального нет.
    assert 0  "(−) кластер доступен — внешний путь, пространство задачи"    world_route_available "маршрут стенда: внешний кластер" "ВНЕШНИЙ ПУТЬ: t841-kaname-own" "ЛОКАЛЬНЫЙ ПУТЬ"
    # (+) один факт против близнеца: кубконфига нет — локально, основание в журнале.
    assert 0  "(+) кубконфиг не назван — локальный путь, основание записано" world_route_unnamed "ЛОКАЛЬНЫЙ ПУТЬ" "route=local ns=- why=кубконфиг внешнего кластера не назван" "ВНЕШНИЙ ПУТЬ"
    # (+) кластер не ответил — локально, вывод проверки в журнале, адреса скрыты.
    assert 0  "(+) кластер не ответил — локальный путь с выводом проверки"   world_route_silent "ЛОКАЛЬНЫЙ ПУТЬ" "auth can-i create namespaces: код 1" "10.1.2.3"
    assert 0  "(+) адрес сервера в выводе проверки замаскирован"            world_route_silent "<кластер>" "-" "api.stand.example"
    # (+) узлы не того кластера: кубконфиг подменён — внешний путь не берётся.
    assert 0  "(+) узел -infra- среди узлов — локальный путь, названо почему" world_route_infra_nodes "ЛОКАЛЬНЫЙ ПУТЬ" "с -infra- 1" "ВНЕШНИЙ ПУТЬ"
    assert 0  "(+) два контекста -client — локальный путь, названо почему"   world_route_two_clients "ЛОКАЛЬНЫЙ ПУТЬ" "контекстов -client в кубконфиге 2" "ВНЕШНИЙ ПУТЬ"
    # (+) явный контекст не -client — отказ 64, и тихо локально стенд не идёт.
    assert 64 "(+) явный контекст не -client — отказ 64"                      world_route_bad_override "только контекст -client" "-" "ЛОКАЛЬНЫЙ ПУТЬ"
    # (+) кластер доступен, номера задачи нет — отказ 64, а не docker.
    assert 64 "(+) кластер доступен без номера задачи — отказ 64, не docker"  world_route_no_task "номера задачи нет" "-" "ЛОКАЛЬНЫЙ ПУТЬ"

    echo "--- ось 10: внешнее пространство снимается своей задачей, чужое не трогается, перепись — числом"
    assert 0  "(−) снос своего пространства — перепись 0"                   world_ext_down_own "пространство t841-kaname-own снято" "задачи 841 во внешнем кластере: 0" "НАХОДКА"
    # (+) законный близнец переписи: оставшееся пространство она видит.
    assert 1  "(+) пространство осталось — перепись 1, код 1"                world_ext_census_left "задачи 841 во внешнем кластере: 1" "-" "задачи 841 во внешнем кластере: 0"
    assert 75 "(+) снос чужого пространства — отказ, не снято"               world_ext_down_foreign "заведено не этим стендом" "-" "снято"
    assert 75 "(+) подъём в чужое пространство — отказ, не заведено"          world_ext_claim_foreign "заведено не этим стендом" "-" "НАХОДКА"

    echo "--- ось 11: слушатели пода — по таблице сокетов ядра, а не по пробросу"
    assert 0  "(−) оба порта в LISTEN — слушатели на месте"                 world_tcp_both "все слушатели пода на месте" "-" "НЕ слушает"
    assert 1  "(+) второй порт не в LISTEN — назван недостающий"            world_tcp_one ":9091 НЕ слушает" ":9090 слушает" "все слушатели пода на месте"

    echo "--- ось 12: раннер — форма объектов судится до записи, роль лишь в своём пространстве (kaname#940)"
    RF_BAD="$(printf 'RUNNER-FORM\t')"
    assert 0  "(−) настоящий вывод runner_objects — форма сошлась"           world_rf_ok "RUNNER-FORM-OK" "правил роли 5" "$RF_BAD"
    assert 1  "(+) ClusterRole вместо роли пространства"                     world_rf_clusterrole "виды объектов" "-" "RUNNER-FORM-OK"
    assert 1  "(+) глагол сверх нужного на подах"                            world_rf_verb "['update'] на pods сверх нужного" "-" "RUNNER-FORM-OK"
    assert 1  "(+) звезда в глаголах"                                        world_rf_star "роль со звездой" "-" "RUNNER-FORM-OK"
    assert 1  "(+) пространства — вне нужного стенду"                        world_rf_namespaces "на namespaces — вне нужного стенду" "-" "RUNNER-FORM-OK"
    assert 1  "(+) правило вне основной группы API"                          world_rf_rbac "вне основной группы API" "-" "RUNNER-FORM-OK"
    assert 1  "(+) привязка к чужой роли"                                    world_rf_binding "а не к роли раннера" "-" "RUNNER-FORM-OK"
    assert 1  "(+) pod под чужой учёткой"                                    world_rf_sa "pod под учёткой default" "-" "RUNNER-FORM-OK"
    assert 1  "(+) том узла"                                                 world_rf_hostpath "том hostPath h" "-" "RUNNER-FORM-OK"
    assert 1  "(+) сеть узла"                                                world_rf_hostnet "pod: hostNetwork" "-" "RUNNER-FORM-OK"
    assert 1  "(+) привилегированный контейнер"                              world_rf_priv "privileged либо добавленные возможности" "-" "RUNNER-FORM-OK"
    assert 1  "(+) повышение прав не запрещено"                              world_rf_escalate "повышение прав не запрещено" "-" "RUNNER-FORM-OK"
    assert 1  "(+) контейнер без предела памяти"                             world_rf_nolimit "без предела памяти" "-" "RUNNER-FORM-OK"
    assert 1  "(+) объект вне своего пространства"                           world_rf_foreign_ns "вне своего пространства t841-kaname-own" "-" "RUNNER-FORM-OK"

    echo "--- ось 13: раннер — отчёты сверены с перечнем pod, лишнее машине не уходит"
    assert 0  "(−) целый поток — доставлено 3 из 3, ни ключа, ни venv, ни сырого отчёта" world_fetch_whole "доставлено 3 из 3" "размер и сумма каждого сверены" "ЗАБРАНО ЛИШНЕЕ"
    assert 1  "(+) поток оборван в каждой попытке — неполно, с перечнем"     world_fetch_cut "ОТЧЁТЫ ДОСТАВЛЕНЫ НЕПОЛНО" "попытка 2 — доставлено" "доставлено 3 из 3"
    assert 0  "(−) каталогов шаблонов нет — не отчёт, доставлено 1 из 1"     world_fetch_absent "доставлено 1 из 1" "размер и сумма каждого сверены" "перечень отчётов в pod не собран"

    echo "--- ось 14: стенд изнутри pod раннера — лишь своё пространство, пространств не заводит"
    assert 0  "(−) своё пространство — внешний путь, учётка pod"             world_inpod_own "ВНЕШНИЙ ПУТЬ: t841-kaname-own" "остаток снят учёткой pod, токен — файлом" "ВЫЗОВ ВНЕ СВОЕГО ПРОСТРАНСТВА"
    assert 64 "(+) pod в чужом пространстве — отказ 64"                      world_inpod_foreign "стенд ставится лишь в своё пространство" "-" "ВНЕШНИЙ ПУТЬ"
    assert 64 "(+) учётки pod нет — отказ 64"                                world_inpod_no_sa "лишь изнутри pod раннера" "-" "ВНЕШНИЙ ПУТЬ"
    assert 0  "(−) снос изнутри pod — объекты сняты, пространство не трогается" world_inpod_down "пространстве раннера t841-kaname-own: 0" "пространство снимает раннер машины" "СНЯТО ПРОСТРАНСТВО"
    assert 1  "(+) под стенда остался — перепись 1, код 1"                   world_inpod_census_left "пространстве раннера t841-kaname-own: 1" "-" "пространстве раннера t841-kaname-own: 0"

    echo "--- ось 15: раннер с машины — код команды pod, пространство снимается всегда, отказы до записи"
    assert 0  "(−) команда pod 0 — код 0, пространство снято, перепись 0"    world_runner_ok "раннер: код 0" "задачи 841 во внешнем кластере: 0" "УСЛОВИЕ НЕ СОЗДАНО"
    assert 3  "(+) команда pod 3 — код 3, пространство снято всё равно"      world_runner_rc3 "раннер: код 3" "задачи 841 во внешнем кластере: 0" "УСЛОВИЕ НЕ СОЗДАНО"
    assert 125 "(+) pod вышел без кода — 125, не красное"                    world_runner_pod_gone "кода команды из pod нет" "задачи 841 во внешнем кластере: 0" "раннер: код 0"
    assert 0  "(−) исходники больше буфера канала — доставлены, код 0"      world_runner_big_src "раннер: код 0" "-" "в pod не доставлены"
    assert 125 "(+) приёмник исходников в pod отказал — 125, не красное"     world_runner_src_refused "в pod не доставлены" "задачи 841 во внешнем кластере: 0" "раннер: код 0"
    assert 64 "(+) правка вне коммита — 64 до записи"                        world_runner_dirty "правки вне коммита" "-" "ЗАПИСЬ В КЛАСТЕР БЫЛА"
    assert 125 "(+) кубконфиг не назван — 125, локального подъёма нет"      world_runner_unnamed "pod раннеру ставить негде" "-" "ЗАПИСЬ В КЛАСТЕР БЫЛА"
    assert 1  "(+) пространство уже есть — 1 до записи"                      world_runner_ns_exists "уже есть" "-" "ЗАПИСЬ В КЛАСТЕР БЫЛА"
    assert 64 "(+) команда не названа — 64 до записи"                        world_runner_no_cmd "команда не названа" "-" "ЗАПИСЬ В КЛАСТЕР БЫЛА"
    assert 0  "(−) команда 0, отчёт забран перечнем pod — код 0"            world_runner_reports "доставлено 1 из 1" "раннер: команда в pod завершилась кодом 0" "УСЛОВИЕ НЕ СОЗДАНО"
    assert 3  "(−) поток забора рвётся за первым отчётом — повтор недоставленного, 4 из 4, код команды" world_runner_reports_part "доставлено 4 из 4" "раннер: команда в pod завершилась кодом 3" "НЕПОЛНО"
    assert 76 "(+) поток забора рвётся в каждой попытке до отчёта — 76, не 125" world_runner_reports_cut "доставлено 0 из 1 при коде команды 0" "отказ забора: «tar:" "раннер: команда в pod завершилась кодом 0"
    assert 76 "(+) тот же обрыв — пространство снято, код 76"                  world_runner_reports_cut "задачи 841 во внешнем кластере: 0" "раннер: код 76" "раннер: код 125"
    assert 125 "(+) pod вышел без кода, забор оборван — 125, не 76"           world_runner_reports_cut_pod_gone "кода команды из pod нет" "-" "НЕ ВЫПОЛНИЛОСЬ: отчёты"
    assert 125 "(+) setup 125, отчёт забран — команда не исполнялась"          world_runner_reports_setup125 "подготовка pod завершилась кодом 125 до команды" "доставлено 1 из 1" "раннер: команда в pod завершилась"
    assert 125 "(+) setup 125 и тот же обрыв — не подменяется на 76"             world_runner_reports_cut_setup125 "подготовка pod завершилась кодом 125 до команды" "задачи 841 во внешнем кластере: 0" "раннер: код 76"
    assert 125 "(−) настоящая команда 125 и полный отчёт — код команды 125"     world_runner_reports_cmd125 "раннер: команда в pod завершилась кодом 125" "доставлено 1 из 1" "подготовка pod завершилась"
    assert 76 "(+) настоящая команда 125 и тот же обрыв — неполные отчёты 76"   world_runner_reports_cut_cmd125 "доставлено 0 из 1 при коде команды 125" "задачи 841 во внешнем кластере: 0" "подготовка pod завершилась"

    echo
    echo "stand-own --self-test: проб исполнено $probes, утверждений $checks, провалов $failed"
    [ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
    [ "$failed" -gt 0 ] && exit 1
    exit 0
fi

case "${1:-}" in
  up) stand_up; exit $? ;;
  env)
    # Печать посадки для соседнего шага: он читает её `eval`-ом, а не повторяет.
    stand_env
    env | grep -E '^KANAME_' | sort
    exit 0
    ;;
  down) stand_down; exit $? ;;
  runner) shift; runner_main "$@"; exit $? ;;
  census)
    # Перепись внешних пространств задачи: после `down` — 0 (kaname#841).
    if ! route_load; then
      route_decide || exit $?
      if [ "$ROUTE" != external ]; then say "внешний кластер недоступен ($WHY) — переписывать нечего"; exit 0; fi
      ext_name_ns || exit $?
    fi
    ext_census; exit $? ;;
  db-fold) db_fold_routed; exit 0 ;;
  db-unfold) db_unfold_routed; exit 0 ;;
  failclosed-prepare) failclosed_prepare "${2:-}"; exit 0 ;;
  failclosed-judge) failclosed_judge "${2:-}"; exit $? ;;
  *)
    printf 'использование: %s {up|env|down|runner|census|db-fold|db-unfold|failclosed-prepare|failclosed-judge|--self-test}\n' "$0" >&2
    exit 2
    ;;
esac
