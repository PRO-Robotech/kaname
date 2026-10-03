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
# Он поднимает ПРОЦЕСС, а не ЧАРТ: helm, kubectl и kind в нём не встречаются ни
# разу. Значит вердикта об установке в кластере он не даёт вовсе — ни зелёного,
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
  mkdir -p "$RUNDIR" "$PKI"
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
  # ─── ПОЧТОВЫЕ РУЧКИ ТАБЛИЦЫ Р8 И ФЛАГ ПОЧТЫ (приёмка NTF-2 Р4, Р8; Д11) ──
  #
  # Страж таблицы границ (`config.ValidateMailBounds`) требует их на ЛЮБОЙ
  # посадке и в любом режиме, умолчаний нет ни у одной: без них старт
  # отказывает, называя каждый ключ. Числа — те же, что объявляет боевой
  # профиль (`deploy/values.prod.yaml`: блоки `authn.login`, `invite`,
  # `notifications`), — стенд судит посадку, которую поставка уносит клиенту.
  export KANAME_NOTIFICATIONS__ENABLED=true
  export KANAME_AUTHN__LOGIN__REGISTRATION_CODE_TTL=60m
  local purpose
  for purpose in RECOVERY VERIFICATION REGISTRATION; do
    export "KANAME_AUTHN__LOGIN__MAIL_WINDOW__${purpose}__FIRST_PAUSE=60s"
    export "KANAME_AUTHN__LOGIN__MAIL_WINDOW__${purpose}__SECOND_PAUSE=5m"
    export "KANAME_AUTHN__LOGIN__MAIL_WINDOW__${purpose}__PER_HOUR=3"
    export "KANAME_AUTHN__LOGIN__MAIL_WINDOW__${purpose}__PER_DAY=5"
    export "KANAME_AUTHN__LOGIN__MAIL_WINDOW__${purpose}__FLOOR_INTERVAL=6h"
  done
  export KANAME_AUTHN__LOGIN__ATTEMPTS__ADDRESS_SOURCE_PER_WINDOW=5
  export KANAME_AUTHN__LOGIN__ATTEMPTS__WINDOW=15m
  export KANAME_AUTHN__LOGIN__ATTEMPTS__ADDRESS_FAILURE_CEILING=100
  export KANAME_AUTHN__LOGIN__MAIL_THROTTLED_INTERVAL=168h
  export KANAME_AUTHN__LOGIN__TRUSTED_DEVICE__TTL=2160h
  export KANAME_AUTHN__LOGIN__TRUSTED_DEVICE__RECOVERY_PER_DAY=2
  export KANAME_INVITE__TTL=168h
  export KANAME_INVITE__ACCOUNT_PER_DAY=200
  export KANAME_INVITE__YOUNG_ACCOUNT_PER_DAY=50
  export KANAME_INVITE__YOUNG_ACCOUNT_AGE=720h
  export KANAME_INVITE__PENDING_MAX=200
  export KANAME_INVITE__RECIPIENT_PER_HOUR=3
  export KANAME_INVITE__RECIPIENT_PER_DAY=5
  export KANAME_INVITE__RECIPIENT_PER_DAY_ALL=10
  # ФАЙЛЫ КЛЮЧЕЙ ПОЧТОВОЙ ПОЛОСЫ (замысел NTF-2 З18): k_window и k_device —
  # по 32 случайных байта, ФАЙЛАМИ под каталогом УЦ стенда: его контейнер
  # службы монтирует тем же путём (только чтение), а процесс читает путь, а не
  # значение. В окружение и в печать посадки (`env`) уходят ПУТИ — сами ключи
  # не попадают ни в лог, ни в окружение. Ключи ПОСТОЯННЫ, как ключи обёртки
  # выше: смена k_window начинает окна адресатов заново, смена k_device снимает
  # все метки устройств.
  if [ ! -f "$PKI/mail-window.key" ] || [ ! -f "$PKI/device-label.key" ]; then
    ( umask 077
      openssl rand 32 > "$PKI/mail-window.key" && openssl rand 32 > "$PKI/device-label.key" ) || {
        unmet "ключи почтовой полосы не выпустились (openssl)"; exit "$RC_UNMET"; }
  fi
  export KANAME_AUTHN__SECRETS__MAIL_WINDOW_KEY_FILE="$PKI/mail-window.key"
  export KANAME_AUTHN__SECRETS__DEVICE_LABEL_KEY_FILE="$PKI/device-label.key"
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
  out="$("$BIN/kaname-migrator" up 2>&1)"; rc=$?
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
  mkdir -p "$RUNDIR" "$PKI"
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
  mkdir -p "$RUNDIR" "$PKI"
  local envs=() v
  # Посадка уезжает в контейнер ИМЕНАМИ, а не значениями: `-e ИМЯ` берёт
  # величину из окружения, и ключи с переводом строки доезжают целыми. Ручки
  # самого стенда (`KANAME_STAND_*`) службе не принадлежат и не передаются.
  for v in $(compgen -e); do
    case "$v" in KANAME_STAND_*) ;; KANAME_*) envs+=(-e "$v") ;; esac
  done
  docker rm -f "$SERVICE_NAME" >/dev/null 2>&1
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
  command -v docker >/dev/null 2>&1 && docker rm -f "$SERVICE_NAME" "$PG_NAME" >/dev/null 2>&1
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
  fold_db
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
    make_pki; start_pg; start_mailbox; stand_env; build_binaries; migrate; start_service
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
  db-fold) fold_db; exit 0 ;;
  db-unfold) unfold_db; exit 0 ;;
  failclosed-prepare) failclosed_prepare "${2:-}"; exit 0 ;;
  failclosed-judge) failclosed_judge "${2:-}"; exit $? ;;
  *)
    printf 'использование: %s {up|env|down|db-fold|db-unfold|failclosed-prepare|failclosed-judge|--self-test}\n' "$0" >&2
    exit 2
    ;;
esac
