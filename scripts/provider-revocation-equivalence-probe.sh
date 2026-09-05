#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
# provider-revocation-equivalence-probe.sh
#
# ВОПРОС (#797). Делает ли снятие СЕССИИ ВХОДА у провайдера уже выданный ТОКЕН
# ДОСТУПА неактивным в интроспекции? Это свойство ПРОВАЙДЕРА; в нашем дереве оно
# не выражено, поэтому его нельзя вывести чтением кода — только спросить.
#
# ЗАЧЕМ ЭТО СКРИПТ, А НЕ ЗАПИСЬ В ДОКУМЕНТЕ. Ответ — про стороннюю программу
# конкретной версии. Он МОЛЧА протухнет при её подъёме, а документ об этом не
# узнает. Скрипт можно перепрогнать на новой версии одной командой:
#
#     IMG=oryd/hydra:<новая версия> bash services/iam/scripts/provider-revocation-equivalence-probe.sh
#
# ИЗОЛЯЦИЯ. Провайдер поднимается СВОЙ, с памятью вместо базы, на локальных
# портах. Ни одна строка общего стенда не читается и не меняется — проба не
# зависит от того, занят ли стенд, и не мешает тому, кто его занял.
#
# КОНТРОЛИ В ОБЕ СТОРОНЫ — иначе «токен активен» неотличимо от «проба сломана»:
#   К1 (положительный) свежий токен       → active=true
#   К2 (отрицательный) штатный отзыв      → active=false
#   К3 (отрицательный) заведомо мусорный  → active=false
# Проба, у которой К2 не сработал, вердикта НЕ выносит и выходит кодом 2.
#
# КОДЫ ВОЗВРАТА: 0 — не эквивалентны (сессия снята, токен жив); 1 — эквивалентны;
# 2 — ПРОБА НЕ ВЫПОЛНЕНА (провайдер не поднялся, токен не выдан, контроль не
# сработал). Третий исход отдельный намеренно: «не выполнилось» не вычитается из
# вердикта и не зачитывается ни в одну сторону.
set -uo pipefail

IMG=${IMG:-oryd/hydra:v26.2.0}
NAME=${NAME:-hydra-revocation-probe}
PUB=http://127.0.0.1:${PUB_PORT:-14444}
ADMIN=http://127.0.0.1:${ADMIN_PORT:-14445}
SUBJ=usr-probe-subject
JAR=$(mktemp)
cleanup(){ docker rm -f "$NAME" >/dev/null 2>&1; rm -f "$JAR"; }
trap cleanup EXIT

say(){ printf '%s\n' "$*"; }
die(){ say "ПРОБА НЕ ВЫПОЛНЕНА: $*"; exit 2; }
intro(){ curl -s -X POST "$ADMIN/admin/oauth2/introspect" -d "token=$1" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("active"))' 2>/dev/null; }

docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e DSN=memory -e URLS_SELF_ISSUER="$PUB" \
  -e SECRETS_SYSTEM=probe-secret-probe-secret-32chars \
  -e STRATEGIES_ACCESS_TOKEN=opaque -e TTL_ACCESS_TOKEN=1h \
  -p "127.0.0.1:${PUB_PORT:-14444}:4444" -p "127.0.0.1:${ADMIN_PORT:-14445}:4445" \
  "$IMG" serve all --dev >/dev/null 2>&1 || die "не удалось запустить $IMG"
for _ in $(seq 1 40); do curl -sf "$ADMIN/health/ready" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "$ADMIN/health/ready" >/dev/null 2>&1 || die "$IMG не пришёл в готовность"
say "провайдер: $IMG (изолированный, DSN=memory)"

curl -s -X POST "$ADMIN/admin/clients" -H 'Content-Type: application/json' -d '{
 "client_id":"probe-web","client_secret":"probe-secret",
 "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
 "redirect_uris":["http://127.0.0.1:19999/cb"],"scope":"openid offline",
 "token_endpoint_auth_method":"client_secret_post"}' >/dev/null

# Поток входа целиком через админ-API с банкой печений — сессия входа заводится
# ТОЛЬКО при remember=true, поэтому браузер не нужен, а сессия настоящая.
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -c "$JAR" \
 "$PUB/oauth2/auth?client_id=probe-web&response_type=code&scope=openid+offline&redirect_uri=http%3A%2F%2F127.0.0.1%3A19999%2Fcb&state=probestate12345678")
LC=${LOC##*login_challenge=}; LC=${LC%%&*}
[ -n "$LC" ] || die "провайдер не выдал login_challenge"
RT=$(curl -s -X PUT "$ADMIN/admin/oauth2/auth/requests/login/accept?login_challenge=$LC" \
 -H 'Content-Type: application/json' \
 -d "{\"subject\":\"$SUBJ\",\"remember\":true,\"remember_for\":3600}" \
 | python3 -c 'import json,sys;print(json.load(sys.stdin).get("redirect_to",""))')
LOC2=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$JAR" -c "$JAR" "$RT")
CC=${LOC2##*consent_challenge=}; CC=${CC%%&*}
[ -n "$CC" ] || die "провайдер не выдал consent_challenge"
RT2=$(curl -s -X PUT "$ADMIN/admin/oauth2/auth/requests/consent/accept?consent_challenge=$CC" \
 -H 'Content-Type: application/json' \
 -d '{"grant_scope":["openid","offline"],"remember":true,"remember_for":3600,"session":{}}' \
 | python3 -c 'import json,sys;print(json.load(sys.stdin).get("redirect_to",""))')
CB=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$JAR" -c "$JAR" "$RT2")
CODE=${CB##*[?&]code=}; CODE=${CODE%%&*}
TOK=$(curl -s -X POST "$PUB/oauth2/token" -d grant_type=authorization_code -d "code=$CODE" \
 -d 'redirect_uri=http://127.0.0.1:19999/cb' -d client_id=probe-web -d client_secret=probe-secret)
AT=$(echo "$TOK" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("access_token",""))')
RF=$(echo "$TOK" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("refresh_token",""))')
[ -n "$AT" ] || die "токен доступа не выдан"

[ "$(intro "$AT")" = "True" ] || die "К1: свежий токен не читается активным — спрашивать нечего"
say "К1 ok: свежий токен active=True"

HC=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$ADMIN/admin/oauth2/auth/sessions/login?subject=$SUBJ")
[ "$HC" = "204" ] || die "провайдер не принял снятие сессии (HTTP $HC)"
sleep 1
AFTER=$(intro "$AT")
say "ПРОБА: сессия входа снята (204) → интроспекция токена active=$AFTER"

NEW_AT=$(curl -s -X POST "$PUB/oauth2/token" -d grant_type=refresh_token \
 -d "refresh_token=$RF" -d client_id=probe-web -d client_secret=probe-secret \
 | python3 -c 'import json,sys;print(json.load(sys.stdin).get("access_token",""))')
if [ -n "$NEW_AT" ]; then
  say "СЛЕДСТВИЕ: refresh ПОСЛЕ снятия сессии чеканит НОВЫЙ токен — ДА"
else
  say "СЛЕДСТВИЕ: refresh ПОСЛЕ снятия сессии чеканит НОВЫЙ токен — нет"
fi

# К2 гоняется на ЗАВЕДОМО ЖИВОМ токене. Раньше здесь стоял $AT — и это было
# негодно: обновление ротирует набор, гася предъявленный токен, поэтому К2
# «проходил» на токене, который погасил не отзыв, а предыдущий шаг. Контроль,
# не создающий своего условия, подтверждает не то, что утверждает; поймано
# инъекцией «отзыв не зовётся» — она осталась зелёной.
K2AT=${NEW_AT:-$AT}
[ "$(intro "$K2AT")" = "True" ] || die "К2: контрольный токен не активен ДО отзыва — гасить нечего"
curl -s -o /dev/null -X POST "$PUB/oauth2/revoke" -d "token=$K2AT" \
 -d client_id=probe-web -d client_secret=probe-secret
sleep 1
[ "$(intro "$K2AT")" = "False" ] || die "К2: штатный отзыв не погасил токен — проба не умеет видеть неактивность"
[ "$(intro 'ory_at_bogus')" = "False" ] || die "К3: мусорный токен читается активным"
say "К2 ok: штатный отзыв → active=False;  К3 ok: мусор → active=False"

say ""
if [ "$AFTER" = "True" ]; then
  say "ВЕРДИКТ: НЕ ЭКВИВАЛЕНТНЫ — снятие сессии входа НЕ гасит выданный токен."
  exit 0
fi
say "ВЕРДИКТ: эквивалентны — снятие сессии входа погасило токен."
exit 1
