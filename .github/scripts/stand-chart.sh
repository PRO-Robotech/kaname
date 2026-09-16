#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

# stand-chart.sh — подъём службы ЧАРТОМ в настоящем кластере.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЗАЧЕМ ОН ЕСТЬ, ЕСЛИ РЯДОМ УЖЕ ЛЕЖИТ stand-own.sh
#
# Предметы у них РАЗНЫЕ, и различие несущее.
#
#   stand-own.sh   поднимает ПРОЦЕСС: свой бинарь, свой Postgres в docker, свой
#                  УЦ. Он доказывает, что служба живёт без платформы, и ничего
#                  не утверждает о ЧАРТЕ — helm, kubectl и kind в нём не
#                  встречаются ни разу.
#   render-guard.sh судит РЕНДЕР: вход, который чарт отдаёт процессу, страж
#                  старта принимает. Его собственная шапка говорит прямо: «пода
#                  не поднимает и об установке в кластере не утверждает ничего».
#   ЭТОТ скрипт    закрывает оставшуюся половину: `helm install` в живом
#                  кластере плюс ГОТОВНОСТЬ ВЫКАТА, а не только успешная
#                  установка. «Под Ready» доказательством посадки не является —
#                  процесс мог подняться в другой посадке, поэтому посадка
#                  сверяется по ДВУМ независимым источникам: самоотчёту процесса
#                  при старте и `pg_stat_ssl` со стороны базы.
#
# Предикат веха M11 требует ПАРУ, и первая её половина — ровно это:
# «отдельный клон поднимается в боевой посадке: helm install + rollout-ready,
# не только helm template».
#
# ─────────────────────────────────────────────────────────────────────────────
# ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ (та же дисциплина, что у stand-own.sh)
#
#   0  — стенд поднят и посадка сошлась;
#   1  — НАХОДКА: чарт не поставился, выкат не дошёл до готовности, либо
#        объявленная посадка разошлась с фактической. Это вердикт о дереве;
#   75 — УСЛОВИЕ НЕ СОЗДАНО: нет docker/kind/helm/kubectl, нет вида
#        PrometheusRule, не работает DNS кластера, не поднялась база. Вердикта о
#        дереве нет НИ ОДНОГО.
#
# Различие несущее ровно так же: отказ стража посадки — находка, а неподнявшийся
# кластер — расписание. Перепутать их значит либо спрятать дефект, либо объявить
# дефектом чужую машину.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЧЕГО ЭТОТ СТЕНД НЕ ДЕЛАЕТ, И ЭТО НАЗВАНО, А НЕ ПОДРАЗУМЕВАЕТСЯ
#
#   · он НЕ поднимает внешнего поставщика удостоверений. Адреса поставщика
#     ОБЪЯВЛЕНЫ и недостижимы намеренно: страж требует, чтобы их НАЗВАЛИ
#     (выведенный из издателя адрес выглядел бы настроенным, никуда не ведя), но
#     соединения при старте не делает. Пути, которым поставщик нужен, отвечают
#     честным отказом — и это ровно то состояние, в котором служба стоит у того,
#     у кого поставщика нет;
#   · он НЕ поднимает посадку `own`. На ней служба сегодня СТАРТОВАТЬ
#     ОТКАЗЫВАЕТСЯ, и это состояние ПРОДУКТА, а не стенда; перечень причин и
#     число записей каталога перемеряется командой, а не помнится:
#       go test ./cmd/kaname/ -run TestEveryLaneIsEitherProfiledOrProvablyUnreachable -v
#   · он НЕ утверждает ничего о поведении API за пределами того, что перечислено
#     в `assert`: это подъём, а не сквозной прогон.
#
# ─────────────────────────────────────────────────────────────────────────────
# ПОЧЕМУ ПОСАДКА БЕРЁТСЯ ИЗ deploy/values.prod.yaml, А НЕ ПИШЕТСЯ ЗДЕСЬ
#
# Профиль есть ОБЪЯВЛЕНИЕ посадки. Стенд, объявляющий её сам, проверял бы
# СОБСТВЕННУЮ накладку, а поставляемый профиль остался бы непроверенным — то
# есть вердикт выносился бы о файле, который клиенту не уезжает. Поэтому боевой
# профиль подключается КАК ЕСТЬ, а накладка стенда несёт ТОЛЬКО координаты этой
# установки (образ, узел базы, имена секретов, домен) и посадки не касается.

set -euo pipefail

RC_UNMET=75

SCRIPT_DIR_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_EARLY="$(cd "$SCRIPT_DIR_EARLY/../.." && pwd)"

# ─── УМОЛЧАНИЯ РАЗЛИЧАЮТ ПОЛОСУ ─────────────────────────────────────────────
#
# На одной машине рядом работают несколько рабочих копий. Общие умолчания
# (`kaname-chart`, `kaname:stand`, `$TMPDIR/kaname-stand-chart`) делали кластер,
# тег образа и рабочий каталог ОДНИМИ на всех: `down` одной полосы уносил PKI и
# накладку идущего прогона соседа, а `kind load` мог увезти чужую сборку — и
# вердикт оказывался о чужом дереве (`multi-agent-flow-shared-tree.md` §13).
#
# Признак полосы ВЫВОДИТСЯ из пути рабочей копии, а не выписывается: выписанное
# имя пришлось бы задавать каждой полосе руками, то есть помнить, — а
# умолчание, которое надо помнить, умолчанием не является. Суффикс короткий и
# устойчивый: имена кластера kind ограничены длиной и алфавитом.
lane_tag() {
	printf '%s' "${1:-$ROOT_EARLY}" | sha256sum | cut -c1-8
}
LANE="$(lane_tag "$ROOT_EARLY")"

CLUSTER="${KANAME_STAND_CLUSTER:-kaname-chart-$LANE}"
NS="${KANAME_STAND_NS:-kaname}"
RELEASE="${KANAME_STAND_RELEASE:-kaname}"
IMAGE="${KANAME_STAND_IMAGE:-kaname:stand-$LANE}"
DOMAIN="${KANAME_STAND_DOMAIN:-kaname.local}"
PG_PASSWORD="${KANAME_STAND_PG_PASSWORD:-standpassword}"
ALERT_RULES="${KANAME_STAND_ALERT_RULES:-on}"
# АДРЕС УЗЛА БАЗЫ, НАЗВАННЫЙ ЯВНО, — КООРДИНАТА, А НЕ ПОСЛАБЛЕНИЕ ПОСАДКИ.
# Умолчание — имя Service, то есть тот путь, которым базу адресует всякая
# установка. Явный адрес нужен там, где резолвер кластера не работает по
# причинам, к дереву отношения не имеющим (см. предпосылку в start_cluster);
# посадки он не касается: шифрование, режим и круг отправителей остаются теми же.
#
# Величина `pod-ip` означает «взять адрес узла базы, который поднял этот же
# скрипт». Она названа словом, а не оставлена на догадку: адрес пода до его
# создания не существует, и вписать его в накладку заранее нельзя.
DB_ADDR="${KANAME_STAND_DB_ADDR:-}"

SCRIPT_DIR="$SCRIPT_DIR_EARLY"
ROOT="$ROOT_EARLY"
WORK="${KANAME_STAND_WORKDIR:-${TMPDIR:-/tmp}/kaname-stand-chart-$LANE}"
PKI="$WORK/pki"

# KUBECONFIG У СКРИПТА СВОЙ, И ЭТО НЕ УДОБСТВО.
#
# `kind create cluster` без своего файла пишет в общий `~/.kube/config` И
# ПЕРЕКЛЮЧАЕТ в нём текущий контекст. Полоса, поднявшая стенд, тем самым
# уводила `kubectl` соседа на свой кластер — молча, потому что вызовы соседа
# продолжают работать, просто не там.
#
# Названный снаружи файл уважается: задание конвейера имеет право положить его
# куда хочет, и тогда решение принимает вызывающий.
export KUBECONFIG="${KUBECONFIG:-$WORK/kubeconfig}"

say()   { printf '%s\n' "$*"; }
fail()  { printf 'НАХОДКА: %s\n' "$*" >&2; }
unmet() { printf 'УСЛОВИЕ НЕ СОЗДАНО: %s\n' "$*" >&2; }

KCTL=(kubectl --context "kind-$CLUSTER")

need_tool() {
	command -v "$1" >/dev/null 2>&1 || {
		unmet "нет инструмента $1 — стенд обещал вердикт и дать его не может"
		exit "$RC_UNMET"
	}
}

# ─── ВНУТРЕННИЙ УЦ УСТАНОВКИ ────────────────────────────────────────────────
#
# Свой, а не чужой: боевая посадка требует взаимного TLS на каждом слушателе, и
# УЦ — часть того, что оператор заводит у себя. Имя SPIFFE серверного и
# клиентского листов совпадает с кругом отправителей ниже намеренно: служба ходит
# к собственному слушателю через свой REST-фронт и обязана быть в этом круге.
make_pki() {
	rm -rf "$PKI"; mkdir -p "$PKI"
	local san_srv="DNS:$RELEASE,DNS:$RELEASE.$NS,DNS:$RELEASE.$NS.svc,DNS:$RELEASE.$NS.svc.cluster.local"
	san_srv="$san_srv,DNS:$RELEASE-internal,DNS:$RELEASE-internal.$NS,DNS:$RELEASE-internal.$NS.svc"
	san_srv="$san_srv,DNS:$RELEASE-internal.$NS.svc.cluster.local,DNS:localhost,IP:127.0.0.1"
	san_srv="$san_srv,URI:spiffe://$DOMAIN/ns/$NS/sa/$RELEASE"

	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PKI/ca.key" -out "$PKI/ca.crt" -days 3 \
		-subj "/CN=kaname stand internal CA" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

	_leaf() { # _leaf <имя> <SAN> <EKU>
		openssl req -newkey rsa:2048 -nodes -keyout "$PKI/$1.key" -out "$PKI/$1.csr" \
			-subj "/CN=$1" 2>/dev/null
		printf 'subjectAltName=%s\nextendedKeyUsage=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\n' \
			"$2" "$3" > "$PKI/$1.ext"
		openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
			-CAcreateserial -out "$PKI/$1.crt" -days 3 -extfile "$PKI/$1.ext" 2>/dev/null
	}
	_leaf srv "$san_srv" "serverAuth,clientAuth"
	_leaf cli "URI:spiffe://$DOMAIN/ns/$NS/sa/$RELEASE,DNS:$RELEASE" "clientAuth,serverAuth"
	_leaf pg  "DNS:$RELEASE-postgres,DNS:$RELEASE-postgres.$NS,DNS:$RELEASE-postgres.$NS.svc,DNS:$RELEASE-postgres.$NS.svc.cluster.local" "serverAuth"
	say "стенд: УЦ и три листа выписаны ($PKI)"
}

start_cluster() {
	if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
		say "стенд: кластер $CLUSTER уже есть"
	else
		kind create cluster --name "$CLUSTER" --wait 180s >/dev/null 2>&1 || {
			unmet "kind не поднял кластер $CLUSTER"
			exit "$RC_UNMET"
		}
		say "стенд: кластер $CLUSTER поднят"
	fi
	# DNS кластера — ПРЕДПОСЫЛКА, а не свойство продукта. Накат ходит к базе по
	# имени Service, и неработающий резолвер даёт отказ, к дереву отношения не
	# имеющий. Частая причина на машине разработчика — исчерпанный
	# fs.inotify.max_user_instances (умолчание 128): kube-proxy падает с
	# «too many open files», Service-адреса не маршрутизируются, CoreDNS не
	# доходит до API. Рекомендация kind — 512.
	if [ -n "$DB_ADDR" ]; then
		say "стенд: узел базы адресуется явно ($DB_ADDR) — предпосылка резолвера не спрашивается"
		return 0
	fi
	local ready
	ready="$("${KCTL[@]}" -n kube-system get pod -l k8s-app=kube-dns \
		-o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | grep -c True || true)"
	if [ "${ready:-0}" -eq 0 ]; then
		unmet "резолвер кластера не готов (готовых CoreDNS: ${ready:-0}) — накат пойдёт к базе по имени Service и не дойдёт.
  Проверьте: kubectl -n kube-system get pod -l k8s-app=kube-proxy
  Частая причина: fs.inotify.max_user_instances=$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo '?') при рекомендованных kind 512"
		exit "$RC_UNMET"
	fi
	say "стенд: резолвер кластера готов (CoreDNS: $ready)"
}

# ─── ВИД PrometheusRule — ПРЕДПОСЫЛКА УСТАНОВКИ, А НЕ УКРАШЕНИЕ ─────────────
#
# Чарт везёт правила тревоги объектом `PrometheusRule`, и ручка `alertRules`
# включена УМОЛЧАНИЕМ. Вид заводит не Kubernetes, а Prometheus Operator: там,
# где его нет, `helm install` отвергает установку ЦЕЛИКОМ, а не одну тревогу.
# Это предпосылка ЭТОГО стенда, а не находка о дереве, поэтому 75.
check_alert_rules_kind() {
	if [ "$ALERT_RULES" = "off" ]; then
		say "стенд: правила тревоги выключены накладкой (KANAME_STAND_ALERT_RULES=off)"
		return 0
	fi
	if "${KCTL[@]}" get crd prometheusrules.monitoring.coreos.com >/dev/null 2>&1; then
		say "стенд: вид PrometheusRule в кластере есть — чарт ставится умолчанием"
		return 0
	fi
	unmet "вида PrometheusRule в кластере нет, а ручка alertRules включена умолчанием чарта.
  Исходов два, и оба задокументированы (docs/content/install/deploy.mdx):
    1. поставить Prometheus Operator (или хотя бы определение вида prometheusrules.monitoring.coreos.com);
    2. отказаться от правил тревоги — прогнать этот стенд с KANAME_STAND_ALERT_RULES=off."
	exit "$RC_UNMET"
}

start_pg() {
	"${KCTL[@]}" create namespace "$NS" >/dev/null 2>&1 || true
	"${KCTL[@]}" -n "$NS" delete secret "$RELEASE-pg-tls" >/dev/null 2>&1 || true
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-pg-tls" \
		--from-file=tls.crt="$PKI/pg.crt" --from-file=tls.key="$PKI/pg.key" >/dev/null

	# ssl=on, потому что боевая посадка требует sslmode=require: страж отказывает
	# на `disable`, и база без TLS дала бы отказ старта по причине, к дереву
	# отношения не имеющей. Приватная половина копируется в emptyDir и
	# перекладывается под пользователя базы: секрет монтируется от root, а
	# Postgres отвергает ключ с групповым и мировым доступом.
	"${KCTL[@]}" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Service
metadata: { name: $RELEASE-postgres, namespace: $NS }
spec:
  selector: { app: $RELEASE-postgres }
  ports: [{ name: pg, port: 5432, targetPort: 5432 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: $RELEASE-postgres, namespace: $NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: $RELEASE-postgres } }
  template:
    metadata: { labels: { app: $RELEASE-postgres } }
    spec:
      volumes:
        - { name: tls-src, secret: { secretName: $RELEASE-pg-tls } }
        - { name: tls,  emptyDir: {} }
        - { name: data, emptyDir: {} }
      initContainers:
        - name: prepare-tls
          image: mirror.gcr.io/library/postgres:16-alpine
          command: ["/bin/sh","-c","cp /src/tls.crt /src/tls.key /pgtls/ && chown 70:70 /pgtls/tls.* && chmod 600 /pgtls/tls.key && chmod 644 /pgtls/tls.crt"]
          volumeMounts:
            - { name: tls-src, mountPath: /src, readOnly: true }
            - { name: tls, mountPath: /pgtls }
      containers:
        - name: postgres
          image: mirror.gcr.io/library/postgres:16-alpine
          args: ["-c","ssl=on","-c","ssl_cert_file=/pgtls/tls.crt","-c","ssl_key_file=/pgtls/tls.key"]
          env:
            - { name: POSTGRES_USER,     value: iam }
            - { name: POSTGRES_PASSWORD, value: "$PG_PASSWORD" }
            - { name: POSTGRES_DB,       value: kaname }
            - { name: PGDATA,            value: /var/lib/postgresql/data/pgdata }
          ports: [{ containerPort: 5432 }]
          volumeMounts:
            - { name: tls,  mountPath: /pgtls }
            - { name: data, mountPath: /var/lib/postgresql/data }
          readinessProbe:
            exec: { command: ["pg_isready","-U","iam","-d","kaname"] }
            initialDelaySeconds: 5
            periodSeconds: 5
EOF
	"${KCTL[@]}" -n "$NS" rollout status "deploy/$RELEASE-postgres" --timeout=180s >/dev/null || {
		unmet "узел базы не поднялся за 180 с"
		exit "$RC_UNMET"
	}
	if [ "$DB_ADDR" = "pod-ip" ]; then
		DB_ADDR="$("${KCTL[@]}" -n "$NS" get pod -l "app=$RELEASE-postgres" \
			-o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)"
		[ -n "$DB_ADDR" ] || { unmet "адрес пода базы не прочитался"; exit "$RC_UNMET"; }
		say "стенд: узел базы адресуется своим адресом $DB_ADDR"
	fi
	say "стенд: база поднята, канал шифруется (ssl=on)"
}

make_secrets() {
	local s
	for s in "$RELEASE-db" "$RELEASE-server-tls" "$RELEASE-client-tls" "$RELEASE-provider-ca" "$RELEASE-authn"; do
		"${KCTL[@]}" -n "$NS" delete secret "$s" >/dev/null 2>&1 || true
	done
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-db" \
		--from-literal=password="$PG_PASSWORD" >/dev/null
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-server-tls" \
		--from-file=tls.crt="$PKI/srv.crt" --from-file=tls.key="$PKI/srv.key" \
		--from-file=ca.crt="$PKI/ca.crt" >/dev/null
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-client-tls" \
		--from-file=tls.crt="$PKI/cli.crt" --from-file=tls.key="$PKI/cli.key" \
		--from-file=ca.crt="$PKI/ca.crt" >/dev/null
	# ЯКОРЬ ПОСТАВЩИКА — ТРЕТЬЯ КООРДИНАТА, а не ключ в чужом секрете: «чьим
	# сертификатам сервера я верю у соседа» и «кто вправе прийти ко мне
	# клиентом» суть разные вопросы. Здесь совпадает содержимое — поставщика
	# выпускал бы тот же УЦ, — но координата своя, и выбор поэтому выразим.
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-provider-ca" \
		--from-file=ca.crt="$PKI/ca.crt" >/dev/null
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-authn" \
		--from-literal=hook-shared-secret="$(openssl rand -hex 16)" \
		--from-literal=jwks-encryption-key-hex="$(openssl rand -hex 32)" >/dev/null
	say "стенд: пять секретов заведены (база · серверный лист · клиентский лист · якорь поставщика · величины authn)"
}

build_image() {
	if [ "${KANAME_STAND_SKIP_BUILD:-0}" = "1" ]; then
		say "стенд: сборка образа пропущена по KANAME_STAND_SKIP_BUILD=1"
	else
		docker build -f "$ROOT/Dockerfile" -t "$IMAGE" "$ROOT" >/dev/null 2>&1 || {
			unmet "образ $IMAGE не собрался"
			exit "$RC_UNMET"
		}
		say "стенд: образ $IMAGE собран"
	fi
	kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null 2>&1 || {
		unmet "образ $IMAGE не уехал в узлы кластера"
		exit "$RC_UNMET"
	}
}

# Накладка несёт ТОЛЬКО координаты этой установки. Посадку объявляет боевой
# профиль чарта, и он подключается как есть — см. шапку.
write_overlay() {
	cat > "$WORK/values.stand.yaml" <<EOF
image: "$IMAGE"
imagePullPolicy: IfNotPresent
db:
  host: "${DB_ADDR:-$RELEASE-postgres.$NS.svc.cluster.local}"
  user: iam
  name: kaname
  passwordSecretName: $RELEASE-db
  passwordSecretKey: password
authn:
  domain: $DOMAIN
  trustDomain: $DOMAIN
  trustedForwarderSANs:
    - "spiffe://$DOMAIN/ns/$NS/sa/$RELEASE"
  tokenSigning:
    issuer: "https://$DOMAIN"
  presentedCredential:
    audience: "https://$DOMAIN"
apiServer:
  registryToken:
    issuer: "https://$DOMAIN/iam/token"
    service: "registry.$DOMAIN"
tls:
  secretName: $RELEASE-server-tls
  clientSecretName: $RELEASE-client-tls
  providerSecretName: $RELEASE-provider-ca
secrets:
  KANAME_HOOK_TOKEN:
    secretName: $RELEASE-authn
    secretKey: hook-shared-secret
  KANAME_JWKS_ENC_KEY:
    secretName: $RELEASE-authn
    secretKey: jwks-encryption-key-hex
env:
  KANAME_HYDRA_ADMIN_URL: "https://127.0.0.1:14445"
  KANAME_HYDRA_JWKS_URL: "https://127.0.0.1:14444/.well-known/jwks.json"
  KANAME_HYDRA_TOKEN_URL: "https://127.0.0.1:14444/oauth2/token"
EOF
}

install_chart() {
	local extra=()
	[ "$ALERT_RULES" = "off" ] && extra+=(--set alertRules.enabled=false)
	helm upgrade --install "$RELEASE" "$ROOT/deploy" \
		-f "$ROOT/deploy/values.yaml" \
		-f "$ROOT/deploy/values.prod.yaml" \
		-f "$WORK/values.stand.yaml" \
		--kube-context "kind-$CLUSTER" -n "$NS" "${extra[@]}" || {
		fail "чарт не поставился — вердикт о дереве"
		exit 1
	}
	say "стенд: чарт поставлен"
	"${KCTL[@]}" -n "$NS" rollout status "deploy/$RELEASE" --timeout=300s || {
		fail "выкат не дошёл до готовности за 300 с — вердикт о дереве"
		"${KCTL[@]}" -n "$NS" logs "deploy/$RELEASE" -c migrate --tail=20 2>&1 | sed 's/^/  накат: /' || true
		"${KCTL[@]}" -n "$NS" logs "deploy/$RELEASE" -c "$RELEASE" --tail=40 2>&1 | sed 's/^/  служба: /' || true
		exit 1
	}
	say "стенд: выкат дошёл до готовности"
}

# ─── ШЕСТЬ ОСЕЙ ПОСАДКИ, СРАВНИВАЕМЫЕ С ОБЪЯВЛЕННЫМ ────────────────────────
#
# Вынесено отдельной функцией НЕ ради красоты: так сравнение проверяемо без
# кластера. `--self-test` кормит её строками самоотчёта — законной, изменённой
# на ОДИН факт и отсутствующей вовсе — и требует, чтобы она молчала на первой и
# падала на второй. Без этой пробы «сверка прошла» было бы неотличимо от
# «сверка ничего не спросила».
posture_matches() {
	local posture="$1" rc=0 key want
	for kv in auth_mode=production-strict db_sslmode=require public_mtls=true \
		internal_mtls=true authz_check=true trusted_forwarders=true; do
		key="${kv%%=*}"; want="${kv#*=}"
		case "$posture" in
			*"\"$key\":\"$want\""*|*"\"$key\":$want"*) say "  посадка: $key=$want — сходится" ;;
			*) fail "посадка: $key объявлен не как $want"; rc=1 ;;
		esac
	done
	return "$rc"
}

self_test() {
	local legal off rc=0
	legal='{"msg":"boot security posture","auth_mode":"production-strict","db_sslmode":"require","public_mtls":true,"internal_mtls":"true","authz_check":true,"trusted_forwarders":true}'
	# ОДИН факт против законного близнеца, не два: иначе неизвестно, который
	# из них дал красное, и вердикт пробы недействителен.
	off="${legal/\"db_sslmode\":\"require\"/\"db_sslmode\":\"disable\"}"

	say "самопроба: законный самоотчёт — сверка обязана молчать"
	posture_matches "$legal" >/dev/null 2>&1 || { fail "самопроба: сверка упала на законном самоотчёте"; rc=1; }

	say "самопроба: один факт изменён (db_sslmode) — сверка обязана упасть"
	posture_matches "$off" >/dev/null 2>&1 && { fail "самопроба: сверка смолчала на изменённом факте — она ничего не спрашивает"; rc=1; }

	say "самопроба: самоотчёта нет вовсе — сверка обязана упасть"
	posture_matches "" >/dev/null 2>&1 && { fail "самопроба: сверка смолчала на пустом самоотчёте"; rc=1; }

	# ── УМОЛЧАНИЯ РАЗЛИЧАЮТ ПОЛОСУ ─────────────────────────────────────────
	#
	# Инъекция меняет РОВНО ОДИН факт — путь рабочей копии — и требует, чтобы
	# признак полосы разошёлся. Законный близнец рядом: тот же путь даёт тот же
	# признак, иначе имена кластера гуляли бы от вызова к вызову и `down` сносил
	# бы не то, что поднял `up`.
	local a b
	a="$(lane_tag /полоса/один)"
	b="$(lane_tag /полоса/два)"
	say "самопроба: две рабочие копии — признак полосы обязан разойтись"
	[ "$a" != "$b" ] || { fail "самопроба: разные копии дали один признак полосы ($a) — кластер, тег образа и рабочий каталог остались бы общими"; rc=1; }
	say "самопроба: та же копия — признак полосы обязан совпасть"
	[ "$a" = "$(lane_tag /полоса/один)" ] || { fail "самопроба: один путь дал два признака — down сносил бы не то, что поднял up"; rc=1; }
	# КАЖДОЕ умолчание проверяется ОТДЕЛЬНО: склейка трёх в одну строку
	# зеленела бы, когда признак вошёл в одну из них, — а делят полосы все три.
	say "самопроба: признак полосы входит в КАЖДОЕ из трёх умолчаний"
	for pair in "кластер=$CLUSTER" "образ=$IMAGE" "каталог=$WORK"; do
		case "${pair#*=}" in
			*"$LANE"*) ;;
			*) fail "самопроба: признак полосы не вошёл в умолчание ${pair%%=*} (${pair#*=}) — полосы делили бы его"; rc=1 ;;
		esac
	done
	say "самопроба: KUBECONFIG у скрипта свой"
	[ -n "${KUBECONFIG:-}" ] || { fail "самопроба: KUBECONFIG не задан — kind писал бы в общий файл и уводил kubectl соседа"; rc=1; }

	say "самопроба: утверждений 7 · осей сверки 6"
	[ "$rc" -eq 0 ] && say "===== самопроба пройдена =====" || fail "самопроба не пройдена"
	return "$rc"
}

# ─── СВЕРКА ПОСАДКИ ПО ДВУМ НЕЗАВИСИМЫМ ИСТОЧНИКАМ ──────────────────────────
#
# «Под Ready» посадкой не является: процесс мог подняться в другой. Поэтому
# сверяется (а) то, что процесс ОБЪЯВИЛ о себе при старте, и (б) шифрование со
# стороны БАЗЫ — подтверждение, которое настройкой не подделать.
assert_posture() {
	local rc=0 pod posture
	# ПОД БЕРЁТСЯ ГОТОВЫЙ И САМЫЙ СВЕЖИЙ, а не первый попавшийся, и это не
	# аккуратность. Во время переката в перечне стоят ДВА пода — новый и
	# доживающий старый, — и `items[0]` берёт между ними по жребию. Наблюдалось
	# при самой проверке этого скрипта: сверка после переката прочитала журнал
	# СТАРОГО пода и объявила находку о посадке, которой в кластере уже не было.
	# Отбор по готовности плюс свежесть отсечения не оставляет.
	pod="$("${KCTL[@]}" -n "$NS" get pod -l "app=$RELEASE" \
		--sort-by=.metadata.creationTimestamp \
		-o jsonpath='{range .items[?(@.status.containerStatuses[0].ready==true)]}{.metadata.name}{"\n"}{end}' \
		2>/dev/null | tail -1 || true)"
	[ -n "$pod" ] || { unmet "готового пода службы нет — сверять нечего"; exit "$RC_UNMET"; }
	say "сверяется под: $pod"

	posture="$("${KCTL[@]}" -n "$NS" logs "$pod" -c "$RELEASE" 2>/dev/null \
		| grep -m1 'boot security posture' || true)"
	if [ -z "$posture" ]; then
		unmet "процесс не объявил посадку при старте — вердикта о ней нет"
		exit "$RC_UNMET"
	fi
	say "самоотчёт процесса: $posture"
	posture_matches "$posture" || rc=1

	# Независимое подтверждение со стороны базы. Соединения самой проверки идут
	# по локальному сокету и шифрованными не являются — поэтому считаются
	# соединения ПОЛЬЗОВАТЕЛЯ службы, а не все подряд.
	local pgpod encrypted plain
	pgpod="$("${KCTL[@]}" -n "$NS" get pod -l "app=$RELEASE-postgres" \
		-o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
	if [ -z "$pgpod" ]; then
		unmet "пода базы нет — независимого подтверждения шифрования не будет"
		exit "$RC_UNMET"
	fi
	encrypted="$("${KCTL[@]}" -n "$NS" exec "$pgpod" -c postgres -- psql -U iam -d kaname -tAc \
		"SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.datname=current_database() AND a.usename='iam' AND s.ssl;" 2>/dev/null | tr -d ' \r')"
	plain="$("${KCTL[@]}" -n "$NS" exec "$pgpod" -c postgres -- psql -U iam -d kaname -tAc \
		"SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.datname=current_database() AND a.usename='iam' AND NOT s.ssl AND a.backend_type='client backend' AND a.client_addr IS NOT NULL;" 2>/dev/null | tr -d ' \r')"
	say "  со стороны базы: соединений службы шифрованных ${encrypted:-?} · по сети открытым текстом ${plain:-?}"
	if [ "${encrypted:-0}" -lt 1 ]; then
		fail "база не видит НИ ОДНОГО шифрованного соединения службы — объявленная посадка не подтверждена"
		rc=1
	fi
	if [ "${plain:-0}" -gt 0 ]; then
		fail "база видит ${plain} сетевых соединений службы открытым текстом"
		rc=1
	fi

	# Накат: применено всё объявленное. Перепись печатается всегда — «ноль
	# находок» обязано быть отличимо от «ноль прочитанного».
	local applied
	applied="$("${KCTL[@]}" -n "$NS" exec "$pgpod" -c postgres -- psql -U iam -d kaname -tAc \
		"SELECT count(*) FROM information_schema.tables WHERE table_schema='kaname';" 2>/dev/null | tr -d ' \r')"
	say "  схема kaname: таблиц ${applied:-?}"
	[ "${applied:-0}" -ge 1 ] || { fail "схема kaname пуста — накат не применён"; rc=1; }

	# Объявление сбора величин — на поде, и схему читают ОТТУДА, а не
	# подставляют: её задаёт та же ручка, что поднимает транспорт слушателя.
	local scheme
	scheme="$("${KCTL[@]}" -n "$NS" get pod "$pod" \
		-o jsonpath='{.metadata.annotations.prometheus\.io/scheme}' 2>/dev/null || true)"
	say "  объявленная схема сбора величин: ${scheme:-<не объявлена>}"
	[ "$scheme" = "https" ] || { fail "транспорт диагностики включён, а объявлена схема '${scheme:-<нет>}'"; rc=1; }

	# Поверхности: сколько служба объявила поднятыми.
	local surfaces
	surfaces="$("${KCTL[@]}" -n "$NS" logs "$pod" -c "$RELEASE" 2>/dev/null \
		| grep -c 'поверхность поднята' || true)"
	say "  поверхностей поднято: ${surfaces:-0} (плюс два gRPC-слушателя)"

	if [ "$rc" -ne 0 ]; then
		fail "посадка разошлась с объявленной"
		return 1
	fi
	say "===== посадка сошлась по обоим источникам ====="
	return 0
}

down() {
	if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
		kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
		say "стенд: кластер $CLUSTER снесён"
	else
		say "стенд: кластера $CLUSTER нет — сносить нечего"
	fi
	rm -rf "$WORK"
}

case "${1:-}" in
	up)
		say "===== стенд чартом: подъём ====="
		need_tool openssl; need_tool docker; need_tool kind
		need_tool kubectl; need_tool helm
		mkdir -p "$WORK"
		start_cluster
		check_alert_rules_kind
		make_pki
		start_pg
		make_secrets
		build_image
		write_overlay
		install_chart
		say "===== стенд поднят чартом, без платформы и без поставщика ====="
		;;
	assert)
		need_tool kubectl
		assert_posture
		;;
	--self-test)
		self_test
		;;
	down)
		need_tool kind
		down
		;;
	*)
		printf 'использование: %s {up|assert|down|--self-test}\n' "$0" >&2
		exit 2
		;;
esac
