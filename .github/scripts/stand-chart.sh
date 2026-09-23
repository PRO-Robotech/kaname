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
#   · УМОЛЧАНИЕМ он НЕ поднимает посадку `own` — его предмет ПОСТАВЛЯЕМЫЙ
#     профиль, а тот объявляет `external`. Посадку `own` он поднимает по ручке
#     `KANAME_STAND_IDENTITY_PROVIDER=own` — см. раздел «ПОСАДКА `own`» ниже;
#   · он НЕ утверждает ничего о поведении API за пределами того, что перечислено
#     в `assert`: это подъём, а не сквозной прогон. Сквозной прогон полосы входа
#     на посадке `own` — задание `chart-own` процесса `e2e-newman.yml`, и его
#     условие создаёт подкоманда `seed-login-lane`.
#
# ─────────────────────────────────────────────────────────────────────────────
# ПОСАДКА `own`: ЧЕМ СТЕНД ОТЛИЧАЕТСЯ И ПОЧЕМУ ИМЕННО ЭТИМ
#
# Посадка — НАКЛАДКА ОПЕРАТОРА поверх боевого профиля, а не второй профиль:
# `authn.identityProvider: own` и токен-эндпоинт платформы (`authn.clientToken`,
# `enabled: true` и четыре величины) — ровно то, что называет INSTALL.md §1;
# без эндпоинта `own` не собирает сам чарт (kaname#337). Прочее — адрес полосы,
# её взаимный TLS, предел памяти, третий ключ Secret — боевой профиль уже несёт,
# и стенд его не повторяет: повтор проверял бы накладку, а не поставку.
#
# Сверх накладки стенд создаёт ДВА условия, без которых набор полосы входа
# исполняется и не утверждает ничего:
#
#   · КЛИЕНТСКИЙ ЛИСТ С ИМЕНЕМ КРАЯ. Слушатель полосы допускает РОВНО край — по
#     короткому имени службы из SAN проверенного листа под доменом доверия
#     установки (Р7, Р16); лист самой службы получает 403 до чтения тела. Края
#     на стенде нет, и его место занимает прогонщик набора: ретранслирует форму
#     человека и ставит адрес источника. Лист лежит Secret'ом стенда
#     (`<релиз>-edge-client-tls`) и предъявляется ТОЛЬКО полосе;
#   · ЧЕЛОВЕК СО СПОСОБОМ ВХОДА ПАРОЛЕМ. Заводит его посев
#     (`tests/authz-fixtures/seed_login_lane.py`) глаголом продукта на той же
#     двери, учётные данные живут Secret'ом стенда (`<релиз>-login-lane-human`)
#     и в дерево не попадают.
#
# Посадку, с которой процесс поднялся, `assert` сверяет по самоотчёту: под этой
# ручкой ось `identity_provider=own` добавляется к шести осям боевой посадки.
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

# ПОСАДКА ЛИЧНОСТИ СТЕНДА. Пусто — как объявляет поставляемый профиль; `own` —
# накладка оператора (раздел «ПОСАДКА `own`» в шапке). Иных величин нет: третья
# означала бы посадку, которую стенд не умеет ни собрать, ни сверить.
IDENTITY="${KANAME_STAND_IDENTITY_PROVIDER:-}"
case "$IDENTITY" in
	""|own) ;;
	*)
		printf 'KANAME_STAND_IDENTITY_PROVIDER=%s: допустимы пусто (профиль) и own\n' "$IDENTITY" >&2
		exit 2 ;;
esac

# Имя края в SAN листа, которым прогонщик стоит на месте края у полосы входа.
# Полоса разбирает из него короткое имя службы (`kacho-` снимается) и сравнивает
# с константой края — `api-gateway`.
EDGE_SA="kacho-api-gateway"

# РЕВИЗИЯ, КОТОРУЮ ИСПОЛНЯЕТ СТЕНД. Образ собирается с ней (`OCI_IMAGE_REVISION`),
# и `assert` сверяет её с файлом ревизии в РАБОТАЮЩЕМ контейнере: без этого
# вердикт о стенде нечем связать с деревом, которое судят.
REVISION="${KANAME_STAND_REVISION:-$(git -C "$ROOT_EARLY" rev-parse HEAD 2>/dev/null || true)}"

SCRIPT_DIR="$SCRIPT_DIR_EARLY"
ROOT="$ROOT_EARLY"
WORK="${KANAME_STAND_WORKDIR:-${TMPDIR:-/tmp}/kaname-stand-chart-$LANE}"
PKI="$WORK/pki"

# Кластер, который поднял ЭТОТ стенд, помечается файлом в рабочем каталоге, и
# `down` сносит кластер только с этой меткой. Чужой кластер (стенд подселён в
# уже поднятый) остаётся стоять: снимаются лишь релиз и пространство имён,
# которые стенд завёл сам.
CREATED_MARK="$WORK/cluster-created-by-stand"

# Переадресация порта полосы входа живёт между шагами: посев доказывает по ней
# способность, прогон набора ходит по ней же. Снимает её `down`.
LANE_FORWARD_PID="$WORK/login-lane-forward.pid"
LANE_FORWARD_LOG="$WORK/login-lane-forward.log"
EDGE_DIR="$WORK/edge"

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
	# Лист края — только под `own`: на поставляемой посадке полосы входа нет, и
	# лист чужого звена там не предъявлялся бы никому. Только клиентский: сервером
	# край для службы не бывает.
	if [ "$IDENTITY" = "own" ]; then
		_leaf edge "URI:spiffe://$DOMAIN/ns/$NS/sa/$EDGE_SA" "clientAuth"
		say "стенд: четвёртый лист — клиентский, с именем края ($EDGE_SA) для полосы входа"
	fi
}

# RESOLVER_TIMEOUT — предел ОЖИДАНИЯ готовности резолвера, в секундах.
#
# Назван ручкой, потому что зависит от машины, а не от дерева: на ранере
# кластер поднимается за секунды, на загруженной машине разработчика — дольше.
RESOLVER_TIMEOUT="${KANAME_STAND_RESOLVER_TIMEOUT:-120}"

# RESOLVER_POLL — пауза между опросами. Настоящая пауза, а не busy-wait: без неё
# «ожидание» вырождается в подряд идущие вызовы и само создаёт нагрузку.
RESOLVER_POLL="${KANAME_STAND_RESOLVER_POLL:-3}"

# wait_ready — ЖДЁТ, пока названная функция не вернёт положительное число.
#
# Печатает `<величина>:<сколько ждали>` и выходит нулём; по исчерпании предела
# печатает `<сколько ждали>` и выходит единицей. Обе стороны несут время
# ожидания: вызывающий обязан назвать его в любом исходе.
#
# Функция принимается ИМЕНЕМ, а не телом: тем же вызовом самопроба подаёт свою,
# не поднимая кластера, — и проверяет ОБЕ стороны ожидания.
wait_ready() {
	local probe="$1" limit="$2" waited=0 value
	while :; do
		value="$("$probe" 2>/dev/null || true)"
		if [ "${value:-0}" -gt 0 ] 2>/dev/null; then
			printf '%s:%s' "$value" "$waited"
			return 0
		fi
		if [ "$waited" -ge "$limit" ]; then
			printf '%s' "$waited"
			return 1
		fi
		sleep "$RESOLVER_POLL"
		waited=$((waited + RESOLVER_POLL))
	done
}

# resolver_ready_count — сколько подов резолвера кластера готовы.
resolver_ready_count() {
	"${KCTL[@]}" -n kube-system get pod -l k8s-app=kube-dns \
		-o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null \
		| grep -c True || true
}

start_cluster() {
	if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
		say "стенд: кластер $CLUSTER уже есть"
		# Контекст уже поднятого кластера пишется в СВОЙ файл стенда, и только
		# если его там нет: чужой файл, названный снаружи, не трогается (шапка,
		# «KUBECONFIG у скрипта свой»).
		if ! "${KCTL[@]}" get namespace default >/dev/null 2>&1; then
			kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || {
				unmet "контекст кластера $CLUSTER не выписался в $KUBECONFIG"
				exit "$RC_UNMET"
			}
			say "стенд: контекст kind-$CLUSTER выписан в $KUBECONFIG"
		fi
	else
		kind create cluster --name "$CLUSTER" --wait 180s >/dev/null 2>&1 || {
			unmet "kind не поднял кластер $CLUSTER"
			exit "$RC_UNMET"
		}
		: > "$CREATED_MARK"
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
	# ЖДЁМ УСЛОВИЕ, А НЕ СПРАШИВАЕМ ОДНОКРАТНО.
	#
	# Здесь стоял ОДИН вызов сразу после `kind create`: ноль готовых — выход 75.
	# Готовность резолвера наступает ПОЗЖЕ готовности узла, поэтому однократный
	# вопрос объявлял «условие не создано» на кластере, который через несколько
	# секунд был бы готов, — то есть срывал прогон по расписанию собственного
	# опроса (`e2e-flow.md` §4: ждём условие, а не время).
	#
	# Сколько ЖДАЛИ — печатается в ОБОИХ исходах. Без этого «готов» и «готов
	# впритык к пределу» выглядят одинаково, и предел двигают вслепую.
	local ready waited
	ready="$(wait_ready resolver_ready_count "$RESOLVER_TIMEOUT")" || {
		waited="${ready:-?}"
		unmet "резолвер кластера не готов: ждали ${waited} с при пределе ${RESOLVER_TIMEOUT} с — накат пойдёт к базе по имени Service и не дойдёт.
  Проверьте: kubectl -n kube-system get pod -l k8s-app=kube-proxy
  Частая причина: fs.inotify.max_user_instances=$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo '?') при рекомендованных kind 512"
		exit "$RC_UNMET"
	}
	waited="${ready#*:}"; ready="${ready%%:*}"
	say "стенд: резолвер кластера готов (CoreDNS: $ready; ждали ${waited} с из предела ${RESOLVER_TIMEOUT} с)"
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
	# ПЕРЕЧЕНЬ КЛЮЧЕЙ ЭТОГО ОБЪЕКТА ДИКТУЕТ ПРОФИЛЬ, А НЕ СТЕНД: каждая запись
	# карты `secrets` боевого профиля рендерится `secretKeyRef` без `optional`,
	# и ключ, которого в объекте нет, останавливает контейнер до старта
	# (CreateContainerConfigError), — выкат не доходит до готовности, вердикта
	# о посадке нет. Так и случилось: Ф12 добавила третью запись, стенд заводил
	# два ключа, и подъём на голове линии вставал на первом поде. Согласие
	# перечней держит `deploy/stand_secrets_cover_the_profile_test.go`.
	#
	# Кольцо обёртки секретов второго фактора читается только под `own`, но
	# объект обязан нести ключ на любой посадке: `secretKeyRef` судится
	# кластером при создании контейнера, а не процессом при чтении.
	"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-authn" \
		--from-literal=hook-shared-secret="$(openssl rand -hex 16)" \
		--from-literal=jwks-encryption-key-hex="$(openssl rand -hex 32)" \
		--from-literal=second-factor-encryption-key-hex="$(openssl rand -hex 32)" >/dev/null
	say "стенд: пять секретов заведены (база · серверный лист · клиентский лист · якорь поставщика · величины authn: три ключа)"
	# Лист края — Secret'ом стенда, а не только файлом рабочего каталога: посев
	# и прогон берут его ОТСЮДА (`seed-login-lane`), то есть предъявляется ровно
	# тот лист, что выписан под этот УЦ, в каком бы каталоге ни шёл следующий шаг.
	if [ "$IDENTITY" = "own" ]; then
		"${KCTL[@]}" -n "$NS" delete secret "$RELEASE-edge-client-tls" >/dev/null 2>&1 || true
		"${KCTL[@]}" -n "$NS" create secret generic "$RELEASE-edge-client-tls" \
			--from-file=tls.crt="$PKI/edge.crt" --from-file=tls.key="$PKI/edge.key" \
			--from-file=ca.crt="$PKI/ca.crt" >/dev/null
		say "стенд: шестой секрет — клиентский лист с именем края"
	fi
}

build_image() {
	if [ "${KANAME_STAND_SKIP_BUILD:-0}" = "1" ]; then
		say "стенд: сборка образа пропущена по KANAME_STAND_SKIP_BUILD=1"
	else
		# Незакоммиченная правка в образ уезжает, а в ревизию — нет: ревизия
		# называет коммит, контекст сборки — рабочее дерево. Сказано вслух, чтобы
		# «сходится» у `assert` не читалось шире сделанного.
		if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
			say "стенд: ВНИМАНИЕ — в дереве незакоммиченные правки; ревизия образа $REVISION их не называет"
		fi
		docker build -f "$ROOT/Dockerfile" --build-arg "OCI_IMAGE_REVISION=$REVISION" \
			-t "$IMAGE" "$ROOT" >/dev/null 2>&1 || {
			unmet "образ $IMAGE не собрался"
			exit "$RC_UNMET"
		}
		say "стенд: образ $IMAGE собран с ревизией ${REVISION:-<не названа>}"
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
	rm -f "$WORK/values.stand-own.yaml"
	[ "$IDENTITY" = "own" ] || return 0
	# НАКЛАДКА ОПЕРАТОРА `own` — отдельным файлом и ПОСЛЕ накладки координат:
	# она меняет посадку, а не координаты, и читатель рендера видит её целиком.
	#
	# Перечень адресатов несёт адресат докерной полосы — страж старта требует
	# его ВНУТРИ перечня. Срок токена ни одним шагом этого стенда не расходуется
	# (набор полосы входа токенов не чеканит): величина — законная ниже потолка
	# платформы 30m, та, с которой посадка перемерена живым стартом (INSTALL.md
	# §1). Потолок тела — тот же, что у автономного стенда, и довод тот же
	# (`stand-own.sh`, «СРОК ТОКЕНА И ПОТОЛОК ТЕЛА»).
	cat > "$WORK/values.stand-own.yaml" <<EOF
authn:
  identityProvider: own
  clientToken:
    enabled: true
    allowedAudiences: "https://$DOMAIN,registry.$DOMAIN"
    defaultAudience: "https://$DOMAIN"
    tokenTtl: 15m
    bodyCeiling: 16384
EOF
}

install_chart() {
	local extra=()
	[ "$ALERT_RULES" = "off" ] && extra+=(--set alertRules.enabled=false)
	[ "$IDENTITY" = "own" ] && extra+=(-f "$WORK/values.stand-own.yaml")
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
#
# Оси — ПАРАМЕТР со своим умолчанием: под `own` к шести осям боевой посадки
# добавляется седьмая, `identity_provider=own`, — стенд судит посадку, которую
# сам объявил. Под поставляемым профилем посадку личности объявляет профиль, и
# стенд её не дописывает.
BASE_POSTURE_AXES="auth_mode=production-strict db_sslmode=require public_mtls=true internal_mtls=true authz_check=true trusted_forwarders=true"
OWN_POSTURE_AXES="$BASE_POSTURE_AXES identity_provider=own"
POSTURE_AXES="$BASE_POSTURE_AXES"
[ "$IDENTITY" != "own" ] || POSTURE_AXES="$OWN_POSTURE_AXES"

posture_matches() {
	local posture="$1" axes="${2:-$POSTURE_AXES}" rc=0 key want
	for kv in $axes; do
		key="${kv%%=*}"; want="${kv#*=}"
		case "$posture" in
			*"\"$key\":\"$want\""*|*"\"$key\":$want"*) say "  посадка: $key=$want — сходится" ;;
			*) fail "посадка: $key объявлен не как $want"; rc=1 ;;
		esac
	done
	return "$rc"
}

self_test() {
	local legal off rc=0 out
	legal='{"msg":"boot security posture","auth_mode":"production-strict","db_sslmode":"require","public_mtls":true,"internal_mtls":"true","authz_check":true,"trusted_forwarders":true}'
	# ОДИН факт против законного близнеца, не два: иначе неизвестно, который
	# из них дал красное, и вердикт пробы недействителен.
	off="${legal/\"db_sslmode\":\"require\"/\"db_sslmode\":\"disable\"}"

	# Оси передаются ЯВНО: самопроба судит сверку, а не то, с какой ручкой
	# посадки её позвали.
	say "самопроба: законный самоотчёт — сверка обязана молчать"
	posture_matches "$legal" "$BASE_POSTURE_AXES" >/dev/null 2>&1 || { fail "самопроба: сверка упала на законном самоотчёте"; rc=1; }

	say "самопроба: один факт изменён (db_sslmode) — сверка обязана упасть"
	posture_matches "$off" "$BASE_POSTURE_AXES" >/dev/null 2>&1 && { fail "самопроба: сверка смолчала на изменённом факте — она ничего не спрашивает"; rc=1; }

	say "самопроба: самоотчёта нет вовсе — сверка обязана упасть"
	posture_matches "" "$BASE_POSTURE_AXES" >/dev/null 2>&1 && { fail "самопроба: сверка смолчала на пустом самоотчёте"; rc=1; }

	# ── ПОСАДКА `own`: СЕДЬМАЯ ОСЬ ──────────────────────────────────────────
	#
	# Законный близнец — самоотчёт `own` под осями `own`; инъекция меняет ОДИН
	# факт — посадку личности. Третья проба держит обратное: седьмая ось не
	# навязывается стенду поставляемого профиля.
	local own_legal own_off
	own_legal="${legal%\}},\"identity_provider\":\"own\"}"
	own_off="${own_legal/\"identity_provider\":\"own\"/\"identity_provider\":\"external\"}"
	say "самопроба: самоотчёт own под осями own — сверка обязана молчать"
	posture_matches "$own_legal" "$OWN_POSTURE_AXES" >/dev/null 2>&1 || { fail "самопроба: сверка упала на законном самоотчёте own"; rc=1; }
	say "самопроба: процесс поднялся в external при заказанной own — сверка обязана упасть"
	posture_matches "$own_off" "$OWN_POSTURE_AXES" >/dev/null 2>&1 && { fail "самопроба: сверка смолчала, когда процесс поднялся не в той посадке личности"; rc=1; }
	say "самопроба: оси профиля посадку личности не требуют — законный самоотчёт без неё молчит"
	posture_matches "$legal" "$BASE_POSTURE_AXES" >/dev/null 2>&1 || { fail "самопроба: оси профиля требуют посадку личности, которую стенд не объявлял"; rc=1; }

	# ── ЛИСТ С ИМЕНЕМ КРАЯ ─────────────────────────────────────────────────
	#
	# Настоящий `make_pki` в своём каталоге: под `own` лист края есть, несёт имя
	# края и только клиентское назначение; без ручки его нет вовсе (близнец).
	local pki_tmp san eku
	pki_tmp="$(mktemp -d)"
	( PKI="$pki_tmp/own"; IDENTITY=own; make_pki >/dev/null 2>&1 ) || true
	san="$(openssl x509 -in "$pki_tmp/own/edge.crt" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
	eku="$(openssl x509 -in "$pki_tmp/own/edge.crt" -noout -ext extendedKeyUsage 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
	say "самопроба: под own лист края несёт имя края и только клиентское назначение"
	[ "$san" = "URI:spiffe://$DOMAIN/ns/$NS/sa/$EDGE_SA" ] && [ "$eku" = "TLSWebClientAuthentication" ] || {
		fail "самопроба: лист края выписан не так (SAN «$san», назначение «$eku»)"; rc=1; }
	say "самопроба: лист края не выписан на имя службы и выписан УЦ стенда"
	openssl verify -CAfile "$pki_tmp/own/ca.crt" "$pki_tmp/own/edge.crt" >/dev/null 2>&1 \
		&& ! openssl x509 -in "$pki_tmp/own/cli.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "sa/$EDGE_SA" || {
		fail "самопроба: лист края не проверяется УЦ стенда либо имя края стоит и в листе службы"; rc=1; }
	( PKI="$pki_tmp/profile"; IDENTITY=""; make_pki >/dev/null 2>&1 ) || true
	say "самопроба: без ручки own листа края нет"
	[ -f "$pki_tmp/profile/cli.crt" ] && [ ! -e "$pki_tmp/profile/edge.crt" ] || {
		fail "самопроба: лист края выписан стенду поставляемого профиля"; rc=1; }
	rm -rf "$pki_tmp"

	# ── ПЕРЕАДРЕСАЦИЯ И ПРОВЕНАНС ───────────────────────────────────────────
	#
	# Порт берётся из строки IPv4 и только из неё: переадресация, вставшая лишь
	# на `[::1]`, уже давала прогон на чужом слушателе того же номера.
	local log_tmp
	log_tmp="$(mktemp)"
	printf 'Forwarding from [::1]:41000 -> 9100\n' > "$log_tmp"
	say "самопроба: переадресация только на [::1] — порта нет"
	[ -z "$(forward_port_of "$log_tmp" 9100)" ] || { fail "самопроба: порт взят из строки [::1]"; rc=1; }
	printf 'Forwarding from 127.0.0.1:41001 -> 9100\nForwarding from [::1]:41000 -> 9100\n' > "$log_tmp"
	say "самопроба: строка IPv4 есть — порт её"
	[ "$(forward_port_of "$log_tmp" 9100)" = "41001" ] || { fail "самопроба: порт IPv4 не распознан"; rc=1; }
	rm -f "$log_tmp"

	say "самопроба: провенанс — четыре исхода различены"
	[ "$(revision_outcome abc123def abc123def)" = "сходится" ] \
		&& [ "$(revision_outcome abc123def 999999999)" = "расходится" ] \
		&& [ "$(revision_outcome "" abc123def)" = "у образа нет метки" ] \
		&& [ "$(revision_outcome abc123def "")" = "ожидаемая ревизия не названа" ] || {
		fail "самопроба: исходы сверки ревизии не различены"; rc=1; }

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

	# ── ОЖИДАНИЕ УСЛОВИЯ ────────────────────────────────────────────────────
	#
	# Обе стороны: условие наступает — ждали и дождались; не наступает — предел
	# исчерпан, и время ожидания НАЗВАНО. Подаётся своя функция, кластер не
	# нужен.
	local saved_poll="$RESOLVER_POLL"
	RESOLVER_POLL=1
	self_never_ready() { printf '0'; }
	self_always_ready() { printf '2'; }
	say "самопроба: условие выполнено сразу — ожидание обязано вернуть величину и ноль секунд"
	[ "$(wait_ready self_always_ready 2)" = "2:0" ] || { fail "самопроба: готовое условие не распознано"; rc=1; }
	say "самопроба: условие не наступает — предел обязан исчерпаться и назвать ожидание"
	if out="$(wait_ready self_never_ready 1)"; then
		fail "самопроба: ожидание объявило готовность там, где условие не наступало ни разу"
		rc=1
	elif [ "$out" != "1" ]; then
		fail "самопроба: исчерпанный предел не назвал времени ожидания (получено «$out»)"
		rc=1
	fi
	RESOLVER_POLL="$saved_poll"

	say "самопроба: утверждений 18 · осей сверки 6 (под own — 7)"
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

	# ПРОВЕНАНС — ДО ПОСАДКИ: посадка, сверенная у процесса чужой ревизии, —
	# вердикт о чужом дереве. Файл ревизии читается в РАБОТАЮЩЕМ контейнере, а не
	# у образа на машине: исполняет кластер то, что загружено в узел.
	local running prov
	if ! running="$("${KCTL[@]}" -n "$NS" exec "$pod" -c "$RELEASE" -- cat /etc/kacho/image-revision 2>/dev/null)"; then
		unmet "провенанс: стенд не опрошен — файл ревизии в контейнере $pod не прочитан"
		exit "$RC_UNMET"
	fi
	running="$(printf '%s' "$running" | tr -d ' \r\n')"
	prov="$(revision_outcome "$running" "$REVISION")"
	say "  провенанс: контейнер ${running:-<пусто>} · ожидалась ${REVISION:-<не названа>} — $prov"
	if [ "$prov" != "сходится" ]; then
		unmet "провенанс: $prov — стенд не исполняет ревизию, о которой выносится вердикт"
		exit "$RC_UNMET"
	fi

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

# revision_outcome <в контейнере> <ожидаемая> — исход сверки провенанса словом.
#
# Сверка ПО КОММИТУ: ожидаемая может быть названа сокращённо, и тогда ревизия
# контейнера обязана с неё начинаться. Исходов четыре, и «не названа» не
# сливается со «сходится»: сверить нечем — не значит сошлось.
revision_outcome() {
	local running="$1" want="$2"
	if [ -z "$running" ]; then printf 'у образа нет метки'; return 0; fi
	if [ -z "$want" ]; then printf 'ожидаемая ревизия не названа'; return 0; fi
	case "$running" in
		"$want"*) printf 'сходится' ;;
		*) printf 'расходится' ;;
	esac
}

# forward_port_of <журнал переадресации> <порт полосы> — местный порт IPv4.
forward_port_of() {
	sed -n "s/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> $2\$/\1/p" "$1" 2>/dev/null | head -1
}

stop_lane_forward() {
	if [ -f "$LANE_FORWARD_PID" ]; then
		kill "$(cat "$LANE_FORWARD_PID")" 2>/dev/null || true
		rm -f "$LANE_FORWARD_PID"
	fi
}

# start_lane_forward — переадресация порта полосы на 127.0.0.1, местный порт
# выбирает ядро. Номер удалённого порта читается у Service ПО ИМЕНИ, а не
# выписывается: адрес полосы объявляет профиль (`apiServer.loginLaneEndpoint`).
start_lane_forward() {
	local remote pid i port=""
	remote="$("${KCTL[@]}" -n "$NS" get svc "$RELEASE-internal" \
		-o jsonpath='{.spec.ports[?(@.name=="http-login-lane")].port}' 2>/dev/null || true)"
	if [ -z "$remote" ]; then
		fail "у Service $RELEASE-internal нет порта http-login-lane — профиль не объявил полосу входа"
		exit 1
	fi
	stop_lane_forward
	nohup "${KCTL[@]}" -n "$NS" port-forward --address 127.0.0.1 "svc/$RELEASE-internal" ":$remote" \
		> "$LANE_FORWARD_LOG" 2>&1 < /dev/null &
	pid=$!
	echo "$pid" > "$LANE_FORWARD_PID"
	for i in $(seq 1 30); do
		port="$(forward_port_of "$LANE_FORWARD_LOG" "$remote")"
		[ -n "$port" ] && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 1
	done
	if [ -z "$port" ]; then
		unmet "переадресация полосы не встала: $(tail -2 "$LANE_FORWARD_LOG" 2>/dev/null | tr '\n' ' ')"
		stop_lane_forward
		exit "$RC_UNMET"
	fi
	LANE_URL="https://127.0.0.1:$port"
	say "стенд: полоса входа переадресована — $LANE_URL (порт службы $remote)"
}

# secret_value <имя объекта> <ключ> — значение ключа Secret стенда.
secret_value() {
	local key="${2//./\\.}"
	"${KCTL[@]}" -n "$NS" get secret "$1" -o "jsonpath={.data.$key}" 2>/dev/null | base64 -d
}

# ─── ПОСЕВ ЧЕЛОВЕКА ПОЛОСЫ ВХОДА ────────────────────────────────────────────
#
# Отдельная подкоманда, а не часть `up`: подъём создаёт стенд, посев — данные
# стенда, и отказ посева не должен выглядеть отказом подъёма. Исходы — те же три:
# 0 — человек входит паролем и окружение записано; 1 — находка (от посева либо
# профиль без полосы); 75 — условие не создано.
#
# Учётные данные человека живут Secret'ом стенда и заводятся ОДИН раз: повторный
# посев на том же стенде берёт их оттуда, и посев входом доказывает, что человек
# есть, а не заводит второго. Пароль в аргументы процессов не попадает: kubectl
# читает его из файла под 0600, посев — из переменной окружения.
seed_login_lane() {
	if [ "$IDENTITY" != "own" ]; then
		printf 'seed-login-lane — посев стенда посадки own: задайте KANAME_STAND_IDENTITY_PROVIDER=own\n' >&2
		exit 2
	fi
	need_tool python3; need_tool base64
	mkdir -p "$EDGE_DIR"; chmod 700 "$EDGE_DIR"
	local k f
	for k in tls.crt:edge.crt tls.key:edge.key ca.crt:ca.crt; do
		f="$EDGE_DIR/${k#*:}"
		secret_value "$RELEASE-edge-client-tls" "${k%%:*}" > "$f" || true
		[ -s "$f" ] || { unmet "лист края не вынесен из Secret $RELEASE-edge-client-tls (ключ ${k%%:*}) — стенд поднят не под own?"; exit "$RC_UNMET"; }
	done
	chmod 600 "$EDGE_DIR/edge.key"

	local human="$RELEASE-login-lane-human"
	if ! "${KCTL[@]}" -n "$NS" get secret "$human" >/dev/null 2>&1; then
		local hdir="$WORK/human"
		mkdir -p "$hdir"; chmod 700 "$hdir"
		( umask 077
		  printf 'login-lane-%s@%s' "$(openssl rand -hex 6)" "$DOMAIN" > "$hdir/email"
		  openssl rand -hex 16 | tr -d '\n' > "$hdir/password" )
		"${KCTL[@]}" -n "$NS" create secret generic "$human" \
			--from-file=email="$hdir/email" --from-file=password="$hdir/password" >/dev/null
		rm -rf "$hdir"
		say "стенд: учётные данные человека заведены Secret'ом $human"
	else
		say "стенд: учётные данные человека взяты из Secret $human"
	fi
	local email password
	email="$(secret_value "$human" email || true)"
	password="$(secret_value "$human" password || true)"

	start_lane_forward
	local rc=0
	KANAME_STAND_LANE_EMAIL="$email" KANAME_STAND_LANE_PASSWORD="$password" \
		python3 "$ROOT/tests/authz-fixtures/seed_login_lane.py" \
		--base-url "$LANE_URL" --pki "$EDGE_DIR" || rc=$?
	return "$rc"
}

down() {
	stop_lane_forward
	if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
		if [ -f "$CREATED_MARK" ]; then
			kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
			say "стенд: кластер $CLUSTER снесён"
		else
			# Кластер поднимал не этот стенд: снимается то, что стенд завёл сам.
			helm uninstall "$RELEASE" --kube-context "kind-$CLUSTER" -n "$NS" >/dev/null 2>&1 || true
			"${KCTL[@]}" delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
			say "стенд: кластер $CLUSTER чужой — сняты релиз $RELEASE и пространство имён $NS, кластер стоит"
		fi
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
	seed-login-lane)
		need_tool kubectl
		seed_login_lane
		;;
	down)
		need_tool kind
		down
		;;
	*)
		printf 'использование: %s {up|assert|seed-login-lane|down|--self-test}\n' "$0" >&2
		exit 2
		;;
esac
