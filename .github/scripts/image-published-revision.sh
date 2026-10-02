#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# image-published-revision.sh <ссылка-на-образ> <ревизия> <платформы-через-запятую>
# image-published-revision.sh --self-test
#
# ОПУБЛИКОВАННЫЙ ОБРАЗ НЕСЁТ ТУ РЕВИЗИЮ, ИЗ КОТОРОЙ ЕГО СОБРАЛИ
# (задача PRO-Robotech/kaname#429, п.1 предиката).
#
# ─────────────────────────────────────────────────────────────────────────────
# ПРЕДМЕТ
#
# Шаг сборки отвечает «отправлено» — и только. Есть ли тег в реестре и из какого
# дерева собрано то, что под ним лежит, он не спрашивает, а потребитель — зонт
# линии платформы, пинящий службу тегом, — получает именно то, что лежит в
# реестре. До этой сверки первый пункт предиката #429 перемеряли руками, раз на
# голову и когда о нём вспоминали, то есть держался он вниманием.
#
# Здесь спрашивается РЕЕСТР, по каждой заявленной платформе:
#
#   1. индекс тега (`docker buildx imagetools inspect --raw`) — есть ли тег и
#      какие платформы под ним названы, каждая своим отпечатком;
#   2. образ ПО ОТПЕЧАТКУ платформы (`docker create --pull always … @sha256:…`)
#      и файл ревизии в нём.
#
# ПОЧЕМУ ПО ОТПЕЧАТКУ, А НЕ ПО ТЕГУ С `--platform`. Замер 2026-10-01, демон с
# хранилищем containerd: у контейнера, созданного по тегу с `--platform
# linux/arm64`, образом назван ИНДЕКС, и `docker image inspect` его отвечает
# `linux/amd64`. Сверка, судящая архитектуру так, на одном виде хранилища лгала
# бы, на другом молчала. Отпечаток из индекса называет манифест платформы
# однозначно, и читается ровно он.
#
# ПОЧЕМУ `--pull always`. Без него демон взял бы образ, уже лежащий у него под
# тем же именем, и сверка ответила бы о нём, а не о реестре.
#
# ПОЧЕМУ ФАЙЛ, А НЕ КЛЕЙМО. Файл и клеймо берут величину из одного довода сборки
# (шапка `Dockerfile`), но провенанс стенда платформы читает у работающего
# контейнера именно файл. Сверяется то, что потом назовёт стенд.
#
# ─────────────────────────────────────────────────────────────────────────────
# КОДЫ ВОЗВРАТА
#
#   0  у КАЖДОЙ заявленной платформы файл ревизии прочитан и равен ожидаемой;
#   1  НАХОДКА: платформы нет в индексе тега, под тегом не индекс платформ, файл
#      пуст либо несёт другую ревизию — каждая названа поимённо;
#   2  НЕ УСТАНОВЛЕНО: доводы негодны (пустая ссылка, ссылка без тега либо с
#      отпечатком, ревизия не полная, платформ ноль), нет инструмента, реестр
#      отказал на теге, образ платформы не получен либо файла в нём нет.
#
# Отказ реестра на теге — код 2, а не 1, хотя настоящий реестр на отсутствующий
# тег отвечает `not found`: тот же текст приходит и от зеркала, и от реестра без
# прав на чтение, и различать их разбором чужого сообщения значило бы выдать
# догадку за находку. Текст отказа печатается дословно — читающий видит его сам.
#
# Код 1 сильнее кода 2: «у платформы другая ревизия» — положительное утверждение
# о реестре, «не прочитано» — граница инструмента. С кодом 0 код 2 не сливается
# никогда: «ноль расхождений» обязано быть отличимо от «ноль прочитанного».
#
# ─────────────────────────────────────────────────────────────────────────────
# ЧЕГО ЭТА СВЕРКА НЕ ДОКАЗЫВАЕТ — сказано прямо
#
# Что бинарь службы собран из того же дерева, она не судит: файл ревизии пишет
# та же сборка из того же довода, что и штамп бинаря, и их согласие держит
# проба дерева `TestBuildStampReachesTheBinaryItLabels`. Поднимается ли стенд
# линии на этом теге, — п.3 предиката, это вопрос к стенду, а не к реестру.
#
# Провязку в задание образа (сверка зовётся после сборки, условием публикации и
# теми же величинами, что сборка) судит гейт дерева
# `internal/check/image_published_revision.go`.
set -uo pipefail

# REVISION_PATH — путь величины внутри образа. Его же пишет конечная ступень
# `Dockerfile` и читает провенанс стенда платформы.
readonly REVISION_PATH="/etc/kacho/image-revision"

# docker_cli — чем спрашивается реестр. Умолчание `docker`; самопроверка
# подставляет записывающего двойника. ЧИТАЕТСЯ В МОМЕНТ ВЫЗОВА, а не при
# загрузке: подделка, назначенная до подстановки, подделкой не является (довод —
# шапка trunk-verdict-holder.sh у `reporter`).
docker_cli() { printf '%s' "${IMAGE_REVISION_DOCKER:-docker}"; }

# annotate <заголовок> <текст> — строка, которую провайдер показывает аннотацией.
annotate() { printf '::error title=%s::%s\n' "$1" "$2"; }

# verify <ссылка> <ревизия> <платформы> — сверка с каталогом для чтения,
# убираемым при любом исходе.
verify() {
    local work rc=0
    work="$(mktemp -d)" || {
        annotate "НЕ ИСПОЛНЯЛАСЬ" "каталог для чтения не заведён — реестр не спрошен"
        return 2
    }
    verify_in "$work" "$@" || rc=$?
    rm -rf "$work"
    return "$rc"
}

verify_in() {
    local work="$1" ref="${2:-}" want="${3:-}" platforms="${4:-}"
    local d; d="$(docker_cli)"

    # ── доводы ──────────────────────────────────────────────────────────────
    if [ -z "$ref" ]; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "ссылка на образ пуста — о реестре не спрошено ничего"
        return 2
    fi
    case "$ref" in *@*)
        annotate "НЕ ИСПОЛНЯЛАСЬ" "ссылка $ref уже несёт отпечаток — сверяется ТЕГ, отпечатки платформ берутся из его индекса"
        return 2 ;;
    esac
    # Тег — после ПОСЛЕДНЕГО двоеточия последней части пути: двоеточие раньше —
    # это порт реестра, а не тег.
    if [[ "${ref##*/}" != *:* ]]; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "ссылка $ref без тега — сверять нечего: публикуется тег"
        return 2
    fi
    local repo="${ref%:*}"
    if ! [[ "$want" =~ ^[0-9a-f]{40}$ ]]; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "ожидаемая ревизия «$want» — не полная ревизия в 40 знаков: короткую с файлом не сравнить, пустая совпала бы с чем угодно"
        return 2
    fi
    local plats=() wanted=() p
    IFS=',' read -ra plats <<<"$platforms"
    for p in "${plats[@]}"; do
        p="${p//[[:space:]]/}"
        [ -n "$p" ] && wanted+=("$p")
    done
    if [ "${#wanted[@]}" -eq 0 ]; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "платформ не заявлено ни одной — «ноль расхождений» значил бы «ноль прочитанного»"
        return 2
    fi
    if ! command -v "$d" >/dev/null 2>&1; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "нет инструмента $d — реестр не спрошен"
        return 2
    fi
    # jq спрашивается ИСПОЛНЕНИЕМ, а не поиском в PATH: найденная обёртка, которая
    # не запускается, иначе выдала бы свой отказ за «ответ реестра не разобран».
    if ! jq -n true >/dev/null 2>&1; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "jq не исполняется — индекс тега прочитать нечем, реестр не спрошен"
        return 2
    fi

    # ── индекс тега ─────────────────────────────────────────────────────────
    if ! "$d" buildx imagetools inspect --raw "$ref" >"$work/index" 2>"$work/err"; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "реестр отказал на теге $ref: $(tail -n1 "$work/err") — тега нет либо реестр недоступен, и что из двух, сверка не различает"
        return 2
    fi
    if ! jq -e . "$work/index" >/dev/null 2>&1; then
        annotate "НЕ ИСПОЛНЯЛАСЬ" "ответ реестра о теге $ref не разбирается как JSON — что под тегом, не установлено"
        return 2
    fi
    if ! jq -e '.manifests | type == "array"' "$work/index" >/dev/null 2>&1; then
        annotate "ОБРАЗ НЕ ТОТ" "под тегом $ref одиночный манифест, а не индекс платформ: заявлено ${#wanted[@]} (${wanted[*]}), и какая из них лежит в реестре, не названо"
        echo "перепись: тег $ref · платформ заявлено ${#wanted[@]} · в индексе 0 · прочитано 0 · сошлись 0 · находок 1 · не прочитано 0"
        return 1
    fi
    local listed indexed
    listed="$(jq -r '[.manifests[] | select(.platform != null) | .platform.os + "/" + .platform.architecture + (if .platform.variant then "/" + .platform.variant else "" end)] | join(" ")' "$work/index")"
    indexed="$(jq -r '[.manifests[] | select(.platform != null)] | length' "$work/index")"

    # ── файл ревизии у каждой платформы ─────────────────────────────────────
    local findings=0 unread=0 equal=0 readn=0 i=0
    for p in "${wanted[@]}"; do
        i=$((i + 1))
        local os="${p%%/*}" rest="${p#*/}" arch variant="" digest cid got
        arch="${rest%%/*}"
        [ "$rest" != "$arch" ] && variant="${rest#*/}"
        digest="$(jq -r --arg os "$os" --arg arch "$arch" --arg variant "$variant" '
            [.manifests[] | select(.platform != null
                and .platform.os == $os and .platform.architecture == $arch
                and ($variant == "" or .platform.variant == $variant)) | .digest] | .[0] // ""' "$work/index")"
        if [ -z "$digest" ]; then
            annotate "ОБРАЗ НЕ ТОТ" "платформы $p в индексе тега $ref НЕТ (названы: ${listed:-никакие}) — потребитель этой архитектуры образа не получит"
            findings=$((findings + 1))
            continue
        fi
        if ! cid="$("$d" create --pull always --quiet --platform "$p" "$repo@$digest" 2>"$work/err")" || [ -z "$cid" ]; then
            annotate "НЕ ИСПОЛНЯЛАСЬ" "платформа $p: образ $repo@$digest из реестра не получен: $(tail -n1 "$work/err")"
            unread=$((unread + 1))
            continue
        fi
        if ! "$d" cp "$cid:$REVISION_PATH" "$work/revision.$i" >/dev/null 2>"$work/err"; then
            "$d" rm -f "$cid" >/dev/null 2>&1 || true
            annotate "НЕ ИСПОЛНЯЛАСЬ" "платформа $p: файл $REVISION_PATH из образа $repo@$digest не прочитан: $(tail -n1 "$work/err")"
            unread=$((unread + 1))
            continue
        fi
        "$d" rm -f "$cid" >/dev/null 2>&1 || true
        readn=$((readn + 1))
        got="$(head -n1 "$work/revision.$i" | tr -d '[:space:]')"
        if [ -z "$got" ]; then
            annotate "ОБРАЗ НЕ ТОТ" "платформа $p ($digest): файл $REVISION_PATH пуст — ревизия при сборке не проставлена"
            findings=$((findings + 1))
        elif [ "$got" != "$want" ]; then
            annotate "ОБРАЗ НЕ ТОТ" "платформа $p ($digest) несёт ревизию $got, а голова — $want: под тегом лежит не то дерево"
            findings=$((findings + 1))
        else
            equal=$((equal + 1))
            echo "  платформа $p ($digest): ревизия $got — равна голове"
        fi
    done

    echo "перепись: тег $ref · платформ заявлено ${#wanted[@]} · в индексе $indexed · прочитано $readn · сошлись $equal · находок $findings · не прочитано $unread"
    if [ "$findings" -gt 0 ]; then return 1; fi
    if [ "$unread" -gt 0 ]; then return 2; fi
    echo "опубликовано: $ref — у каждой из ${#wanted[@]} платформ файл ревизии равен $want"
    return 0
}

# --- самопроверка: доказательство инъекцией в обе стороны ---------------------
#
# Живёт ФЛАГОМ этого же файла, а не соседним: отдельный файл в перечень шагов
# конвейера не попал бы сам, то есть не исполнялся бы никогда.
#
# Реестр подменён ДВОЙНИКОМ CLI, который отвечает так, как ответил настоящий на
# замере 2026-10-01 (тег `357-40a88fba` и заведомо отсутствующий тег): индекс —
# OCI-индексом с платформой и отпечатком у каждого манифеста, отсутствующий тег
# и отсутствующая платформа — отказом с `not found`. Двойник ведёт журнал
# обращений: провязка доказывается тем, КАК его позвали, а не тем, что он
# ответил «хорошо».
if [ "${1:-}" = "--self-test" ]; then
    TMP="$(mktemp -d)" || { echo "ПРОВАЛ: каталог самопроверки не заведён" >&2; exit 2; }
    trap 'rm -rf "$TMP"' EXIT
    if ! jq -n true >/dev/null 2>&1; then
        echo "image-published-revision --self-test: НЕ ВЫПОЛНИЛАСЬ — jq не исполняется, без него сверка не читает индекс" >&2
        exit 2
    fi
    cat > "$TMP/docker" <<'STUB'
#!/usr/bin/env bash
# Двойник CLI: индекс тега — файл STUB_INDEX; образы по отпечатку — STUB_IMAGES
# («<отпечаток>=<ревизия>»; `-` — файл пуст, `!` — файла нет). Отпечаток вне
# перечня — отказ реестра, как у настоящего.
printf '%s\n' "$*" >> "$STUB_LOG"
if [ "${1:-}" = buildx ] && [ "${2:-}" = imagetools ] && [ "${3:-}" = inspect ]; then
    [ -z "${STUB_INDEX_FAIL:-}" ] || { echo "ERROR: ${*: -1}: not found" >&2; exit 1; }
    cat "$STUB_INDEX"; exit 0
fi
lookup() {
    local rec
    for rec in $STUB_IMAGES; do
        [ "${rec%%=*}" = "$1" ] && { printf '%s' "${rec#*=}"; return 0; }
    done
    return 1
}
case "${1:-}" in
    create)
        ref="${*: -1}"
        case "$ref" in *@*) ;; *) echo "Error response from daemon: двойник отдаёт образ только по отпечатку: $ref" >&2; exit 1 ;; esac
        lookup "${ref##*@}" >/dev/null || { echo "Error response from daemon: $ref: not found" >&2; exit 1; }
        echo "cid-${ref##*@}"; exit 0 ;;
    cp)
        src="$2" dst="$3" digest="${2%%:/*}"; digest="${digest#cid-}"
        rev="$(lookup "$digest")" || { echo "Error: No such container: ${src%%:/*}" >&2; exit 1; }
        case "$rev" in
            '!') echo "Error response from daemon: Could not find the file /etc/kacho/image-revision in container ${src%%:/*}" >&2; exit 1 ;;
            '-') : > "$dst" ;;
            *) printf '%s\n' "$rev" > "$dst" ;;
        esac
        exit 0 ;;
    rm) exit 0 ;;
esac
echo "двойник не знает обращения: $*" >&2
exit 64
STUB
    chmod +x "$TMP/docker"
    export IMAGE_REVISION_DOCKER="$TMP/docker" STUB_LOG="$TMP/log" STUB_INDEX="$TMP/index" STUB_IMAGES=""

    # ПРЕДПОСЫЛКА САМОПРОВЕРКИ: реестр спрашивается у двойника, а не у
    # настоящего демона. Проверяется, а не подразумевается.
    # Сравнение — ДО первого обращения: при неподставленном двойнике проба
    # подстановки ушла бы к настоящему демону.
    if [ "$(docker_cli)" != "$TMP/docker" ]; then
        echo "ПРОВАЛ: реестр НЕ подменён двойником (сейчас: $(docker_cli)) — самопроверка отменена" >&2
        exit 2
    fi
    : > "$STUB_LOG"
    "$(docker_cli)" rm проба-подстановки >/dev/null 2>&1 || true
    if ! grep -q 'проба-подстановки' "$STUB_LOG"; then
        echo "ПРОВАЛ: реестр НЕ подменён двойником — двойник не ведёт журнала, самопроверка отменена" >&2
        exit 2
    fi
    echo "предпосылка: реестр подменён двойником ($(docker_cli)), журнал обращений ведётся"

    readonly HEAD=40a88fba4fb6cc5b7345711dade31e6abbb0b044
    readonly OTHER=73dc6598c1a38321cdee20731cb5547cd4a158c3
    readonly REF=docker.io/prorobotech/kaname:357-40a88fba
    readonly BOTH=linux/amd64,linux/arm64
    readonly A=sha256:6ffc4552f6dfbcf0575ee2b8faca18974c64ad7478c929435d920ca23180a946
    readonly B=sha256:81f9dc32fd077dd87e97edde59babfedb4433bf3852bf276afbc07aada5ceb4f
    readonly S=sha256:0000000000000000000000000000000000000000000000000000000000005390

    # index <os/arch[/variant]=отпечаток>… — OCI-индекс той формы, что отдал реестр.
    index() {
        local rec plat dig os arch variant sep='' out='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":['
        for rec in "$@"; do
            plat="${rec%%=*}" dig="${rec#*=}"
            os="${plat%%/*}" arch="${plat#*/}" variant=''
            case "$arch" in */*) variant="${arch#*/}" arch="${arch%%/*}" ;; esac
            out+="$sep{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"$dig\",\"size\":1247,\"platform\":{\"architecture\":\"$arch\",\"os\":\"$os\"${variant:+,\"variant\":\"$variant\"}}}"
            sep=','
        done
        printf '%s]}\n' "$out" > "$STUB_INDEX"
    }

    probes=0 failed=0
    # run <код> <имя> <обязан назвать> <ссылка> <ревизия> <платформы>
    run() {
        local want="$1" name="$2" says="$3" got=0 out
        shift 3
        probes=$((probes + 1))
        : > "$STUB_LOG"
        out="$(verify "$@" 2>&1)" || got=$?
        if [ "$got" -ne "$want" ]; then
            echo "  ПРОВАЛ $name — код ждали $want, получили $got" >&2
            printf '%s\n' "$out" | sed 's/^/        /' >&2
            failed=$((failed + 1)); return
        fi
        if [ -n "$says" ] && ! grep -qF -- "$says" <<<"$out"; then
            echo "  ПРОВАЛ $name — код $got верный, но не названо «$says»:" >&2
            printf '%s\n' "$out" | sed 's/^/        /' >&2
            failed=$((failed + 1)); return
        fi
        echo "  ok   $name (код $got)"
    }

    echo "=== сверка опубликованного образа: доказательство инъекцией ==="

    # (−) ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: без него всё нижеследующее зеленело бы на сверке,
    # которая отказывает ВСЕГДА.
    index "linux/amd64=$A" "linux/arm64=$B"; STUB_IMAGES="$A=$HEAD $B=$HEAD"; unset STUB_INDEX_FAIL
    run 0 "(−) обе платформы несут голову" "сошлись 2" "$REF" "$HEAD" "$BOTH"

    # (−) КАК СПРОШЕН РЕЕСТР — журнал двойника той же пробы: по отпечатку, с
    # `--pull always`, по разу на платформу и каждой своей платформой.
    probes=$((probes + 1))
    creates="$(grep -c '^create ' "$STUB_LOG" || true)"
    if [ "$creates" -eq 2 ] \
       && [ "$(grep '^create ' "$STUB_LOG" | grep -c -- '--pull always')" -eq 2 ] \
       && grep -qF -- "--platform linux/amd64 docker.io/prorobotech/kaname@$A" "$STUB_LOG" \
       && grep -qF -- "--platform linux/arm64 docker.io/prorobotech/kaname@$B" "$STUB_LOG"; then
        echo "  ok   (−) реестр спрошен по отпечатку платформы и с --pull always, по разу на платформу"
    else
        echo "  ПРОВАЛ (−) реестр спрошен не так (созданий $creates):" >&2
        sed 's/^/        /' "$STUB_LOG" >&2
        failed=$((failed + 1))
    fi

    # (−) законная форма: порт реестра в ссылке — двоеточие, не являющееся тегом.
    STUB_IMAGES="$A=$HEAD $B=$HEAD"
    run 0 "(−) порт реестра в ссылке тегом не считается" "сошлись 2" "registry.local:5000/prorobotech/kaname:357-40a88fba" "$HEAD" "$BOTH"

    # (+) один факт против близнеца: одна платформа несёт чужую ревизию.
    STUB_IMAGES="$A=$HEAD $B=$OTHER"
    run 1 "(+) у arm64 чужая ревизия" "платформа linux/arm64 ($B) несёт ревизию $OTHER" "$REF" "$HEAD" "$BOTH"
    STUB_IMAGES="$A=$OTHER $B=$OTHER"
    run 1 "(+) у обеих чужая ревизия" "находок 2" "$REF" "$HEAD" "$BOTH"
    STUB_IMAGES="$A=$HEAD $B=-"
    run 1 "(+) у arm64 файл пуст" "файл /etc/kacho/image-revision пуст" "$REF" "$HEAD" "$BOTH"

    # (+) платформы нет в индексе — и её законный близнец: ЛИШНЯЯ платформа.
    index "linux/amd64=$A"; STUB_IMAGES="$A=$HEAD"
    run 1 "(+) arm64 в индексе нет" "платформы linux/arm64 в индексе тега $REF НЕТ" "$REF" "$HEAD" "$BOTH"
    index "linux/amd64=$A" "linux/arm64=$B" "linux/s390x=$S"; STUB_IMAGES="$A=$HEAD $B=$HEAD $S=$OTHER"
    run 0 "(−) лишняя платформа в индексе не находка" "сошлись 2" "$REF" "$HEAD" "$BOTH"

    # (−)/(+) вариант архитектуры: незаявленный совпадает с любым, заявленный —
    # только с собой.
    index "linux/amd64=$A" "linux/arm64/v8=$B"; STUB_IMAGES="$A=$HEAD $B=$HEAD"
    run 0 "(−) вариант в индексе при незаявленном варианте" "сошлись 2" "$REF" "$HEAD" "$BOTH"
    run 1 "(+) заявлен другой вариант" "платформы linux/arm64/v7 в индексе тега $REF НЕТ" "$REF" "$HEAD" "linux/amd64,linux/arm64/v7"

    # (+) под тегом одиночный манифест.
    printf '%s\n' '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}' > "$STUB_INDEX"
    run 1 "(+) под тегом не индекс платформ" "одиночный манифест" "$REF" "$HEAD" "$BOTH"

    # (+) ТРЕТЬЯ КАТЕГОРИЯ: не прочитано — не зелёное и не находка.
    index "linux/amd64=$A" "linux/arm64=$B"; STUB_IMAGES="$A=$HEAD $B=$HEAD"
    STUB_INDEX_FAIL=1 run 2 "(+) реестр отказал на теге — не установлено" "реестр отказал на теге $REF" "$REF" "$HEAD" "$BOTH"
    printf '%s\n' 'не JSON' > "$STUB_INDEX"
    run 2 "(+) ответ о теге не разобран" "не разбирается как JSON" "$REF" "$HEAD" "$BOTH"
    index "linux/amd64=$A" "linux/arm64=$B"; STUB_IMAGES="$A=$HEAD"
    run 2 "(+) образ arm64 не получен" "платформа linux/arm64: образ docker.io/prorobotech/kaname@$B из реестра не получен" "$REF" "$HEAD" "$BOTH"
    STUB_IMAGES="$A=$HEAD $B=!"
    run 2 "(+) файла ревизии в образе arm64 нет" "файл /etc/kacho/image-revision из образа" "$REF" "$HEAD" "$BOTH"

    # (+) ПОРЯДОК ИСХОДОВ: находка у одной платформы сильнее непрочитанной другой.
    STUB_IMAGES="$B=$OTHER"
    run 1 "(+) чужая ревизия сильнее непрочитанного" "находок 1 · не прочитано 1" "$REF" "$HEAD" "$BOTH"

    # (+) негодные доводы — сверка не исполнялась, и молчанием это не становится.
    STUB_IMAGES="$A=$HEAD $B=$HEAD"
    run 2 "(+) ссылка пуста" "ссылка на образ пуста" "" "$HEAD" "$BOTH"
    run 2 "(+) ссылка без тега" "без тега" "docker.io/prorobotech/kaname" "$HEAD" "$BOTH"
    run 2 "(+) ссылка с отпечатком" "уже несёт отпечаток" "docker.io/prorobotech/kaname@$A" "$HEAD" "$BOTH"
    run 2 "(+) ревизия короткая" "не полная ревизия" "$REF" "${HEAD:0:8}" "$BOTH"
    run 2 "(+) платформ ноль" "платформ не заявлено ни одной" "$REF" "$HEAD" " , "

    echo
    echo "image-published-revision --self-test: проб исполнено $probes, провалов $failed"
    [ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
    [ "$failed" -gt 0 ] && exit 1
    exit 0
fi

if [ "$#" -ne 3 ]; then
    annotate "НЕ ИСПОЛНЯЛАСЬ" "доводов $# из 3: <ссылка-на-образ> <ревизия> <платформы-через-запятую> — о реестре не сказано ничего"
    exit 2
fi
verify "$@"
