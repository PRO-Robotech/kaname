#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# chart-publish.sh <тег> — публикация чарта службы (`deploy/`) в OCI-реестр
# организации из конвейера (задача kaname#964). Зовёт его процесс
# `.github/workflows/chart.yml` на метке версии.
#
# ЧТО ПУБЛИКУЕТСЯ И КУДА
#
#   oci://ghcr.io/pro-robotech/charts/kaname:<МАЖОР>.<МИНОР>.<ПАТЧ>
#
# Тот же реестр, куда публикует свои чарты registry-operator
# (`charts/publish.sh` его дерева): у платформы одно место, откуда ставятся
# чарты. Версия чарта и appVersion берутся из МЕТКИ `v<версия>` — той же, по
# которой производитель образа публикует образ `v<версия>`: одна метка — одна
# версия поставки, образ и чарт. Версия в `deploy/Chart.yaml` в дереве при этом
# не правится: она — версия рабочего дерева, а не выпуска.
#
# ОПУБЛИКОВАННАЯ ВЕРСИЯ НЕИЗМЕНЯЕМА. Если она уже есть в реестре, публикация
# отказывает: новая версия — новая метка. Иначе дайджест, закреплённый
# установкой, менялся бы под ней.
#
# «ВЕРСИИ НЕТ» РАСПОЗНАЁТСЯ ПО ФОРМЕ ОТВЕТА РЕЕСТРА, А НЕ ПО СЛОВУ. Слова
# «not found» в выводе `helm show` мало: его же печатают помощник учётных
# данных («executable file not found in $PATH»), служба токена («404 Not
# Found») и отсутствующий плагин («plugin … not found») — и каждый такой отказ
# читался бы как «версии нет, публикуй». Поэтому «версии нет» — ровно три формы:
# `<ссылка на эту версию>: not found`, код OCI `manifest unknown` и код OCI
# `name unknown`. Всё прочее — отказ «ответ не распознан», а не «наверное, нет».
#
# Окружение: ACTOR, TOKEN (GITHUB_TOKEN задания с `packages: write` — секрета
# в дереве нет), RUNNER_TEMP, GITHUB_STEP_SUMMARY.
#
# Исходы: 0 — опубликовано, дайджест напечатан; 1 — отказ (версия уже есть,
# ответ реестра не распознан, дайджеста нет); 64 — метка не версия.
#
# `--self-test` — разбор метки, классификация ответа реестра и ВЕСЬ сценарий
# публикации с поддельным helm в PATH: каждая ветка отказа доказывается тем,
# что чарт НЕ отправлен, а не только кодом классификатора. Сети и реестра
# самопроверка не трогает.
set -euo pipefail

OCI_HOST="ghcr.io"
OCI_REPO="oci://$OCI_HOST/pro-robotech/charts"
CHART_NAME="kaname"

# version_of_tag <метка> — печатает версию из `v<МАЖОР>.<МИНОР>.<ПАТЧ>`, иначе
# код 64. Ведущий ноль в числе — не версия: semver его не допускает, и helm
# отверг бы её уже при упаковке, назвав не тот предмет.
version_of_tag() {
    local ref="$1"
    if [[ "$ref" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
        printf '%s\n' "${ref#v}"
        return 0
    fi
    return 64
}

# classify_show <код helm show> <вывод> <версия> — 0: версии в реестре нет,
# публиковать; 1: версия уже опубликована (или реестр ответил успехом); 2: ответ
# не распознан — ни то, ни другое.
classify_show() {
    local rc="$1" out="$2" version="$3"
    if [ "$rc" -eq 0 ]; then
        return 1
    fi
    # Ссылка на ЭТУ версию, за ней «: not found» — отказ самого реестра о версии.
    if grep -qiF "$OCI_HOST/pro-robotech/charts/$CHART_NAME:$version: not found" <<<"$out"; then
        return 0
    fi
    # Коды ошибок OCI distribution: манифеста или репозитория в реестре нет.
    if grep -qE '(^|[^A-Za-z_])(manifest unknown|name unknown)([^A-Za-z_]|$)' <<<"$out"; then
        return 0
    fi
    return 2
}

# publish <метка> — весь сценарий публикации.
publish() {
    local ref="$1" version declared root chart_dir show_rc show_out verdict pkg push_out digest
    version="$(version_of_tag "$ref")" || {
        echo "chart-publish: метка «$ref» не версия v<МАЖОР>.<МИНОР>.<ПАТЧ> — публиковать нечего" >&2
        exit 64
    }
    : "${ACTOR:?ACTOR не задан}" "${TOKEN:?TOKEN не задан}" "${RUNNER_TEMP:?RUNNER_TEMP не задан}"
    : "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY не задан}"

    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    chart_dir="$root/deploy"
    declared="$(sed -n 's/^name: //p' "$chart_dir/Chart.yaml")"
    if [ "$declared" != "$CHART_NAME" ]; then
        echo "chart-publish: в $chart_dir/Chart.yaml имя «$declared», а публикуется «$CHART_NAME» — адрес в реестре разошёлся бы с чартом" >&2
        exit 1
    fi

    printf '%s' "$TOKEN" | helm registry login "$OCI_HOST" -u "$ACTOR" --password-stdin

    show_rc=0
    show_out="$(helm show chart "$OCI_REPO/$CHART_NAME" --version "$version" 2>&1)" || show_rc=$?
    verdict=0
    classify_show "$show_rc" "$show_out" "$version" || verdict=$?
    case "$verdict" in
        0) ;;
        1)
            echo "chart-publish: $CHART_NAME $version уже опубликован; опубликованная версия неизменяема — нужна новая метка" >&2
            exit 1
            ;;
        *)
            echo "chart-publish: ответ реестра не распознан — нельзя сказать, есть ли $CHART_NAME $version, отказ: $show_out" >&2
            exit 1
            ;;
    esac

    pkg="$RUNNER_TEMP/chart-pkg"
    mkdir -p "$pkg"
    helm package "$chart_dir" --version "$version" --app-version "$version" -d "$pkg"
    push_out="$(helm push "$pkg/$CHART_NAME-$version.tgz" "$OCI_REPO" 2>&1)"
    echo "$push_out"
    digest="$(sed -n 's/^Digest: //p' <<<"$push_out")"
    if [[ ! "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        echo "chart-publish: в выводе helm push нет дайджеста — публикацию не подтвердить" >&2
        exit 1
    fi
    echo "опубликовано \`$OCI_REPO/$CHART_NAME:$version@$digest\`" >> "$GITHUB_STEP_SUMMARY"
}

# self_test — доказательство инъекцией в обе стороны.
self_test() {
    local probes=0 failed=0 box self
    self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    box="$(mktemp -d)"
    # shellcheck disable=SC2064 # путь фиксируется сейчас намеренно
    trap "rm -rf '$box'" EXIT

    tag() { # tag <ожидаемый код> <метка> [ожидаемая версия]
        local want="$1" ref="$2" ver="${3:-}" got=0 out=""
        probes=$((probes + 1))
        out="$(version_of_tag "$ref")" || got=$?
        if [ "$got" -ne "$want" ] || [ "$out" != "$ver" ]; then
            echo "  ПРОВАЛ метка «$ref» — ждали код $want и «$ver», получили $got и «$out»" >&2
            failed=$((failed + 1))
            return 0
        fi
        echo "  ok   метка «$ref» (код $got${out:+, версия $out})"
    }
    show() { # show <ожидаемый> <код helm show> <вывод> <имя>
        local want="$1" got=0
        probes=$((probes + 1))
        classify_show "$2" "$3" "9.9.9" || got=$?
        if [ "$got" -ne "$want" ]; then
            echo "  ПРОВАЛ $4 — ждали $want, получили $got" >&2
            failed=$((failed + 1))
            return 0
        fi
        echo "  ok   $4 (код $got)"
    }

    # Поддельный helm: отвечает на `show chart` заданным выводом и кодом, на
    # `package` кладёт пустой архив, на `push` печатает дайджест (или заданный
    # вывод) — и пишет каждый вызов в журнал. Отправлен ли чарт, видно по
    # журналу, а не по слову скрипта о себе.
    mkdir -p "$box/bin"
    cat > "$box/bin/helm" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_LOG"
case "${1:-} ${2:-}" in
    "registry login") cat > /dev/null; exit 0 ;;
    "show chart") printf '%s' "$FAKE_SHOW_OUT"; exit "$FAKE_SHOW_RC" ;;
esac
case "${1:-}" in
    package)
        d=""; v=""
        while [ $# -gt 0 ]; do
            case "$1" in -d) d="$2"; shift ;; --version) v="$2"; shift ;; esac
            shift
        done
        : > "$d/kaname-$v.tgz"; echo "Successfully packaged"; exit 0 ;;
    push)
        if [ -n "${FAKE_PUSH_OUT+x}" ]; then printf '%s\n' "$FAKE_PUSH_OUT"
        else printf 'Pushed: ghcr.io/pro-robotech/charts/kaname:9.9.9\nDigest: sha256:%s\n' \
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; fi
        exit 0 ;;
esac
exit 99
FAKE
    chmod +x "$box/bin/helm"

    # scenario <ожидаемо: publish|refuse|refuse64|pushed-refused> <код show> <вывод show> <имя> [метка]
    scenario() {
        local want="$1" src="$2" sout="$3" name="$4" ref="${5:-v9.9.9}" rc=0 pushed=no got
        probes=$((probes + 1))
        : > "$box/log"; : > "$box/sum"; rm -rf "$box/rt"; mkdir -p "$box/rt"
        PATH="$box/bin:$PATH" FAKE_LOG="$box/log" FAKE_SHOW_RC="$src" FAKE_SHOW_OUT="$sout" \
            ACTOR=probe TOKEN=probe RUNNER_TEMP="$box/rt" GITHUB_STEP_SUMMARY="$box/sum" \
            bash "$self" "$ref" > "$box/out" 2>&1 || rc=$?
        grep -q '^push ' "$box/log" && pushed=yes
        case "$rc:$pushed" in
            0:yes) got=publish ;;
            64:no) got=refuse64 ;;
            0:no) got="код 0 без отправки" ;;
            *:no) got=refuse ;;
            *:yes) got="pushed-refused" ;;
        esac
        if [ "$got" != "$want" ]; then
            echo "  ПРОВАЛ сценарий $name — ждали $want, получили $got (код $rc, отправлен: $pushed)" >&2
            sed 's/^/         /' "$box/out" | tail -3 >&2
            failed=$((failed + 1))
            return 0
        fi
        echo "  ok   сценарий $name ($got)"
    }

    # Дословный вывод помощника учётных данных: `$PATH` в нём — текст, а не
    # подстановка.
    # shellcheck disable=SC2016 # литерал вывода, раскрытие не нужно
    local cred_helper_out='Error: error getting credentials - err: exec: "docker-credential-desktop": executable file not found in $PATH, out: ``'

    echo "=== chart-publish: метка версии ==="
    # Положительные близнецы: без них отказы ниже зеленели бы на разборе,
    # отвергающем всё.
    tag 0 "v0.1.0" "0.1.0"
    tag 0 "v12.0.304" "12.0.304"
    tag 64 "0.1.0"
    tag 64 "v1.2"
    tag 64 "v1.2.3-rc1"
    tag 64 "v01.2.3"
    tag 64 "kaname-1.2.3"
    tag 64 "v1.2.3 "
    tag 64 ""

    echo "=== chart-publish: ответ реестра о версии (классификатор) ==="
    show 0 1 "Error: ghcr.io/pro-robotech/charts/kaname:9.9.9: not found" "(−) версии нет — публиковать"
    show 0 1 "Error: failed to perform \"FetchReference\" on source: manifest unknown" "(−) манифеста нет — публиковать"
    show 1 0 "apiVersion: v2
name: kaname
version: 0.1.0" "(+) версия есть — отказ, неизменяемость"
    show 2 1 "Error: unexpected status code 401: unauthorized" "(+) отказ доступа — не распознан, а не «нет»"
    show 2 1 "" "(+) пустой ответ — не распознан"
    show 2 1 "Error: ghcr.io/pro-robotech/charts/kaname:1.0.0: not found" "(+) «not found» о ДРУГОЙ версии — не распознан"
    show 2 1 "$cred_helper_out" "(+) S12 помощник учётных данных — не распознан"
    show 2 1 "Error: failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token?scope=repository%3Apro-robotech%2Fcharts%2Fkaname%3Apull&service=ghcr.io: 404 Not Found" "(+) S13 служба токена 404 — не распознан"
    show 2 1 'Error: plugin "oci-helper" not found' "(+) S14 плагин не найден — не распознан"

    echo "=== chart-publish: весь сценарий с поддельным helm ==="
    # Положительные близнецы: три формы «версии нет» — чарт отправлен.
    scenario publish 1 "Error: ghcr.io/pro-robotech/charts/kaname:9.9.9: not found" "S02 версии нет"
    scenario publish 1 "Error: failed to perform \"FetchReference\" on source: manifest unknown" "S03 manifest unknown"
    scenario publish 1 "Error: GET \"https://ghcr.io/v2/pro-robotech/charts/kaname/tags/list\": response status code 404: name unknown: repository name not known to registry" "S04 name unknown"
    # Ветка «уже опубликована»: чарт НЕ отправлен.
    scenario refuse 0 "apiVersion: v2
name: kaname
version: 9.9.9" "S01 версия есть"
    scenario refuse 0 "" "S10 успех с пустым выводом"
    # Ветка «ответ не распознан»: чарт НЕ отправлен.
    scenario refuse 1 "Error: unexpected status code 401: unauthorized" "S05 401"
    scenario refuse 1 "Error: failed to authorize: failed to fetch oauth token: unexpected status: 403 Forbidden" "S06 403"
    scenario refuse 1 "Error: GET \"https://ghcr.io/v2/pro-robotech/charts/kaname/manifests/9.9.9\": response status code 500: Internal Server Error" "S07 500"
    scenario refuse 1 "Error: Get \"https://ghcr.io/v2/\": context deadline exceeded" "S08 таймаут"
    scenario refuse 1 "" "S09 пустой ответ"
    scenario refuse 1 "Error: Get \"https://ghcr.io/v2/\": dial tcp: lookup ghcr.io on 127.0.0.53:53: no such host" "S11 DNS"
    scenario refuse 1 "$cred_helper_out" "S12 помощник учётных данных"
    scenario refuse 1 "Error: failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token?scope=repository%3Apro-robotech%2Fcharts%2Fkaname%3Apull&service=ghcr.io: 404 Not Found" "S13 служба токена 404"
    scenario refuse 1 'Error: plugin "oci-helper" not found' "S14 плагин не найден"
    scenario refuse64 1 "Error: ghcr.io/pro-robotech/charts/kaname:9.9.9: not found" "S15 метка не версия" "v1.2"
    FAKE_PUSH_OUT='Pushed: ghcr.io/pro-robotech/charts/kaname:9.9.9' \
        scenario pushed-refused 1 "Error: ghcr.io/pro-robotech/charts/kaname:9.9.9: not found" "S16 отправка без дайджеста"

    echo
    echo "chart-publish --self-test: проб исполнено $probes, провалов $failed"
    [ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
    [ "$failed" -gt 0 ] && exit 1
    exit 0
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
fi
publish "${1:?метка: chart-publish.sh v<МАЖОР>.<МИНОР>.<ПАТЧ>}"
