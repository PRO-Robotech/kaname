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
# установкой, менялся бы под ней. Ответ реестра, по которому нельзя сказать,
# есть версия или нет, — тоже отказ, а не «наверное, нет».
#
# Окружение: ACTOR, TOKEN (GITHUB_TOKEN задания с `packages: write` — секрета
# в дереве нет), RUNNER_TEMP, GITHUB_STEP_SUMMARY.
#
# Исходы: 0 — опубликовано, дайджест напечатан; 1 — отказ (версия уже есть,
# ответ реестра не распознан, дайджеста нет); 64 — метка не версия.
#
# `--self-test` — разбор метки и классификация ответа реестра, обе стороны,
# без сети.
set -euo pipefail

OCI_REPO="oci://ghcr.io/pro-robotech/charts"
OCI_HOST="ghcr.io"
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

# classify_show <код helm show> <вывод> — 0: версии в реестре нет, публиковать;
# 1: версия уже опубликована; 2: ответ не распознан — ни то, ни другое.
classify_show() {
    local rc="$1" out="$2"
    if [ "$rc" -eq 0 ]; then
        return 1
    fi
    if grep -qiE 'not found|manifest unknown|name unknown' <<<"$out"; then
        return 0
    fi
    return 2
}

if [ "${1:-}" = "--self-test" ]; then
    probes=0
    failed=0
    tag() { # tag <ожидаемый код> <метка> [ожидаемая версия]
        local want="$1" ref="$2" ver="${3:-}" got=0 out=""
        probes=$((probes + 1))
        out="$(version_of_tag "$ref")" || got=$?
        if [ "$got" -ne "$want" ] || [ "$out" != "$ver" ]; then
            echo "  ПРОВАЛ метка «$ref» — ждали код $want и «$ver», получили $got и «$out»" >&2
            failed=$((failed + 1))
            return
        fi
        echo "  ok   метка «$ref» (код $got${out:+, версия $out})"
    }
    show() { # show <ожидаемый> <код helm show> <вывод> <имя>
        local want="$1" got=0
        probes=$((probes + 1))
        classify_show "$2" "$3" || got=$?
        if [ "$got" -ne "$want" ]; then
            echo "  ПРОВАЛ $4 — ждали $want, получили $got" >&2
            failed=$((failed + 1))
            return
        fi
        echo "  ok   $4 (код $got)"
    }

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

    echo "=== chart-publish: ответ реестра о версии ==="
    show 0 1 "Error: ghcr.io/pro-robotech/charts/kaname:9.9.9: not found" "(−) версии нет — публиковать"
    show 0 1 "Error: failed to perform \"FetchReference\" on source: manifest unknown" "(−) манифеста нет — публиковать"
    show 1 0 "apiVersion: v2
name: kaname
version: 0.1.0" "(+) версия есть — отказ, неизменяемость"
    show 2 1 "Error: unexpected status code 401: unauthorized" "(+) отказ доступа — не распознан, а не «нет»"
    show 2 1 "" "(+) пустой ответ — не распознан"

    echo
    echo "chart-publish --self-test: проб исполнено $probes, провалов $failed"
    [ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
    [ "$failed" -gt 0 ] && exit 1
    exit 0
fi

ref="${1:?метка: chart-publish.sh v<МАЖОР>.<МИНОР>.<ПАТЧ>}"
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
classify_show "$show_rc" "$show_out" || verdict=$?
case "$verdict" in
    0) ;;
    1)
        echo "chart-publish: $CHART_NAME $version уже опубликован; опубликованная версия неизменяема — нужна новая метка" >&2
        exit 1
        ;;
    *)
        echo "chart-publish: по ответу реестра нельзя сказать, есть ли $CHART_NAME $version, — отказ: $show_out" >&2
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
