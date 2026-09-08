#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

#
# render-guard.sh — офлайновый страж РЕНДЕРА чарта отдельно поставленной службы.
#
# ЧТО ОН УТВЕРЖДАЕТ: вход, который чарт отдаёт процессу, страж старта ПРИНИМАЕТ.
# Вход собирается настоящим `helm template`, а не переложением шаблона на Go:
# переложение проверялось в одну сторону, и два ключа оказались вне наблюдения —
# один из них нёс отказ, из-за которого боевой профиль рендерился и не стартовал
# (задачи #2333, #2334).
#
# ЧЕМ ОН НЕ ЯВЛЯЕТСЯ: он не поднимает пода и об установке в кластере не
# утверждает ничего — это «не выполнилось», третья категория, а не зелёное.
#
# ПОЧЕМУ ОТДЕЛЬНЫЙ ВХОД, А НЕ ОБЫЧНЫЙ `go test ./deploy/`. helm пришпилен ровно к
# одной job конвейера (`helm` в .github/workflows/ci.yaml); job, гоняющая юниты
# модуля службы, его не несёт. Прогон рендер-проб оттуда либо падал бы на
# отсутствии helm, либо — что хуже — молча пропускался, и гейт стал бы инертным
# на той самой джобе, что гейтит мёрж.
#
# Поэтому вердикт производит ЭТА полоса, и она объявляет себя переменной
# HELM_RENDER_GUARD_LANE: с ней отсутствие helm — ОТКАЗ (полоса обещала вердикт
# и не может его дать), без неё — пропуск с прямо названной третьей категорией.
# Там, где helm есть, пробы идут всегда: на машине разработчика гейт живой.
#
# Провязку из конвейера держит гейт класса
# internal/repohygiene/artifactgates/renderguard_test.go: страж рендера, который
# не зовётся ниоткуда, — ровно тот дефект, против которого он написан.
#
# Использование: deploy/render-guard.sh   (либо `make -C services/iam helm-render-guard`)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HELM_BIN="${HELM_BIN:-helm}"

command -v "$HELM_BIN" >/dev/null 2>&1 || {
	echo "render-guard: helm не в PATH — полоса рендера обещала вердикт и дать его не может" >&2
	exit 1
}

echo "render-guard: helm $("$HELM_BIN" version --short 2>/dev/null || echo '?') · чарт $SCRIPT_DIR"

# Отбор именами, а не всем пакетом: остальные пробы каталога helm не требуют и
# гоняются обычной job юнитов. Прогон их здесь второй раз стоил бы времени и
# ничего не добавил.
#
# `-count=1` обязателен: состав ответа берётся из ПОДПРОЦЕССА (helm), о котором
# `go test` не знает, и кеш вернул бы вердикт о чужом дереве.
cd "$MODULE_DIR"
HELM_RENDER_GUARD_LANE=1 go test ./deploy/ -count=1 -v \
	-run 'TestProdProfile_Rendered|TestConfigBridge_CoversEveryKeyTheChartRenders|TestBridgeCoverageCensusCanFail|TestRenderedInputRefusesAnEmptyRender|TestRenderedFilesAreMountableCanFail|TestRenderedSecretStandInsCanFail|TestRenderedVerdictNamesEveryRefusal'

echo "render-guard: вход рендера принят стражем старта"
