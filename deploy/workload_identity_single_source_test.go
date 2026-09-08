// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// workload_identity_single_source_test.go — имя рабочей нагрузки и метка, по
// которой её находит служба, обязаны выводиться ИЗ ОДНОГО ключа значений.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// У имени нагрузки в этом чарте ДВЕ стороны: Deployment им называет себя и
// помечает поды, Service по той же метке их отбирает. Пока обе стороны — один
// литерал, расхождения не бывает by construction. Как только одна выводится из
// значений, а вторая остаётся литералом, они становятся ДВУМЯ МЕСТАМИ ОБ ОДНОМ
// ПРЕДМЕТЕ — и первая же правка `.Values.name` разводит их молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТО ДОРОЖЕ, ЧЕМ ВЫГЛЯДИТ
//
// Расхождение НЕ даёт ни отказа рендера, ни отказа установки: оба объекта
// валидны, оба создаются, `helm install` выходит успехом. Service просто
// отбирает ПУСТОЕ множество подов — то есть служба поднялась, поды Ready,
// а по её адресу не отвечает никто. Со стороны это неотличимо от сетевой
// поломки, и ищут её где угодно, только не в чарте.
//
// Наблюдалось на этом дереве: `.Values.name` сменили с `iam` на `kaname`
// (собственное имя продукта, #2076) — Deployment и метки подов поехали за
// значением, Service остался с литералом `iam`, и его отбор стал пустым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ
//
// Отбор Service (`spec.selector.app`) записан ТЕМ ЖЕ выражением, что метка пода
// Deployment (`spec.template.metadata.labels.app`). Сравниваются ВЫРАЖЕНИЯ, а не
// их значения: значение зависит от профиля, а согласие сторон обязано держаться
// при любом.
//
// Проба читает ОБЪЯВЛЕНИЯ, а не рендер: ей не нужен ни helm, ни скачанные
// зависимости, поэтому она не умеет пропуститься.
//
// Пустой обход — находка: чарт без Deployment либо без Service означает, что
// проверка стережёт координату, которой больше нет.

package deploy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// reSelectorApp — значение ключа `app:` внутри блока отбора Service.
var reSelectorApp = regexp.MustCompile(`(?m)^\s*selector:\s*\n\s*app:\s*(\S.*?)\s*$`)

// rePodLabelApp — значение ключа `app:` в метках шаблона пода Deployment.
var rePodLabelApp = regexp.MustCompile(`(?m)^\s*template:\s*\n\s*metadata:\s*\n\s*labels:\s*\n\s*app:\s*(\S.*?)\s*$`)

func TestServiceSelectorAndPodLabelComeFromOneSource(t *testing.T) {
	dir := "templates"

	svc, err := os.ReadFile(filepath.Join(dir, "service.yaml"))
	require.NoError(t, err, "шаблона Service в чарте нет — проверка стережёт координату, которой больше нет")
	dep, err := os.ReadFile(filepath.Join(dir, "deployment.yaml"))
	require.NoError(t, err, "шаблона Deployment в чарте нет — проверка стережёт координату, которой больше нет")

	msel := reSelectorApp.FindStringSubmatch(string(svc))
	require.NotNil(t, msel, "в шаблоне Service не найден отбор `selector.app` — "+
		"либо форма объявления сменилась, либо отбора нет вовсе; в обоих случаях "+
		"эта проверка больше ничего не читает")
	mlab := rePodLabelApp.FindStringSubmatch(string(dep))
	require.NotNil(t, mlab, "в шаблоне Deployment не найдена метка пода `template.metadata.labels.app` — "+
		"обход пуст, вердикт беспредметен")

	t.Logf("осмотрено: шаблонов 2; отбор Service `app: %s`, метка пода Deployment `app: %s`",
		msel[1], mlab[1])

	require.Equal(t, mlab[1], msel[1],
		"отбор Service и метка пода записаны РАЗНЫМИ выражениями: Service отбирает `app: %s`, "+
			"а Deployment помечает поды `app: %s`. Рендер, установка и готовность подов при этом "+
			"проходят — отбор просто становится пустым, и по адресу службы не отвечает никто. "+
			"Обе стороны обязаны выводиться из одного ключа значений", msel[1], mlab[1])
}
