// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// exclusion_expiry_test.go — послабление обязано истекать САМО, на внешнем факте.
//
// `conditions` исключён из гейта сужения списка не потому, что сужать нечего, а
// потому, что сужать СЕЙЧАС нельзя: модель объявляет тип `iam_condition` со всем
// набором глаголов, но ни одна строка их не материализует — `iam.condition` нет в
// множестве материализуемых типов реконсайлера. Сузить страницу этим отношением
// значило бы вернуть пустую страницу всем, кроме тех, кто доходит до условия
// каскадом `super_admin from project`, — включая редактора, который условие создал.
//
// Предикат снятия взят НЕ из того, что переделывает само послабление (это и есть
// классическая ошибка самоистечения — предикат, тождественно истинный после
// изменения), а из внешнего факта: множества материализуемых типов. В тот момент,
// когда условия туда попадут, обоснование исчезает, фильтр становится должен — и
// эта проба обязана покраснеть, а не молча остаться зелёной.
package auditlistfilter

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// conditionsType — как условия названы в реестре типов реконсайлера.
const conditionsType = `"iam.condition"`

// feedRegistry — файл, объявляющий, какие типы реконсайлер умеет материализовать
// per-object. Это и есть внешний факт, на котором держится послабление.
const feedRegistry = "../../internal/domain/feed_registry.go"

// runnerScript — обёртка, несущая список послаблений.
const runnerScript = "../audit-list-filter.sh"

func readRelativeToThisFile(t *testing.T, rel string) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller не сработал — проба не знает, где она лежит")
	}
	p := filepath.Join(filepath.Dir(self), rel)
	raw, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatalf("не прочитан %s: %v", p, err)
	}
	if len(raw) == 0 {
		t.Fatalf("%s пуст — проба смотрит не туда, её вердикт беспредметен", p)
	}
	return string(raw)
}

// Пока условия НЕ материализуемы — послабление законно. Как только станут —
// послабление обязано уйти, и эта проба краснеет, пока оно на месте.
func TestConditionsExclusion_ExpiresWhenConditionsBecomeMaterialisable(t *testing.T) {
	registry := readRelativeToThisFile(t, feedRegistry)
	runner := readRelativeToThisFile(t, runnerScript)

	// Утверждение о ПРЕДПОСЫЛКЕ пробы: файл, который она читает, действительно
	// объявляет множество типов. Иначе «условий там нет» означало бы «я читаю не
	// тот файл», и оба исхода были бы одним и тем же зелёным.
	if !strings.Contains(registry, "labelSelectableTypes") {
		t.Fatalf("%s не объявляет labelSelectableTypes — предпосылка пробы не выполняется, "+
			"предикат снятия проверять не по чему", feedRegistry)
	}

	materialisable := strings.Contains(registry, conditionsType)
	excluded := strings.Contains(runner, "--allow=conditions")

	switch {
	case materialisable && excluded:
		t.Fatalf("условия стали материализуемы (%s появился в %s), значит per-object отношение "+
			"на них теперь кто-то пишет и сужение страницы стало возможным — "+
			"снимите --allow=conditions из %s и сузьте ConditionsService/List",
			conditionsType, feedRegistry, runnerScript)
	case !materialisable && !excluded:
		t.Fatalf("условия по-прежнему НЕ материализуемы (%s отсутствует в %s), но исключение "+
			"уже снято: сужение отдаст пустую страницу всем, кроме доходящих каскадом, "+
			"включая создателя условия", conditionsType, feedRegistry)
	}

	t.Logf("предпосылка держится: условия материализуемы=%v, исключение стоит=%v", materialisable, excluded)
}
