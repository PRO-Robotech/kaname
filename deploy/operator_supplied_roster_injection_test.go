// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operator_supplied_roster_injection_test.go — доказательство того, что соседний
// гейт СПОСОБЕН упасть и падает на своём предмете.
//
// Инъекция зовёт ТО ЖЕ ТЕЛО ВЕРДИКТА (`judgeOperatorSuppliedRoster`) и ТОТ ЖЕ
// РАСПОЗНАВАТЕЛЬ (`rosterJudged`), что исполняются на дереве: второе тело
// разошлось бы с первым молча, и доказательство относилось бы к другому коду.
//
// ПОДМЕНЯЕТСЯ ОДИН ФАКТ на случай, и у каждого отрицания рядом законный близнец.
package deploy_test

import (
	"strings"
	"testing"
)

// rosterSets — вход вердикта одним местом: класс координат, что перечень
// стережёт, что называет, у чего пусто умолчание.
func rosterSets(class, guarded, named, empty []string) (c, g, n, e map[string]bool) {
	mk := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	return mk(class), mk(guarded), mk(named), mk(empty)
}

func TestOperatorSuppliedRosterInjection_CompleteRosterIsSilent(t *testing.T) {
	// КОНТРОЛЬ: каждая координата класса и стережётся, и названа.
	c, g, n, e := rosterSets(
		[]string{"image", "db.host", "tls.secretName"},
		[]string{"image", "db.host", "tls.secretName"},
		[]string{"image", "db.host", "tls.secretName"},
		[]string{"image", "db.host", "tls.secretName"})
	if f := judgeOperatorSuppliedRoster(c, g, n, e); len(f) != 0 {
		t.Fatalf("вердикт покраснел на полном перечне: %v", f)
	}
}

func TestOperatorSuppliedRosterInjection_UnguardedCoordinateIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ, ОДИН ФАКТ: координата класса выпала из перечня. Это и есть
	// состояние до фикса #2488.
	c, g, n, e := rosterSets(
		[]string{"image", "tls.secretName"},
		[]string{"image"},
		[]string{"image"},
		[]string{"image", "tls.secretName"})
	f := judgeOperatorSuppliedRoster(c, g, n, e)
	if len(f) != 1 || !strings.Contains(f[0], "tls.secretName") {
		t.Fatalf("выпавшая координата не найдена: %v", f)
	}
}

func TestOperatorSuppliedRosterInjection_GuardedButUnnamedIsAFinding(t *testing.T) {
	// ВТОРОЕ ИЗМЕРЕНИЕ: условие есть, имени в тексте отказа нет. Оператор
	// получает отказ установки и не знает, какой ключ дописать.
	c, g, n, e := rosterSets(
		[]string{"image"}, []string{"image"}, []string{}, []string{"image"})
	f := judgeOperatorSuppliedRoster(c, g, n, e)
	if len(f) != 1 || !strings.Contains(f[0], "НАЗЫВАЕТ") {
		t.Fatalf("условие без имени не найдено: %v", f)
	}
}

// TestOperatorSuppliedRosterInjection_CoordinateWithADefaultIsNotDemanded —
// ЗАКОННЫЙ БЛИЗНЕЦ инъекции про выпавшую координату: у той же координаты
// ПОЯВИЛОСЬ умолчание, и требовать её от оператора больше нечего.
//
// Без этой пробы гейт запрещал бы чарту заводить умолчание — то есть краснел бы
// на верном чарте, и его отключили бы первым.
func TestOperatorSuppliedRosterInjection_CoordinateWithADefaultIsNotDemanded(t *testing.T) {
	c, g, n, e := rosterSets(
		[]string{"image", "tls.secretName"},
		[]string{"image"},
		[]string{"image"},
		[]string{"image"}) // у tls.secretName умолчание непусто
	if f := judgeOperatorSuppliedRoster(c, g, n, e); len(f) != 0 {
		t.Fatalf("координата с умолчанием потребована от оператора: %v", f)
	}
}

func TestOperatorSuppliedRosterInjection_StaleEntryIsAFinding(t *testing.T) {
	// САМОИСТЕЧЕНИЕ В ОБРАТНУЮ СТОРОНУ: перечень называет то, чего в классе нет.
	c, g, n, e := rosterSets(
		[]string{"image"}, []string{"image"},
		[]string{"image", "db.legacyHost"}, []string{"image"})
	f := judgeOperatorSuppliedRoster(c, g, n, e)
	if len(f) != 1 || !strings.Contains(f[0], "db.legacyHost") {
		t.Fatalf("запись без предмета не найдена: %v", f)
	}
}

// TestOperatorSuppliedRosterInjection_RecognizerKnowsBothWritings — обе законные
// формы записи перечня.
//
// Литерал и `printf` — разные тексты, и распознаватель, знающий одну, о другой
// МОЛЧИТ: не краснеет и не зеленеет, а просто не видит. Именно так три
// координаты TLS оказались бы вне наблюдения, будучи заведёнными.
func TestOperatorSuppliedRosterInjection_RecognizerKnowsBothWritings(t *testing.T) {
	body := "{{- $db := .Values.db | default dict -}}\n" +
		"{{- $tls := .Values.tls | default dict -}}\n" +
		"{{- if not .Values.image -}}\n" +
		"{{- $missing = append $missing \"  image  — координата образа\" -}}\n" +
		"{{- end -}}\n" +
		"{{- if not $db.host -}}\n" +
		"{{- $missing = append $missing \"  db.host  — узел базы\" -}}\n" +
		"{{- end -}}\n" +
		"{{- if and $namesServer (not $tls.secretName) -}}\n" +
		"{{- $missing = append $missing (printf \"  tls.secretName  — секрет %s\" $namesServer) -}}\n" +
		"{{- end -}}\n"
	guarded, named := rosterJudged(body)
	for _, want := range []string{"image", "db.host", "tls.secretName"} {
		if !guarded[want] {
			t.Fatalf("условие для %q не распознано: %v", want, guarded)
		}
		if !named[want] {
			t.Fatalf("имя %q в тексте отказа не распознано: %v", want, named)
		}
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ распознавателя: проза о ключе объявлением НЕ является.
	// Без этой половины распознаватель краснел бы на собственном объяснении.
	prose := "{{/* здесь мы судим .Values.image и db.host, а также $tls.secretName */}}\n"
	guarded, named = rosterJudged(prose)
	if len(guarded) != 0 || len(named) != 0 {
		t.Fatalf("проза сосчитана объявлением: стережёт %v, называет %v", guarded, named)
	}
}
