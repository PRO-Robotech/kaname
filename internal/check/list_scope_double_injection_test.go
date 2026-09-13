// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_scope_double_injection_test.go — доказательство, что гейт
// снисходительного дублёра СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17,
// семейство `listscopedoubleisnotlenient`).
//
// Инъекция зовёт ТУ ЖЕ функцию, что и гейт (`check.AuditLenientScopes`), а не
// свою копию: копия доказывала бы свойство копии.
//
// # Законный близнец у КАЖДОЙ оси
//
// Односторонняя проверка зеленела бы на дереве, где сломано всё сразу. Поэтому
// рядом с каждой находкой стоит вход той же формы, на котором гейт обязан
// МОЛЧАТЬ.
//
// # Каждая инъекция меняет РОВНО ОДИН факт против своего близнеца
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// lenientDouble — исполняемое объявление снисходительной области. Ровно та
// форма, которую разбор обязан узнавать узлом.
const lenientDouble = `package probe

import "x/visibility"

type double struct{}

func (double) ScopeOf() visibility.Scope {
	return visibility.Scope{Unrestricted: true}
}
`

// strictDouble — законный близнец: дублёр, который область СУЖАЕТ.
const strictDouble = `package probe

import "x/visibility"

type double struct{}

func (double) ScopeOf() visibility.Scope {
	return visibility.Scope{Unrestricted: false}
}
`

// holderTests — тело держателя: пробы у него есть.
const holderTests = `package listvisibility

import "testing"

func TestCandidatesAreNarrowed(t *testing.T) {}
`

// lenientTree — синтетический корень use-case.
type lenientTree map[string]string // относительный путь → тело файла

func (tr lenientTree) build(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range tr {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
	}
	return root
}

// withRef — то же тело дублёра, но с ссылкой на держателя в комментарии.
func withRef(coord string) string {
	return "// Настоящий отбор держит " + coord + ".\n" + lenientDouble
}

// auditOn — находки гейта на синтетическом дереве.
func auditOn(t *testing.T, tr lenientTree) (check.LenientScopeCensus, []string) {
	t.Helper()
	census, findings, err := check.AuditLenientScopes(tr.build(t))
	if err != nil {
		t.Fatalf("фикстура не прочитана: %v", err)
	}
	return census, findings
}

// TestLenientScopeDoubleGate_Injection — обе способности по каждой оси.
func TestLenientScopeDoubleGate_Injection(t *testing.T) {
	t.Parallel()

	// ── КОНТРОЛЬ: ссылка есть, держатель жив — гейт обязан молчать ──────────
	//
	// Стоит первым и не формальность: без него всякая находка ниже объяснялась
	// бы гейтом, который краснеет на любом входе.
	{
		census, got := auditOn(t, lenientTree{
			"role/list_test.go":             withRef("internal/apps/kaname/api/listvisibility"),
			"listvisibility/holder_test.go": holderTests,
			"account/strict_test.go":        strictDouble,
		})
		if len(got) != 0 {
			t.Fatalf("КОНТРОЛЬ: на исправном дереве гейт нашёл %d — он краснеет на исправном "+
				"входе, и ни одна находка ниже ничего не доказывает:\n  %s",
				len(got), strings.Join(got, "\n  "))
		}
		if census.Lenient != 1 {
			t.Fatalf("КОНТРОЛЬ: снисходительных насчитано %d вместо 1 — разбор узла сломан",
				census.Lenient)
		}
		// Пакет, СУЖАЮЩИЙ область, под разбор не подпадает: гейт, требующий
		// ссылку от каждого пакета, краснел бы на двадцати из двадцати семи.
		t.Logf("контроль: %s", census.String())
	}

	// ── ОСЬ 1: ОБЕ формы координаты видны разбору ──────────────────────────
	//
	// Несущая ось порта. В дереве живут две законные формы: с приставкой
	// платформы (канон вызовов `platformtree`) и без неё. Распознаватель,
	// знающий одну, дал бы не красное и не зелёное, а НЕВИДИМОСТЬ половины —
	// и семь пакетов из семи объявились бы «держателя не назвали».
	for name, coord := range map[string]string{
		"с приставкой платформы": "services/iam/internal/apps/kaname/api/listvisibility",
		"без приставки":          "internal/apps/kaname/api/listvisibility",
	} {
		census, got := auditOn(t, lenientTree{
			"role/list_test.go":             withRef(coord),
			"listvisibility/holder_test.go": holderTests,
		})
		if len(got) != 0 {
			t.Fatalf("ось «%s»: гейт нашёл %d на входе, где ссылка законна — форма "+
				"выпала бы из наблюдения молча:\n  %s", name, len(got), strings.Join(got, "\n  "))
		}
		if census.Named != 1 {
			t.Fatalf("ось «%s»: ссылка не зачтена (названо %d из 1)", name, census.Named)
		}
	}
	t.Log("ось «две формы координаты»: обе прочитаны, ни одна не выпала из наблюдения")

	// ── ОСЬ 2: снисходительный дублёр БЕЗ ссылки — находка ─────────────────
	//
	// Меняется ровно один факт против контроля: из комментария убрана ссылка.
	{
		_, got := auditOn(t, lenientTree{
			"role/list_test.go":             lenientDouble,
			"listvisibility/holder_test.go": holderTests,
		})
		if len(got) != 1 || !strings.Contains(got[0], "держатель свойства не назван") {
			t.Fatalf("ось «нет ссылки»: ожидалась 1 находка с этим предметом, получено %d:\n  %s",
				len(got), strings.Join(got, "\n  "))
		}
		if !strings.Contains(got[0], "role") {
			t.Errorf("находка не называет пакет: %s", got[0])
		}
		t.Logf("инъекция «нет ссылки»: 1 находка — %s", got[0])
	}

	// ── ОСЬ 3: держателя СНЯЛИ — ссылка есть, каталога нет ─────────────────
	//
	// Ровно тот случай, ради которого семейство заведено: свойство перестало
	// проверяться где бы то ни было, а ссылка осталась и читается как покрытие.
	{
		_, got := auditOn(t, lenientTree{
			"role/list_test.go": withRef("internal/apps/kaname/api/listvisibility"),
		})
		if len(got) != 1 || !strings.Contains(got[0], "проб не несёт") {
			t.Fatalf("ось «держателя сняли»: ожидалась 1 находка с этим предметом, получено %d:\n  %s",
				len(got), strings.Join(got, "\n  "))
		}
		if !strings.Contains(got[0], "listvisibility") {
			t.Errorf("находка не называет ИМЯ снятого держателя — снятие было бы тихим: %s", got[0])
		}
		t.Logf("инъекция «держателя сняли»: 1 находка с его именем")
	}

	// ── ОСЬ 4: держатель ЕСТЬ, но проб в нём НЕТ ───────────────────────────
	//
	// Отличается от оси 3 ровно одним фактом: каталог существует. Без этой оси
	// гейт зеленел бы на пустом держателе — та же тишина, только с адресом.
	{
		_, got := auditOn(t, lenientTree{
			"role/list_test.go":              withRef("internal/apps/kaname/api/listvisibility"),
			"listvisibility/nothing_test.go": "package listvisibility\n",
		})
		if len(got) != 1 || !strings.Contains(got[0], "ни одной пробы") {
			t.Fatalf("ось «держатель без проб»: ожидалась 1 находка с этим предметом, получено %d:\n  %s",
				len(got), strings.Join(got, "\n  "))
		}
		t.Log("инъекция «держатель без проб»: ссылка на пустой каталог покрытием не зачтена")
	}

	// ── ОСЬ 5: слово в КОММЕНТАРИИ снисходительностью не является ──────────
	//
	// Разбор по тексту зеленел бы на объяснении этой же снисходительности —
	// оставаясь зелёным на дереве, где снисходительных нет вовсе, и краснея
	// там, где они объяснены прозой.
	{
		census, _, err := check.AuditLenientScopes(lenientTree{
			"role/list_test.go": "// Дублёр возвращает visibility.Scope{Unrestricted: true} — так было раньше.\n" +
				strictDouble,
			"listvisibility/holder_test.go": holderTests,
		}.build(t))
		if err == nil {
			t.Fatalf("ось «слово в комментарии»: разбор зачёл прозу за снисходительность "+
				"(насчитано %d) — гейт зеленел бы на собственном объяснении", census.Lenient)
		}
		if !strings.Contains(err.Error(), "не найдено ни одного") {
			t.Errorf("отказ предпосылки не назван словами: %v", err)
		}
		t.Log("инъекция «слово в комментарии»: за объявление НЕ зачтено, предпосылка объявлена вслух")
	}

	// ── ПУСТОЙ ОБХОД — не «находок нет», а «прочитано ноль» ────────────────
	{
		if _, _, err := check.AuditLenientScopes(filepath.Join(t.TempDir(), "нетути")); err == nil {
			t.Error("несуществующий корень прочитался без ошибки — «ноль находок» стало бы " +
				"неотличимо от «ноль прочитанного»")
		}
		_, _, err := check.AuditLenientScopes(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "обход слеп") {
			t.Errorf("пустой корень не объявлен слепым обходом: %v", err)
		}
	}
}
