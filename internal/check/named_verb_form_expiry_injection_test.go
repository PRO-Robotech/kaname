// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// named_verb_form_expiry_injection_test.go — ДОКАЗАТЕЛЬСТВО способности гейта
// `TestNamedVerbFormReturnsOnlyWithItsCompletenessCheck` упасть И смолчать.
//
// Порт с монорепо (снятый носитель инъекции того же семейства,
// `internal/repohygiene`, снят вынесением службы — `kacho#2597`). Дословно:
// предикат, фикстуры, все шесть прогонов. Изменилось только: пакет
// (`repohygiene` → `check`, экспортированные имена — `check.Xxx`).
//
// Гоняется ТОТ ЖЕ предикат, что и на дереве (`ScanVerbFormSentinel`,
// `NamedVerbFormFinding`), а не его копия «по образцу»: копия разошлась бы с
// оригиналом молча — и разошлась бы именно там, где расхождение не видно,
// потому что на сегодняшнем входе обе отвечают одинаково.
//
// ПРОГОНОВ ТРИ, и третий обязателен: инъекция, роняющая всё сразу, не отличает
// живой контроль от мёртвого.
//
//	контроль        сентинел возвращается, проб нет            → молчит
//	инъекция нового сентинел НЕ возвращается, проб нет         → находка, 6 имён
//	инъекция старого сентинел НЕ возвращается, но пробы ЕСТЬ   → молчит
package check_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// sentinelReturnedSrc — источник, в котором сентинел ВОЗВРАЩАЕТСЯ. Форма
// взята у продукта: составной литерал с полем `kind` внутри `return`.
const sentinelReturnedSrc = `package manifest

type linkFault struct {
	kind   error
	detail string
}

var ErrRoleRuleVerbsRetired = errorsNew("verbs is not a form of a role right anymore")

func refuseRuleVerbs() error {
	return linkFault{
		kind:   ErrRoleRuleVerbsRetired,
		detail: "ключ ` + "`verbs`" + ` снят",
	}
}
`

// sentinelOnlyMentionedSrc — ЗАКОННЫЙ БЛИЗНЕЦ распознавателя: то же имя стоит в
// комментарии, в строковом литерале и в объявлении — и НЕ возвращается ни разу.
//
// Без этой стороны гейт судил бы вхождение имени и молчал бы на мёртвом
// сентинеле, объявленном и никем не возвращаемом, — то есть ровно на состоянии,
// ради которого он заведён.
const sentinelOnlyMentionedSrc = `package manifest

// ErrRoleRuleVerbsRetired — правило роли записано снятым ключом ` + "`verbs`" + `.
var ErrRoleRuleVerbsRetired = errorsNew("manifest: verbs retired")

type linkFault struct {
	kind   error
	detail string
}

func refuseRuleVerbs() error {
	// Прежде здесь возвращался ErrRoleRuleVerbsRetired.
	_ = "ErrRoleRuleVerbsRetired"
	return linkFault{
		kind:   ErrSomethingElse,
		detail: "ErrRoleRuleVerbsRetired",
	}
}
`

// TestVerbFormSentinelIsJudgedByReturnNotByMention — распознаватель, обе стороны.
func TestVerbFormSentinelIsJudgedByReturnNotByMention(t *testing.T) {
	t.Parallel()
	returned, err := check.ScanVerbFormSentinel("returned.go", []byte(sentinelReturnedSrc))
	if err != nil {
		t.Fatalf("разбор источника с возвратом: %v", err)
	}
	if returned.SentinelReturns != 1 {
		t.Errorf("возвратов %d, ожидался 1 — распознаватель не видит формы, которой "+
			"сентинел возвращается в продукте", returned.SentinelReturns)
	}
	if returned.CompositeLits == 0 || returned.Idents == 0 {
		t.Errorf("перепись разбора пуста (литералов %d, идентификаторов %d) — «возвратов N» "+
			"получено даром", returned.CompositeLits, returned.Idents)
	}

	mentioned, err := check.ScanVerbFormSentinel("mentioned.go", []byte(sentinelOnlyMentionedSrc))
	if err != nil {
		t.Fatalf("разбор источника с упоминаниями: %v", err)
	}
	if mentioned.SentinelReturns != 0 {
		t.Errorf("возвратов %d, ожидалось 0 — имя в комментарии, строке и объявлении "+
			"зачтено за возврат, и гейт краснел бы на собственном объяснении",
			mentioned.SentinelReturns)
	}
	if mentioned.CompositeLits == 0 {
		t.Error("законный близнец прочитан вхолостую: составных литералов ноль")
	}
}

// probeNamesWithAllSix — перечень имён, в котором ЕСТЬ проба каждого из шести
// сценариев. Строится из самого закрытого перечня: выписанный руками разошёлся
// бы с ним при добавлении сценария.
func probeNamesWithAllSix() []string {
	out := []string{"TestMODRL05EmptyClassOnANamedResourceIsRefused"}
	for _, s := range check.NamedVerbScenarios {
		out = append(out, check.ScenarioProbeName(s)+"HasItsProbe")
	}
	sort.Strings(out)
	return out
}

// TestNamedVerbFormExpiryGateFallsAndStaysSilentOnItsLegalTwins — ТРИ ПРОГОНА.
func TestNamedVerbFormExpiryGateFallsAndStaysSilentOnItsLegalTwins(t *testing.T) {
	t.Parallel()
	// Сегодняшний перечень проб дерева: пятого и двадцать второго сценариев — да,
	// шести отсроченных — нет.
	todayProbes := []string{
		"TestMODRL05EmptyClassOnANamedResourceIsRefused",
		"TestMODRL05aNonEmptyClassIsSilent",
		"TestMODRL22DeclaredClassMustSatisfyTheGate",
		"TestMODRL22aFixedClassIsSilent",
	}

	t.Run("контроль: сентинел возвращается, проб нет — молчит", func(t *testing.T) {
		if got := check.NamedVerbFormFinding(1, todayProbes); len(got) != 0 {
			t.Fatalf("гейт краснеет на ЗАКОННОЙ отсрочке: %v — форма отвергается, "+
				"проверять полноту не по чему", got)
		}
	})

	t.Run("инъекция нового: сентинел не возвращается, проб нет — находка", func(t *testing.T) {
		got := check.NamedVerbFormFinding(0, todayProbes)
		if len(got) != len(check.NamedVerbScenarios) {
			t.Fatalf("находок %d %v, ожидалось %d — форма вернулась БЕЗ проверки полноты, "+
				"и это обязано быть названо поимённо",
				len(got), got, len(check.NamedVerbScenarios))
		}
		for _, want := range check.NamedVerbScenarios {
			found := false
			for _, g := range got {
				if g == want {
					found = true
				}
			}
			if !found {
				t.Errorf("сценарий %q не назван находкой %v — читатель не узнает, "+
					"какой пробы недостаёт", want, got)
			}
		}
	})

	t.Run("инъекция старого: сентинел не возвращается, но пробы ЕСТЬ — молчит", func(t *testing.T) {
		if got := check.NamedVerbFormFinding(0, probeNamesWithAllSix()); len(got) != 0 {
			t.Fatalf("гейт краснеет на состоянии, которого приёмка и требует (форма "+
				"вернулась ВМЕСТЕ с проверкой): %v", got)
		}
	})

	t.Run("частичная посадка названа поимённо, а не скопом", func(t *testing.T) {
		half := append([]string{}, todayProbes...)
		half = append(half, check.ScenarioProbeName("04"), check.ScenarioProbeName("04a"))
		got := check.NamedVerbFormFinding(0, half)
		if len(got) != 4 {
			t.Fatalf("находок %d %v, ожидалось 4 — гейт не различает частичную посадку "+
				"и требует всё или ничего", len(got), got)
		}
		if strings.Join(got, ",") != "18,18a,19,19a" {
			t.Errorf("названы %v, ожидались 18,18a,19,19a — гейт зачёл посаженные "+
				"пробы не тем сценариям", got)
		}
	})

	t.Run("`04` не зачитывается пробой `04a` — префикс не есть имя", func(t *testing.T) {
		only04a := []string{check.ScenarioProbeName("04a") + "IsSilent"}
		got := check.MissingScenarioProbes(only04a)
		found04 := false
		for _, g := range got {
			if g == "04" {
				found04 = true
			}
		}
		if !found04 {
			t.Fatalf("сценарий 04 зачтён пробой 04a (%v) — одна проба закрыла бы два "+
				"сценария, и второй остался бы без проверки молча", got)
		}
	})
}
