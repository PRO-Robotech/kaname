// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// nested_rule_test.go — вложенное правило роли (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2, отпечаток f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6).
//
// Здесь — домен: проекция правила в селекторы материализации (ось вложенности
// едет вместе с отбором правила-владельца), отпечаток, кодек хранимой формы,
// компиляция прав, ворота покрытия цели (ND-12), «только чтение» и ворота
// класса (ND-05, M1 круга 1: прежде оба читали только верхний уровень).
//
// Каждое «нет» стоит в паре с «да» на соседе, отличающемся одним фактом.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ndReader — роль `registry.reader` таблицы П1: правило над реестрами с
// вложенным правилом над репозиториями.
func ndReader() domain.Rules {
	return domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
		Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}},
	}}
}

// ndViewer — близнец без вложенного правила (`registry.viewer`).
func ndViewer() domain.Rules {
	return domain.Rules{{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}}}
}

func ndSelectorFor(t *testing.T, sels []domain.RuleSelector, objectType string) domain.RuleSelector {
	t.Helper()
	for _, s := range sels {
		if slices.Contains(s.ObjectTypes, objectType) {
			return s
		}
	}
	t.Fatalf("селектора над %s нет среди %d селекторов: %+v", objectType, len(sels), sels)
	return domain.RuleSelector{}
}

// ND-02: вложенное правило проецируется в СВОЙ селектор над своим типом, и
// селектор несёт контейнер — тип правила-владельца и его отбор.
func TestNestedRule_ND02_SelectorCarriesTheContainerOfItsOwner(t *testing.T) {
	sels := ndReader().MaterializingSelectors()
	if len(sels) != 2 {
		t.Fatalf("селекторов %d, ждали 2 (владелец и вложенное): %+v", len(sels), sels)
	}
	owner := ndSelectorFor(t, sels, "registry.registries")
	if owner.Container != nil {
		t.Errorf("селектор правила верхнего уровня несёт контейнер %+v: верхний уровень сравнивает точно", owner.Container)
	}
	nested := ndSelectorFor(t, sels, "registry.repositories")
	if nested.Container == nil {
		t.Fatalf("селектор вложенного правила без контейнера: ось вложенности потеряна (%+v)", nested)
	}
	if nested.Container.Type != "registry.registries" || nested.Container.Arm != domain.ArmAnchor {
		t.Errorf("контейнер вложенного селектора %+v, ждали тип registry.registries и якорь", *nested.Container)
	}
	if !slices.Equal(nested.Verbs, []string{"get", "list"}) || nested.Arm != domain.ArmAnchor {
		t.Errorf("вложенный селектор: глаголы %v, ветвь %v; ждали [get list] и якорь", nested.Verbs, nested.Arm)
	}
	if nested.RuleFP == owner.RuleFP {
		t.Errorf("у вложенного и владельца один ключ %s: члены материализации слиплись бы", owner.RuleFP)
	}

	// Близнец: роль без вложенного — ровно один селектор, без контейнера.
	if got := ndViewer().MaterializingSelectors(); len(got) != 1 || got[0].Container != nil {
		t.Errorf("близнец без children: %+v, ждали один селектор без контейнера", got)
	}
}

// ND-08 «И»: отбор правила-владельца (имена, метки) едет в контейнер
// вложенного селектора — выдача «вся область» выбирает только те контейнеры,
// которые проходит ветвь владельца.
func TestNestedRule_ND08_OwnerArmTravelsWithTheNestedSelector(t *testing.T) {
	names := domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
		ResourceNames: []string{"reg00000000000000001"},
		Children:      []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}},
	}}
	n := ndSelectorFor(t, names.MaterializingSelectors(), "registry.repositories")
	if n.Container == nil || n.Container.Arm != domain.ArmNames ||
		!slices.Equal(n.Container.ResourceNames, []string{"reg00000000000000001"}) {
		t.Errorf("ветвь имён владельца не доехала до вложенного селектора: %+v", n.Container)
	}
	if n.Arm != domain.ArmAnchor || len(n.ResourceNames) != 0 {
		t.Errorf("имена владельца попали в отбор САМОГО вложенного правила: ветвь %v, имена %v", n.Arm, n.ResourceNames)
	}

	labels := domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "a"},
		Children:    []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}},
	}}
	l := ndSelectorFor(t, labels.MaterializingSelectors(), "registry.repositories")
	if l.Container == nil || l.Container.Arm != domain.ArmLabels || l.Container.MatchLabels["team"] != "a" {
		t.Errorf("ветвь меток владельца не доехала до вложенного селектора: %+v", l.Container)
	}
}

// Отпечаток правила без вложенных НЕ меняется: на нём стоят хранимые члены
// материализации (ND-07 (а) — роль прежней формы смысла не меняет). Правило с
// вложенными отличается от себя без них.
func TestNestedRule_ND07_FingerprintOfAPlainRuleIsUnchanged(t *testing.T) {
	plain := ndViewer()[0]
	withEmpty := plain
	withEmpty.Children = []domain.Rule{}
	if plain.Fingerprint() != withEmpty.Fingerprint() {
		t.Errorf("пустой перечень вложенных сдвинул отпечаток: %s против %s", withEmpty.Fingerprint(), plain.Fingerprint())
	}
	if got := ndReader()[0].Fingerprint(); got == plain.Fingerprint() {
		t.Errorf("правило с вложенными и без них дают один отпечаток %s: члены и селекторы слиплись бы", got)
	}
}

// Вложенное правило под РАЗНЫМИ владельцами — разные ключи селектора: первичный
// ключ селекторов роли — (роль, отпечаток).
func TestNestedRule_ND02_SameNestedUnderTwoOwnersIsTwoSelectors(t *testing.T) {
	child := []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}
	rules := domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, Children: child},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
			ResourceNames: []string{"reg00000000000000001"}, Children: child},
	}
	seen := map[string]bool{}
	for _, s := range rules.MaterializingSelectors() {
		if seen[s.RuleFP] {
			t.Fatalf("ключ селектора %s повторился: вложенные под разными владельцами слиплись", s.RuleFP)
		}
		seen[s.RuleFP] = true
	}
	if len(seen) != 4 {
		t.Errorf("селекторов %d, ждали 4", len(seen))
	}
}

// Хранимая форма несёт вложенные правила; модуль вложенного не пишется — он
// берётся у владельца.
func TestNestedRule_ND02_CodecKeepsChildrenWithoutModule(t *testing.T) {
	raw, err := domain.EncodeRules(ndReader())
	if err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	var shape []map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("разбор хранимой формы: %v", err)
	}
	ch, ok := shape[0]["children"].([]any)
	if !ok || len(ch) != 1 {
		t.Fatalf("хранимая форма без children: %s", raw)
	}
	if _, has := ch[0].(map[string]any)["module"]; has {
		t.Errorf("вложенное правило в хранимой форме несёт module: %s", raw)
	}
	back, err := domain.DecodeRules(raw)
	if err != nil {
		t.Fatalf("декодирование: %v", err)
	}
	if len(back) != 1 || len(back[0].Children) != 1 ||
		!slices.Equal(back[0].Children[0].Resources, []string{"repositories"}) {
		t.Errorf("вложенные правила не пережили кодек: %+v", back)
	}
	plain, err := domain.EncodeRules(ndViewer())
	if err != nil {
		t.Fatalf("кодирование близнеца: %v", err)
	}
	if strings.Contains(string(plain), "children") {
		t.Errorf("правило без вложенных пишется с ключом children: %s", plain)
	}
}

// Р4: скомпилированные права вложенных правил не несут — строка
// `registry.repositories.*.get` обещала бы чтение всех репозиториев области.
func TestNestedRule_ND04_CompiledPermissionsCarryNoNestedRule(t *testing.T) {
	perms, err := domain.CompileRules(ndReader())
	if err != nil {
		t.Fatalf("компиляция: %v", err)
	}
	for _, p := range perms {
		if strings.HasPrefix(string(p), "registry.repositories.") {
			t.Errorf("скомпилированные права несут вложенное правило: %s", p)
		}
	}
	if !slices.Contains(perms, domain.Permission("registry.registries.*.get")) {
		t.Errorf("правило-владелец пропало из прав: %v", perms)
	}
}

// ND-12: ворота покрытия цели читают ТОЛЬКО верхний уровень — вложенное правило
// действует на потомков названного контейнера, а не на названный объект своего
// типа.
func TestNestedRule_ND12_TargetCoverageReadsTheTopLevelOnly(t *testing.T) {
	if ndReader().CoversType("registry.repositories") {
		t.Errorf("тип, покрытый только вложенным правилом, засчитан покрытым целью")
	}
	if !ndReader().CoversType("registry.registries") {
		t.Errorf("близнец: тип правила-владельца не засчитан покрытым")
	}
}

// Объявленные сегменты роли считают и вложенные (ND-02 «И»: declaredSegments = 4).
func TestNestedRule_ND02_DeclaredSegmentsCountNestedRules(t *testing.T) {
	if got := len(domain.RuleRefsOf(ndReader())); got != 4 {
		t.Errorf("объявленных сегментов %d, ждали 4 (реестры и репозитории × get, list)", got)
	}
	states := domain.RuleStatesOf(ndReader(), nil, nil)
	if len(states) != 1 || len(states[0].Children) != 1 || states[0].Children[0].Segments != 2 {
		t.Errorf("состояние правила не несёт вложенного: %+v", states)
	}
}

// M1: «только чтение» читает вложенные правила — пишущий глагол во вложенном
// закрывает роль для класса (ворота SC-21).
func TestNestedRule_ND05_ReadsOnlyReadsNestedRules(t *testing.T) {
	writing := ndReader()
	writing[0].Children[0].Verbs = []string{"get", "update"}
	if (domain.Role{Rules: writing}).GrantsReadsOnly() {
		t.Errorf("роль с пишущим глаголом во вложенном правиле признана только читающей")
	}
	if !(domain.Role{Rules: ndReader()}).GrantsReadsOnly() {
		t.Errorf("близнец: роль только с get/list признана пишущей")
	}
}

// ndContainers — что живой каталог говорит о контейнерах П1 и П3.
func ndContainers(registriesDeclared bool) map[string]domain.PublicReadContainer {
	return map[string]domain.PublicReadContainer{
		"registry.registries": {Type: "registry.registries", Declared: registriesDeclared,
			ChildTypes: []string{"registry.repositories"}},
		"probemod.boxes": {Type: "probemod.boxes", Declared: true, ChildTypes: []string{"probemod.items"}},
	}
}

// ND-05: ворота класса судят каждое вложенное правило роли — три условия Р5.
func TestNestedRule_ND05_ClassGateJudgesEveryNestedRule(t *testing.T) {
	notWhole := "Role %s nests a rule over registry.repositories that does not read it whole " +
		"(get and list, without resourceNames or matchLabels); a system class reads children only whole"

	getOnly := ndReader()
	getOnly[0].Children[0].Verbs = []string{"get"}
	named := ndReader()
	named[0].Children[0].ResourceNames = []string{"app"}
	probe := domain.Rules{{
		Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
		Children: []domain.Rule{{Resources: []string{"tags"}, Verbs: []string{"get", "list"}}},
	}}

	for name, c := range map[string]struct {
		role     domain.RoleID
		rules    domain.Rules
		declared bool
		want     string
	}{
		"(а) вложенное только get": {"rolc36eeca826b9a8603", getOnly, true,
			strings.ReplaceAll(notWhole, "%s", "rolc36eeca826b9a8603")},
		"(б) вложенное с именами": {"rolc8f851eb7a5da3d9f", named, true,
			strings.ReplaceAll(notWhole, "%s", "rolc8f851eb7a5da3d9f")},
		"(в) контейнер не объявлен": {"rolb812261cfaa239694", ndReader(), false,
			"Type registry.registries does not pass public read to its children; role rolb812261cfaa239694 covers its child type registry.repositories"},
		"(г) внук": {"rol533113283eb982de5", probe, true,
			"Type probemod.boxes passes public read to its direct children only; role rol533113283eb982de5 nests a rule over probemod.tags"},
	} {
		t.Run(name, func(t *testing.T) {
			got, refused := domain.ClassNestedRuleRefusal(c.role, c.rules, ndContainers(c.declared))
			if !refused {
				t.Fatalf("ворота класса пропустили роль: ждали отказ %q", c.want)
			}
			if got != c.want {
				t.Errorf("текст отказа\n получен %q\n ждали   %q", got, c.want)
			}
		})
	}

	// Близнец: вложенное [get, list] без сужения над прямым ребёнком объявленного
	// контейнера — принято. И роль без вложенных воротам безразлична.
	if got, refused := domain.ClassNestedRuleRefusal("rolb1325b011aa17211d", ndReader(), ndContainers(true)); refused {
		t.Errorf("близнец ND-03 отвергнут: %q", got)
	}
	if got, refused := domain.ClassNestedRuleRefusal("rol2375080206e7e5e32", ndViewer(), ndContainers(false)); refused {
		t.Errorf("роль без вложенных отвергнута воротами вложенных: %q", got)
	}
}

// M1: ребёнок контейнера, чтение которого роль открывает целиком, ищется и во
// вложенных правилах (ND-05 (в)); правило верхнего уровня над ребёнком
// по-прежнему засчитывается (SC-65 соседа не меняет исхода).
func TestNestedRule_ND05_CoveredChildReadsNestedRules(t *testing.T) {
	c := ndContainers(false)["registry.registries"]
	if child, ok := c.CoveredChild(ndReader()); !ok || child != "registry.repositories" {
		t.Errorf("вложенное правило над ребёнком не найдено: %q %v", child, ok)
	}
	if child, ok := c.CoveredChild(ndViewer()); ok {
		t.Errorf("близнец без children дал покрытого ребёнка %q", child)
	}
	flat := domain.Rules{{Module: "registry", Resources: []string{"registries", "repositories"}, Verbs: []string{"get", "list"}}}
	if child, ok := c.CoveredChild(flat); !ok || child != "registry.repositories" {
		t.Errorf("правило верхнего уровня над ребёнком перестало засчитываться (SC-65): %q %v", child, ok)
	}
}

// Форма вложенности судится и доменом — второй стеной за загрузчиком: роль,
// пришедшая не из манифеста, не проходит с вложенностью, которую загрузчик
// отверг бы.
func TestNestedRule_ND04_DomainRejectsAMalformedNesting(t *testing.T) {
	mods := domain.ModuleSetOf("registry")
	base := func() domain.Rules { return ndReader() }
	cases := map[string]func(domain.Rules) domain.Rules{
		"владелец над двумя ресурсами": func(r domain.Rules) domain.Rules {
			r[0].Resources = []string{"registries", "repositories"}
			return r
		},
		"владелец над *": func(r domain.Rules) domain.Rules { r[0].Resources = []string{"*"}; return r },
		"вложенное с модулем": func(r domain.Rules) domain.Rules {
			r[0].Children[0].Module = "registry"
			return r
		},
		"вложенное со своими children": func(r domain.Rules) domain.Rules {
			r[0].Children[0].Children = []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}}
			return r
		},
		"пустой перечень": func(r domain.Rules) domain.Rules { r[0].Children = []domain.Rule{}; return r },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := mutate(base()).Validate(domain.PolicyOfRole(true, "registry"), mods); err == nil {
				t.Errorf("домен принял негодную вложенность")
			}
		})
	}
	if err := base().Validate(domain.PolicyOfRole(true, "registry"), mods); err != nil {
		t.Errorf("близнец registry.reader отвергнут доменом: %v", err)
	}
}
