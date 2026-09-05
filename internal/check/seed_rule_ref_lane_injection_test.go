// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// seed_rule_ref_lane_injection_test.go — доказательство, что гейт полосы досева
// проекции сегментов СПОСОБЕН упасть, и что он молчит на законном близнеце.
//
// Инъекция идёт настоящим входом гейта — исходником Go, который он и разбирает,
// — а не подделкой его результата. Обе стороны названы по каждой оси: дефект
// обязан находиться, законный близнец обязан молчать.
//
// # Почему близнец здесь — КОММЕНТАРИЙ, а не другой файл
//
// Имя `ReplaceRuleRefs` встречается в этом дереве в комментариях, в приёмках и в
// именах дублёров десятками. Гейт, написанный подстрокой, зеленел бы на
// СОБСТВЕННОМ объяснении: абзац, рассказывающий, что досев обязан звать
// писателя, содержит его имя дословно. Поэтому близнец — исходник, где имя есть
// в комментарии и в строковом литерале, а вызова нет: гейт обязан назвать это
// находкой, а не молчанием.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// srcWriterCalled — досев зовёт писателя: узел вызова есть.
const srcWriterCalled = `package seed

func ReseedSystemRoleRuleRefs(repo R, refs []int) error {
	return repo.RolesW().ReplaceRuleRefs(ctx, id, refs)
}
`

// srcWriterOnlyMentioned — ЗАКОННЫЙ БЛИЗНЕЦ наоборот: имя писателя есть в
// комментарии и в строке, вызова нет. Ровно та форма, на которой проверка по
// подстроке зеленела бы при неработающем досеве.
const srcWriterOnlyMentioned = `package seed

// ReplaceRuleRefs — писатель проекции объявленных сегментов. Досев обязан звать
// именно его, а не свой SQL.
func ReseedSystemRoleRuleRefs(repo R) error {
	return errors.New("ReplaceRuleRefs не провязан")
}
`

// srcEntryPointDeclared — точка входа объявлена экспортированной функцией пакета.
const srcEntryPointDeclared = `package seed

func ReseedSystemRoleRuleRefs(repo R) error { return nil }
`

// srcEntryPointUnexportedAndMethod — близнец оси 2: имя несёт признак, но это
// НЕ экспортированная функция пакета. Точкой входа ни то, ни другое не является.
const srcEntryPointUnexportedAndMethod = `package seed

func reseedSystemRoleRuleRefs(repo R) error { return nil }

type helper struct{}

func (h helper) ReseedSystemRoleRuleRefs(repo R) error { return nil }
`

// srcRootCallsTheLane — композиционный корень зовёт полосу.
const srcRootCallsTheLane = `package main

func boot() error {
	_, err := seed.ReseedSystemRoleRuleRefs(ctx, repo, pool, obs)
	return err
}
`

// srcRootCallsOnlyTheNeighbour — близнец оси 2: корень зовёт СОСЕДНЮЮ полосу и
// лишь упоминает нашу в комментарии. Полоса, которую никто не зовёт, на старте
// не исполняется.
const srcRootCallsOnlyTheNeighbour = `package main

func boot() error {
	// Рядом обязана идти ReseedSystemRoleRuleRefs — но её тут нет.
	_, err := seed.ReseedSystemRoleVerbs(ctx, repo, pool, facts, obs)
	return err
}
`

// TestRuleRefLaneGateFindsTheDefect — ось 1 в обе стороны.
func TestRuleRefLaneGateFindsTheDefect(t *testing.T) {
	t.Run("вызова нет — находка", func(t *testing.T) {
		sites := callSitesOf(t,
			map[string]string{"seed/reseed.go": srcWriterOnlyMentioned}, ruleRefWriterSelector)
		require.Empty(t, sites,
			"имя в комментарии и в строке принято за вызов — гейт судит слово, а не узел разбора")
	})

	t.Run("вызов есть — молчание", func(t *testing.T) {
		sites := callSitesOf(t,
			map[string]string{"seed/reseed.go": srcWriterCalled}, ruleRefWriterSelector)
		require.Len(t, sites, 1, "настоящий вызов писателя не опознан")
	})
}

// TestRuleRefLaneGateNamesTheEntryPoint — ось 2, часть «что считается точкой
// входа».
func TestRuleRefLaneGateNamesTheEntryPoint(t *testing.T) {
	t.Run("экспортированная функция пакета — точка входа", func(t *testing.T) {
		names := exportedFuncsMarked(t,
			map[string]string{"seed/reseed.go": srcEntryPointDeclared}, ruleRefEntryPointMark)
		require.Equal(t, []string{"ReseedSystemRoleRuleRefs"}, names)
	})

	t.Run("неэкспортированная и метод — НЕ точки входа", func(t *testing.T) {
		names := exportedFuncsMarked(t,
			map[string]string{"seed/reseed.go": srcEntryPointUnexportedAndMethod}, ruleRefEntryPointMark)
		require.Empty(t, names,
			"метод либо неэкспортированная функция приняты за точку входа полосы: "+
				"корень позвать их не может, и ось замолчала бы при неработающем досеве")
	})
}

// TestRuleRefLaneGateSeesWhoCallsTheLane — ось 2 в обе стороны.
func TestRuleRefLaneGateSeesWhoCallsTheLane(t *testing.T) {
	const entryPoint = "ReseedSystemRoleRuleRefs"

	t.Run("корень зовёт — молчание", func(t *testing.T) {
		sites := callSitesOf(t,
			map[string]string{"cmd/serve.go": srcRootCallsTheLane}, entryPoint)
		require.Len(t, sites, 1, "настоящий вызов полосы из корня не опознан")
	})

	t.Run("корень зовёт соседнюю полосу — находка", func(t *testing.T) {
		sites := callSitesOf(t,
			map[string]string{"cmd/serve.go": srcRootCallsOnlyTheNeighbour}, entryPoint)
		require.Empty(t, sites,
			"вызов СОСЕДНЕЙ полосы принят за вызов нашей: гейт зеленел бы, "+
				"пока проекция сегментов не пересчитывается вовсе")
	})
}

// TestRuleRefLaneGateRefusesAnEmptyWalk — пустой обход обязан быть отличим от
// «нарушений нет».
//
// Утверждается достижимость самого состояния: каталог, которого в индексе нет,
// даёт пустой набор источников, а на нём обе оси гейта останавливаются
// требованием `NotZero`. Без этого «ноль находок» означало бы «ноль
// прочитанного».
func TestRuleRefLaneGateRefusesAnEmptyWalk(t *testing.T) {
	root := monorepoRoot(t)

	absent := goSourcesOfDir(t, root, filepath.Join(seedPackageDir, "no-such-subdir"))
	require.Empty(t, absent,
		"каталог, которого в индексе нет, дал непустой набор источников — "+
			"обход читает не индекс")

	present := goSourcesOfDir(t, root, seedPackageDir)
	require.NotEmpty(t, present,
		"положительный контроль: настоящий каталог досева обязан читаться, "+
			"иначе пустота выше ничего не доказывает")
	t.Logf("перепись инъекции: источников в настоящем каталоге %d · в несуществующем %d",
		len(present), len(absent))

	// Сверх того: гейт судит НЕПРОБНЫЕ файлы. Пробный сосед в набор не попадает,
	// иначе вызов из пробы сходил бы за провязку продукта.
	for rel := range present {
		require.Falsef(t, strings.HasSuffix(rel, "_test.go"),
			"пробный файл %s попал в набор — вызов из пробы сойдёт за провязку продукта", rel)
	}
}
