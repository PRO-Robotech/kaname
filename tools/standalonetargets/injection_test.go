// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets_test

// injection_test.go — доказательство, что гейт СПОСОБЕН упасть и СПОСОБЕН
// смолчать. Каждая пара меняет ровно один факт.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/standalonetargets"
)

const recipe = `
## build — бинарь службы в bin/
## build-migrator — отдельный бинарь мигратора в bin/
## test — все пробы службы [монорепо]
## docker — образ службы (тег kaname:dev)
`

// TestParse_ReadsTheSameLinesHelpPrints — положительный контроль разбора.
func TestParse_ReadsTheSameLinesHelpPrints(t *testing.T) {
	got := standalonetargets.ParseTargets([]byte(recipe))
	require.Len(t, got, 4, "перечень выведен не из тех строк, которые печатает help")
	require.Equal(t, "build", got[0].Name)
	require.False(t, got[0].Monorepo)
	require.True(t, got[2].Monorepo, "пометка [монорепо] не прочитана")
}

// TestParse_HyphenInTheNameIsNotASeparator — инъекция в распознаватель.
//
// Имена целей содержат дефис (`build-migrator`, `model-canon-check`), а
// разделителем в строке объявления служит ТИРЕ. Образец, принявший дефис за
// разделитель, обрезал бы имя по первому дефису и судил бы цель, которой в
// рецепте нет, — то есть МОЛЧАЛ бы о настоящей. Форма, о которой распознаватель
// не знает, даёт не красное и не зелёное, а невидимость.
func TestParse_HyphenInTheNameIsNotASeparator(t *testing.T) {
	got := standalonetargets.ParseTargets([]byte(recipe))
	names := make([]string, 0, len(got))
	for _, g := range got {
		names = append(names, g.Name)
	}
	require.Contains(t, names, "build-migrator",
		"имя с дефисом не распознано целиком: %v", names)
	require.NotContains(t, names, "build-",
		"имя обрезано по дефису — гейт судил бы цель, которой в рецепте нет: %v", names)
}

// TestParse_EmptyWalkYieldsNothing — предпосылка обхода представима отдельно.
func TestParse_EmptyWalkYieldsNothing(t *testing.T) {
	require.Empty(t, standalonetargets.ParseTargets([]byte("build:\n\tgo build ./...\n")),
		"строки, не объявляющие цель, приняты за объявление")
}

// TestJudged_MarkedAndWaivedAreNotJudged — положительный близнец ведомости.
func TestJudged_MarkedAndWaivedAreNotJudged(t *testing.T) {
	judged, c := standalonetargets.Judged(
		standalonetargets.ParseTargets([]byte(recipe)),
		[]standalonetargets.Waiver{{Target: "docker", Reason: "нужен демон сборки образов"}},
	)
	require.Equal(t, 4, c.Declared)
	require.Equal(t, 1, c.Monorepo)
	require.Equal(t, 1, c.Waived)
	require.Equal(t, 2, c.Judged)
	require.Empty(t, c.StaleWaiv)
	require.Len(t, judged, 2)
}

// TestJudged_WaiverWithNoSubjectIsAFinding — инъекция: послабление пережило
// свою цель. Меняется ровно один факт против близнеца выше — имя в ведомости.
func TestJudged_WaiverWithNoSubjectIsAFinding(t *testing.T) {
	_, c := standalonetargets.Judged(
		standalonetargets.ParseTargets([]byte(recipe)),
		[]standalonetargets.Waiver{{Target: "цели-с-таким-именем-нет", Reason: "предмета нет"}},
	)
	require.Equal(t, []string{"цели-с-таким-именем-нет"}, c.StaleWaiv,
		"запись без предмета не названа — послабление досталось бы следующей цели, случайно совпавшей по имени")
}

// TestJudged_WaiverOfAMarkedTargetIsAlsoAFinding — вторая форма того же: цель
// стала помеченной, и прощать её больше незачем.
func TestJudged_WaiverOfAMarkedTargetIsAlsoAFinding(t *testing.T) {
	_, c := standalonetargets.Judged(
		standalonetargets.ParseTargets([]byte(recipe)),
		[]standalonetargets.Waiver{{Target: "test", Reason: "долгая"}},
	)
	require.Equal(t, []string{"test"}, c.StaleWaiv,
		"помеченная цель прощена ведомостью — двойное послабление, из которых одно молча лишнее")
}

// TestPremise_FixtureInsideARepositoryIsRefused — инъекция в предпосылку
// фикстуры: каталог лежит внутри репозитория.
//
// Это тот самый класс, ради которого написаны tree-root.sh (#2145) и резолв
// канона (#2159). Гейт, воспроизводящий его собственной фикстурой, судил бы
// ЧУЖОЕ дерево — и зелёным.
func TestPremise_FixtureInsideARepositoryIsRefused(t *testing.T) {
	outer := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(outer, ".git"), 0o750))
	inner := filepath.Join(outer, "a", "b")
	require.NoError(t, os.MkdirAll(inner, 0o750))

	err := standalonetargets.AssertOutsideAnyRepository(inner)
	require.Error(t, err, "фикстура внутри чужого репозитория принята — вердикт был бы о чужом дереве")
	require.ErrorIs(t, err, standalonetargets.ErrPostureNotBuilt,
		"отказ предпосылки выдан за находку: «не знаю» не выдаётся ни за «нет находок», ни за «находка»")
	require.Contains(t, err.Error(), "ожидался признак",
		"отказ не назвал предпосылку словами")
}

// TestPremise_FixtureOutsideAnyRepositoryIsSilent — законный близнец. Отличается
// от инъекции выше РОВНО ОДНИМ фактом: каталога .git над фикстурой нет.
func TestPremise_FixtureOutsideAnyRepositoryIsSilent(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "a", "b")
	require.NoError(t, os.MkdirAll(inner, 0o750))

	if err := standalonetargets.AssertOutsideAnyRepository(outer); err != nil {
		t.Skipf("проверка НЕ ИСПОЛНЯЛАСЬ: временный каталог сам лежит в репозитории (%v)", err)
	}
	require.NoError(t, standalonetargets.AssertOutsideAnyRepository(inner),
		"предпосылка отвергла каталог вне всякого репозитория — проверка отвергала бы всё подряд")
}

// TestModuleRoot_FoundByMarkerNotByDepth — корень модуля ищется маркером.
func TestModuleRoot_FoundByMarkerNotByDepth(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o600))
	deep := filepath.Join(root, "tools", "standalonetargets")
	require.NoError(t, os.MkdirAll(deep, 0o750))

	got, err := standalonetargets.ModuleRootFrom(deep)
	require.NoError(t, err)
	require.Equal(t, root, got, "корень найден не по маркеру")
}

// TestModuleRoot_NoMarkerIsNotRun — инъекция: маркера нет ни на одном уровне.
// Отличается от близнеца выше ровно одним фактом — отсутствием go.mod.
func TestModuleRoot_NoMarkerIsNotRun(t *testing.T) {
	deep := filepath.Join(t.TempDir(), "tools", "standalonetargets")
	require.NoError(t, os.MkdirAll(deep, 0o750))

	_, err := standalonetargets.ModuleRootFrom(deep)
	require.ErrorIs(t, err, standalonetargets.ErrPostureNotBuilt,
		"корень выдуман там, где маркера нет: подъём вернул бы ЧУЖОЙ каталог молча")
}

// --- Инъекция в СУЖДЕНИЕ: способность назвать отказавшую цель ----------------
//
// Половина гейта, зовущая цели, до этой пары предъявлялась только поломкой
// самого дерева: «раньше было красно, теперь зелено». Такое доказательство не
// воспроизводится и исчезает вместе с починкой. Пара ниже подаёт отказ НАРОЧНО
// и меняет против близнеца ровно один факт — код возврата цели.

// TestRun_FailingUnmarkedTargetIsAFinding — инъекция.
func TestRun_FailingUnmarkedTargetIsAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "плохая", Desc: "нарочно отказывает"}}
	findings, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, "нечего собирать\n", nil })
	require.NoError(t, err)
	require.Len(t, findings, 1, "отказавшая цель не названа находкой")
	require.Contains(t, findings[0].String(), "плохая", "находка не назвала цель")
	require.Contains(t, findings[0].String(), "нечего собирать",
		"находка не несёт текст отказа — имя посылает читателя искать причину, текст её называет")
}

// TestRun_PassingUnmarkedTargetIsSilent — законный близнец. Отличается ровно
// одним фактом: код возврата цели.
func TestRun_PassingUnmarkedTargetIsSilent(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "хорошая", Desc: "работает"}}
	findings, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 0, "готово\n", nil })
	require.NoError(t, err)
	require.Empty(t, findings, "гейт краснеет на цели, отработавшей кодом 0")
}

// TestRun_LauncherFailureIsNotAFinding — третий исход представим отдельно.
//
// «make не нашёлся» и «цель отказала» — разные вердикты. Схлопни их в один, и
// отсутствие инструмента отчитывалось бы как дефект продукта.
func TestRun_LauncherFailureIsNotAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "любая", Desc: "неважно"}}
	findings, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 0, "", os.ErrNotExist })
	require.ErrorIs(t, err, standalonetargets.ErrPostureNotBuilt,
		"отказ запуска выдан за находку")
	require.Empty(t, findings, "отказ запуска подмешан к находкам")
}
