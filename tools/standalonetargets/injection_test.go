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
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, "нечего собирать\n", nil })
	require.NoError(t, err)
	require.Len(t, findings, 1, "отказавшая цель не названа находкой")
	require.Empty(t, unmet, "отказ без метки зачтён в третий исход — находка стала бы невидимой")
	require.Contains(t, findings[0].String(), "плохая", "находка не назвала цель")
	require.Contains(t, findings[0].String(), "нечего собирать",
		"находка не несёт текст отказа — имя посылает читателя искать причину, текст её называет")
}

// TestRun_PassingUnmarkedTargetIsSilent — законный близнец. Отличается ровно
// одним фактом: код возврата цели.
func TestRun_PassingUnmarkedTargetIsSilent(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "хорошая", Desc: "работает"}}
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 0, "готово\n", nil })
	require.NoError(t, err)
	require.Empty(t, findings, "гейт краснеет на цели, отработавшей кодом 0")
	require.Empty(t, unmet, "цель, отработавшая кодом 0, зачтена в третий исход")
}

// TestRun_LauncherFailureIsNotAFinding — отказ ЗАПУСКА представим отдельно.
//
// «make не нашёлся» и «цель отказала» — разные вердикты. Схлопни их в один, и
// отсутствие инструмента отчитывалось бы как дефект продукта.
func TestRun_LauncherFailureIsNotAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "любая", Desc: "неважно"}}
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 0, "", os.ErrNotExist })
	require.ErrorIs(t, err, standalonetargets.ErrPostureNotBuilt,
		"отказ запуска выдан за находку")
	require.Empty(t, findings, "отказ запуска подмешан к находкам")
	require.Empty(t, unmet, "отказ запуска подмешан к третьему исходу")
}

// --- Инъекция в РАЗВЕДЕНИЕ ТРЁХ ИСХОДОВ (задача #52) -------------------------
//
// До этой пары гейт объявлял находкой ЛЮБОЙ ненулевой код. Рецепт при этом
// объявляет свою договорённость — «условие не создано» печатается словами, — и
// на машине без `buf` три цели контрактов читались как «цель не работает у
// арендатора», хотя цель сказала прямо: инструмента нет.
//
// Каждая пара ниже меняет против своего близнеца РОВНО ОДИН факт — текст,
// который печатает цель. Код возврата у всех один и тот же (2), и это не
// небрежность фикстуры, а воспроизведение того, чем различить нечего: `make`
// схлопывает любой отказ рецепта в собственную двойку.

// TestRun_TargetNamingItsUnmetPremiseIsNotAFinding — цель НАЗВАЛА предпосылку.
func TestRun_TargetNamingItsUnmetPremiseIsNotAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "proto-lint", Desc: "buf lint по контрактам службы"}}
	out := "УСЛОВИЕ НЕ СОЗДАНО: цель proto-lint зовёт buf, а его в PATH нет.\n" +
		"Поставь buf и повтори.\n"
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, out, nil })
	require.NoError(t, err)
	require.Empty(t, findings,
		"«инструмента нет» подано вердиктом о продукте: у всякого, кто склонирует без buf, "+
			"гейт объявлял бы три находки о работающих целях")
	require.Len(t, unmet, 1, "третий исход не назван своим числом")
	require.Contains(t, unmet[0].String(), "proto-lint", "третий исход не назвал цель")
	require.Contains(t, unmet[0].String(), "вердикта о ней НЕТ",
		"третий исход не сказан словами — читатель зачтёт его в успех")
}

// TestRun_SameTargetWithoutTheMarkIsAFinding — законный близнец предыдущей.
//
// Отличается РОВНО ОДНИМ фактом: цель не печатает метку. Без этой половины
// разведение исходов было бы маской — достаточно было бы кода 2, чтобы цель
// перестала проверяться где бы то ни было.
func TestRun_SameTargetWithoutTheMarkIsAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "proto-lint", Desc: "buf lint по контрактам службы"}}
	out := "buf: ошибка разбора контракта proto/kaname/cloud/iam/v1/x.proto:12\n"
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) { return 2, out, nil })
	require.NoError(t, err)
	require.Empty(t, unmet, "отказ БЕЗ метки зачтён в третий исход — дефект стал бы невидимым")
	require.Len(t, findings, 1, "настоящий отказ цели перестал быть находкой")
}

// TestRun_MarkInProseIsStillAFinding — НЕСУЩАЯ ось: слова в прозе меткой не
// становятся.
//
// Слова «условие не создано» встречаются в тексте, который их же объясняет:
// в комментарии рецепта (его эхо начинается со знака комментария), в разборе
// класса, в самой находке. Распознаватель, ищущий вхождение подстрокой, зеленел
// бы на собственном объяснении — то есть цель, честно отказавшая, выпадала бы
// из наблюдения, и заметить это было бы нечем: третий исход выглядит так же
// спокойно, как зелёный.
func TestRun_MarkInProseIsStillAFinding(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "audit-list-filter", Desc: "списочные методы"}}
	for name, out := range map[string]string{
		"эхо комментария рецепта": "# УСЛОВИЕ НЕ СОЗДАНО — так отказывают цели, судящие дерево\n" +
			"audit-list-filter: два метода не сужают выдачу\n",
		"упоминание в середине строки": "разбор: это не «УСЛОВИЕ НЕ СОЗДАНО», а настоящий отказ\n",
		"строчное написание":           "это условие не создано, наверное\n",
	} {
		findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
			func(_, _ string) (int, string, error) { return 2, out, nil })
		require.NoError(t, err)
		require.Emptyf(t, unmet,
			"%s: слова в прозе зачтены за метку — гейт зеленеет оттого, что кто-то их написал", name)
		require.Lenf(t, findings, 1, "%s: находка потеряна", name)
	}
}

// TestRun_MarkIndentedByTheRecipeIsStillTheMark — законный близнец прозы.
//
// Рецепт вправе отступать текст отказа, и отступ метки не отменяет. Отличается
// от прозы выше ровно одним фактом: метка стоит ПЕРВОЙ на своей строке.
func TestRun_MarkIndentedByTheRecipeIsStillTheMark(t *testing.T) {
	targets := []standalonetargets.Target{{Name: "model-canon-check", Desc: "канон модели [не важно]"}}
	findings, unmet, err := standalonetargets.RunTargets("посадка", targets,
		func(_, _ string) (int, string, error) {
			return 2, "сверка канона:\n    УСЛОВИЕ НЕ СОЗДАНО: манифестов соседних модулей рядом нет\n", nil
		})
	require.NoError(t, err)
	require.Empty(t, findings, "отступ перед меткой отменил третий исход")
	require.Len(t, unmet, 1, "метка с отступом не прочитана")
}

// TestCensus_NamesAllThreeOutcomes — перепись печатает ТРИ величины.
//
// «Ноль в ней обязан быть отличим от ненайденного»: без третьего числа
// «судимых 14 · находок 0» читается как вердикт о четырнадцати целях там, где о
// трёх из них вердикта нет вовсе.
func TestCensus_NamesAllThreeOutcomes(t *testing.T) {
	c := standalonetargets.Census{Declared: 24, Monorepo: 5, Waived: 5, Judged: 14,
		Findings: 0, Unmet: 3, Posture: "/tmp/клон"}
	got := c.String()
	require.Contains(t, got, "судимых 14")
	require.Contains(t, got, "находок 0")
	require.Contains(t, got, "условие не создано 3",
		"третья величина не печатается — зелёный прогон неотличим от прогона, "+
			"который о части целей ничего не спросил")
}
