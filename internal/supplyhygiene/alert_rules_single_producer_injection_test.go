// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_rules_single_producer_injection_test.go — доказательство того, что
// проверка единственного производителя СПОСОБНА упасть, и того, что она молчит
// на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годное дерево документации собрано один раз; каждая проба меняет РОВНО ОДНУ
// вещь. Близнецов здесь ЧЕТЫРЕ, потому что молчать проверка обязана по четырём
// разным причинам, и каждую надо доказать отдельно:
//
//	объявление на опубликованной странице — законный пересказ, он и сверяется;
//	имя тревоги в ПРОЗЕ инженерного документа — проза не срабатывает;
//	ключ `alert:` ВНЕ блока кода — вне блока это текст, а не объявление;
//	`alert:` не в позиции ключа (в комментарии блока) — объяснение не объявляет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ СИНТЕТИЧЕСКОЕ ДЕРЕВО, А НЕ НАСТОЯЩЕЕ
//
// В настоящем дереве 121 документ и 636 блоков кода. Инъекция по нему не была
// бы одно-фактной: красное могло бы прийти от чего угодно из этих шести сотен,
// а молчание — от совпадения с чужим блоком. Синтетическое несёт ровно два
// документа, и всё, что не они, — заведомо мимо.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДПОСЫЛКИ ДОКАЗАНЫ ТОЖЕ, И ЭТО НЕ ФОРМАЛЬНОСТЬ
//
// Три страха этой проверки: пустой обход, ноль прочитанных блоков и страница,
// переставшая объявлять правила. В каждом «находок ноль» означает «прочитано
// ноль», и без стража такой зелёный неотличим от чистого дерева.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// injPage — координата опубликованной страницы внутри синтетического дерева.
	injPage = "docs/content/advanced/observability.mdx"
	// injEngineering — координата инженерного документа там же.
	injEngineering = "docs/engineering/components/32-observability.md"
)

// injPageGood — годная страница: пересказывает правила, и это законно.
const injPageGood = "# Наблюдаемость\n\n" +
	"```yaml\n" +
	"- alert: SampleAuthzSlow\n" +
	"  expr: sample_authz_seconds > 0.03\n" +
	"```\n"

// injEngineeringGood — годный инженерный документ: НАЗЫВАЕТ правило прозой и
// НЕ объявляет его.
const injEngineeringGood = "## Правила тревоги\n\n" +
	"Здесь их нет: их везёт объект чарта, а пересказывает опубликованная\n" +
	"страница. Правило `SampleAuthzSlow` звонит, когда ответ о доступе медленнее\n" +
	"порога, и разбирать его надо по `failure-domains.md`.\n"

// writeInjectionTree — синтетическое дерево документации из двух документов.
func writeInjectionTree(t *testing.T, page, engineering string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range map[string]string{injPage: page, injEngineering: engineering} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}
	return root
}

// scanInjectionTree — разбор синтетического дерева теми же глазами, что и
// настоящего: функция одна, различается только корень.
func scanInjectionTree(t *testing.T, page, engineering string) ([]alertDeclaration, []alertDeclaration, alertProducerCensus) {
	t.Helper()
	legit, stray, census, err := collectAlertDeclarations(
		writeInjectionTree(t, page, engineering), injPage)
	require.NoError(t, err)
	return legit, stray, census
}

// TestAlertRulesSingleProducerInjection_SilentOnLegitimateTwins — годное дерево
// и три его законных варианта находок НЕ дают.
func TestAlertRulesSingleProducerInjection_SilentOnLegitimateTwins(t *testing.T) {
	t.Parallel()

	twins := map[string]struct{ page, engineering string }{
		"проза с именем правила": {injPageGood, injEngineeringGood},
		"ключ вне блока кода": {injPageGood, injEngineeringGood +
			"\nФрагмент, который сюда НЕ копируют: alert: SampleAuthzSlow\n"},
		"ключ в комментарии блока": {injPageGood, injEngineeringGood +
			"\n```yaml\n# alert: SampleAuthzSlow — так писать не надо\nexpr: 1\n```\n"},
		"второй блок страницы": {injPageGood + "\n```yaml\n- alert: SampleLROBacklog\n  expr: 1\n```\n",
			injEngineeringGood},
	}

	for name, tw := range twins {
		t.Run(name, func(t *testing.T) {
			legit, stray, census := scanInjectionTree(t, tw.page, tw.engineering)
			t.Logf("перепись близнеца: документов %d · блоков %d · объявлений %d · законных %d · находок %d",
				census.docsRead, census.fencesRead, census.declarations, census.pageDecls, census.strayDecls)
			require.NotZero(t, len(legit), "положительный контроль: страница обязана объявлять правила — "+
				"иначе молчание ниже беспредметно")
			require.Empty(t, stray, "законный близнец «%s» назван находкой", name)
		})
	}
}

// TestAlertRulesSingleProducerInjection_FindsTheCopy — внесённая копия правила в
// инженерном документе находится, и находится С КООРДИНАТОЙ.
func TestAlertRulesSingleProducerInjection_FindsTheCopy(t *testing.T) {
	t.Parallel()

	// Один факт против близнеца: тот же документ, тот же текст, плюс блок с
	// объявлением. Всё прочее — дословно годное.
	defective := injEngineeringGood +
		"\n```yaml\n- alert: SampleAuthzCheckSlow\n  expr: sample_authz_seconds > 0.03\n```\n"

	legit, stray, census := scanInjectionTree(t, injPageGood, defective)
	t.Logf("перепись дефекта: документов %d · блоков %d · объявлений %d · законных %d · находок %d",
		census.docsRead, census.fencesRead, census.declarations, census.pageDecls, census.strayDecls)

	require.NotZero(t, len(legit), "положительный контроль: законное объявление на месте")
	require.Len(t, stray, 1, "внесённая копия правила НЕ НАЙДЕНА — проверка не способна упасть")
	require.Equal(t, injEngineering, stray[0].file, "находка названа без координаты файла")
	require.NotZero(t, stray[0].line, "находка названа без номера строки — читателю некуда идти")
}

// TestAlertRulesSingleProducerInjection_PremisesFailLoudly — «ноль находок»
// отличимо от «ноль прочитанного» по каждому из трёх страхов.
func TestAlertRulesSingleProducerInjection_PremisesFailLoudly(t *testing.T) {
	t.Parallel()

	t.Run("пустой обход", func(t *testing.T) {
		legit, stray, census, err := collectAlertDeclarations(t.TempDir(), injPage)
		require.NoError(t, err, "обход несуществующего каталога не обязан быть ошибкой — он обязан быть ПУСТЫМ")
		require.Zero(t, census.docsRead, "документов прочитано не ноль — предпосылка не воспроизведена")
		require.Empty(t, legit)
		require.Empty(t, stray, "на пустом обходе находок нет — и ИМЕННО поэтому страж переписи обязателен")
	})

	t.Run("ноль блоков кода", func(t *testing.T) {
		_, _, census := scanInjectionTree(t, "# Наблюдаемость\n\nБез единого блока кода.\n", injEngineeringGood)
		require.NotZero(t, census.docsRead, "документы прочитаны")
		require.Zero(t, census.fencesRead, "блоков кода не ноль — предпосылка не воспроизведена")
	})

	t.Run("страница перестала объявлять правила", func(t *testing.T) {
		legit, stray, census := scanInjectionTree(t,
			"# Наблюдаемость\n\n```sh\ncurl /metrics\n```\n", injEngineeringGood)
		require.NotZero(t, census.fencesRead, "блок кода прочитан — обход жив")
		require.Empty(t, legit, "страница не объявляет правил — ровно этот случай страж и ловит")
		require.Empty(t, stray, "находок нет, и без стража этот зелёный неотличим от чистого дерева")
	})
}
