// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// review_trigger_scope_injection_test.go — ГЕЙТ СПОСОБЕН УПАСТЬ И СПОСОБЕН
// СМОЛЧАТЬ (задача PRO-Robotech/kaname#394).
//
// Инъекция идёт НАСТОЯЩИМ входом: объявления процессов читаются из дерева, и
// дефект вносится в КОПИЮ одного из них — по одному факту за раз. Каждой
// половине «краснеет» отвечает законный близнец той же оси, на котором гейт
// молчит; на дереве как есть находок ноль, и это утверждается первым.
package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// reviewInjectRel — объявление, в копию которого вносится дефект.
const reviewInjectRel = "ci.yml"

// Записи из дерева, которые инъекция меняет. Если форма в дереве сменится,
// инъекция откажет ГРОМКО (см. injectOnce), а не станет холостой.
const (
	reviewBlock = "  pull_request:\n    branches:\n      - main\n      - '[0-9]+'\n"
	pushBlock   = "  push:\n    branches: [main]\n"
)

// injectOnce — копия с одной заменой. Замена, не нашедшая своей записи, —
// беспредметная инъекция: она доказывала бы молчание гейта на НЕТРОНУТОМ
// входе, и потому это отказ пробы, а не её зелёное.
func injectOnce(t *testing.T, raw, old, repl string) string {
	t.Helper()
	require.Containsf(t, raw, old, "инъекция беспредметна: записи %q в объявлении нет", old)
	return strings.Replace(raw, old, repl, 1)
}

// reviewAudit — вердикт о корпусе, где одно объявление подменено.
func reviewAudit(t *testing.T, edit func(raw string) string) ([]string, check.ReviewTriggerCensus) {
	t.Helper()
	corpus := trunkCorpusSource(t)
	raw, ok := corpus[reviewInjectRel]
	require.Truef(t, ok, "инъекция беспредметна: %s не прочитан", reviewInjectRel)
	corpus[reviewInjectRel] = edit(raw)
	findings, census, err := check.AuditReviewTriggers(corpus)
	require.NoError(t, err, "инъекция доказывала бы разбор, а не гейт")
	return findings, census
}

// TestReviewTriggerGateCanStaySilent — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ на дереве как есть.
//
// Без него всё нижеследующее зеленело бы на гейте, который краснеет всегда.
func TestReviewTriggerGateCanStaySilent(t *testing.T) {
	t.Parallel()
	findings, census, err := check.AuditReviewTriggers(trunkCorpusSource(t))
	require.NoError(t, err)
	require.Emptyf(t, findings, "на дереве как есть гейт нашёл %d: %v", len(findings), findings)
	require.GreaterOrEqual(t, census.OnReview, 2)
	require.Equal(t, census.OnReview, census.ReviewAtLine)
	require.Positive(t, census.Conditions, "условий `if:` ноль — ось 4 проверялась бы вырожденно")
	require.Positive(t, census.ConditionLinks, "условия есть, а звеньев в них ноль — разбор лексем слеп")
}

// TestReviewTriggerGateCanFail — половина «КРАСНЕЕТ», по оси на подпробу, и
// рядом с каждой — законный близнец той же оси.
func TestReviewTriggerGateCanFail(t *testing.T) {
	t.Parallel()

	// ── ОСЬ 1: базы запроса ─────────────────────────────────────────────────

	t.Run("база линии снята — ровно тот дефект, что закрывала задача", func(t *testing.T) {
		got, census := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "      - '[0-9]+'\n", "")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], reviewInjectRel)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
		require.Equal(t, census.OnReview-1, census.ReviewAtLine,
			"перепись обязана НАЗВАТЬ разрыв числом, а не только находкой")
	})

	t.Run("фильтр расширен до всех веток", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "      - '[0-9]+'\n", "      - '[0-9]+'\n      - '**'\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "лишние {`**`}")
	})

	// Один факт: знак `+` сменён на `*`. Запись похожа, и по виду файла разницы
	// почти нет, а захват другой — `2564-line-b` стала бы линией.
	t.Run("[0-9]* вместо [0-9]+ — захват хвоста", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "      - '[0-9]+'\n", "      - '[0-9]*'\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
		require.Contains(t, got[0], "лишние {`[0-9]*`}")
	})

	t.Run("фильтр баз снят целиком — запрос в любую ветку", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, reviewBlock, "  pull_request:\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "в ЛЮБУЮ")
	})

	t.Run("фильтр баз записан исключением", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, reviewBlock, "  pull_request:\n    branches-ignore:\n      - 'lane/**'\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "ИСКЛЮЧЕНИЕМ")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ ФОРМЫ: то же множество, записанное строкой и в обратном
	// порядке. Гейт, сверяющий текст, а не множество, краснел бы здесь.
	t.Run("то же множество строкой и в другом порядке — не находка", func(t *testing.T) {
		got, census := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, reviewBlock, "  pull_request:\n    branches: ['[0-9]+', main]\n")
		})
		require.Empty(t, got, "законная запись того же множества объявлена нарушением")
		require.Equal(t, census.OnReview, census.ReviewAtLine)
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ ПО РАЗБОРУ: образец, стоящий в КОММЕНТАРИИ, фильтром не
	// является. Гейт по подстроке зеленел бы на собственном объяснении.
	t.Run("образец в комментарии фильтром не считается", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "      - '[0-9]+'\n", "      # - '[0-9]+'\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
	})

	// ── ОСЬ 3: пути ─────────────────────────────────────────────────────────

	t.Run("запрос сужен по путям", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, reviewBlock, reviewBlock+"    paths:\n      - 'internal/**'\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "ПОИМЁННО")
	})

	// ── ОСЬ 2: push ─────────────────────────────────────────────────────────

	t.Run("push расширен на ветки линии", func(t *testing.T) {
		got, census := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, pushBlock, "  push:\n    branches: [main, '[0-9]+']\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "`push` расширен за ствол: {`[0-9]+`}")
		require.Equal(t, census.OnReview, census.ReviewAtLine, "ось 2 не задевает ось 1")
	})

	t.Run("push не сужен по ветке", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, pushBlock, "  push:\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "`push` не сужен по ветке")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ: `push` с одними метками идёт ТОЛЬКО на метки — так
	// провайдер читает тело без `branches`. Без этой половины гейт требовал бы
	// ствола от производителя, которому нужны одни версии.
	t.Run("push только по меткам — не находка", func(t *testing.T) {
		_, control, err := check.AuditReviewTriggers(trunkCorpusSource(t))
		require.NoError(t, err)
		got, census := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, pushBlock, "  push:\n    tags:\n      - 'v[0-9]+.[0-9]+.[0-9]+'\n")
		})
		require.Empty(t, got, "push по одним меткам объявлен нарушением")
		require.Equal(t, control.OnBranchPush-1, census.OnBranchPush,
			"процесс, идущий по одним меткам, не должен считаться идущим по push в ветки")
	})

	// ── ОСЬ 4: задание не различает базу ────────────────────────────────────

	t.Run("задание сужено по базе запроса", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "\n  trunkverdict:\n",
				"\n  onlymain:\n    if: github.base_ref == 'main'\n    runs-on: ubuntu-latest\n"+
					"    steps:\n      - run: echo ok\n  trunkverdict:\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "задание onlymain")
		require.Contains(t, got[0], "читает БАЗУ")
	})

	t.Run("шаг сужен по базе через окружение", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "\n  trunkverdict:\n",
				"\n  onlymain:\n    runs-on: ubuntu-latest\n    steps:\n"+
					"      - if: env.GITHUB_BASE_REF == 'main'\n        run: echo ok\n  trunkverdict:\n")
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "задание onlymain, шаг 1")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ: условие по СОБЫТИЮ базы не различает — запрос в ствол и
	// запрос в линию оно судит одинаково. Такие условия в дереве есть (сборка
	// образа без эмуляции на запросе), и гейт обязан на них молчать.
	t.Run("условие по событию — не находка", func(t *testing.T) {
		got, _ := reviewAudit(t, func(raw string) string {
			return injectOnce(t, raw, "\n  trunkverdict:\n",
				"\n  onlyreview:\n    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n"+
					"    steps:\n      - run: echo ok\n  trunkverdict:\n")
		})
		require.Empty(t, got, "условие по событию объявлено различающим базу")
	})
}

// withConditionJob — копия ci.yml с ОДНИМ новым заданием, чьё условие `if:`
// подано как есть. Меняется один факт — текст условия; всё прочее у красной
// подпробы и её близнеца одинаково.
func withConditionJob(t *testing.T, cond string) []string {
	t.Helper()
	got, _ := reviewAudit(t, func(raw string) string {
		return injectOnce(t, raw, "\n  trunkverdict:\n",
			"\n  onlymain:\n    if: "+cond+"\n    runs-on: ubuntu-latest\n"+
				"    steps:\n      - run: echo ok\n  trunkverdict:\n")
	})
	return got
}

// withConditionStep — то же, но условие стоит у ШАГА: ось 4 судит оба этажа.
func withConditionStep(t *testing.T, cond string) []string {
	t.Helper()
	got, _ := reviewAudit(t, func(raw string) string {
		return injectOnce(t, raw, "\n  trunkverdict:\n",
			"\n  onlymain:\n    runs-on: ubuntu-latest\n    steps:\n"+
				"      - if: "+cond+"\n        run: echo ok\n  trunkverdict:\n")
	})
	return got
}

// baseReadingForm — запись условия, читающая базу, и звено, которое находка
// обязана назвать: по нему видно, ЧТО распознаватель счёл чтением базы.
type baseReadingForm struct {
	name, cond, link string
}

// TestReviewTriggerGateKnowsEveryLawfulBaseReadingForm — ось 4 обязана знать
// ВСЕ законные записи чтения базы в выражении провайдера, а не перечень.
//
// Круг 1 искал подстроки и не видел записи с индексом. Круг 2 разбирал путь
// от корня и не видел звена `base` после `)` — у группы и у вызова. Оба раза
// слепой оказывалась ЛЕВАЯ часть обращения. Здесь стоят формы обоих кругов и
// формы, которые грамматика допускает сверх них; у каждой красной — близнец,
// меняющий один факт, на котором гейт обязан молчать.
func TestReviewTriggerGateKnowsEveryLawfulBaseReadingForm(t *testing.T) {
	t.Parallel()

	red := []baseReadingForm{
		// ── звено названо в тексте: точкой ─────────────────────────────────
		{"через точку", "github.event.pull_request.base.ref == 'main'", "звено `base`"},
		{"base.sha", "github.event.pull_request.base.sha != ''", "звено `base`"},
		{"регистр имён свойств", "GITHUB.EVENT.PULL_REQUEST.BASE.REF == 'main'", "звено `BASE`"},
		{"регистр внутри звена", "github.event.pull_request.bAse.ref == 'main'", "звено `bAse`"},
		{"база события очереди слияния", "github.event.merge_group.base_ref == 'refs/heads/main'",
			"звено `base_ref`"},
		{"двойные кавычки YAML", "\"github.event.pull_request.base.ref == 'main'\"", "звено `base`"},
		// ── звено названо в тексте: литералом индекса ──────────────────────
		{"индекс на одном звене", "github.event.pull_request['base'].ref == 'main'", "звено `base`"},
		{"индекс на каждом звене", "github.event['pull_request']['base']['ref'] == 'main'", "звено `base`"},
		{"индекс у base_ref", "github['base_ref'] == 'main'", "звено `base_ref`"},
		{"индекс у корня события", "github['event'].pull_request.base.ref == 'main'", "звено `base`"},
		{"регистр ключа индекса и обрамление ${{ }}",
			"${{ github.event['pull_request']['BASE']['ref'] == 'main' }}", "звено `BASE`"},
		{"пробелы внутри индекса и между индексами",
			"github.event[ 'pull_request' ] [ 'base' ].ref == 'main'", "звено `base`"},
		// ── звено названо в тексте, слева — группа или вызов (круг 3) ──────
		{"группа, затем точка", "(github.event.pull_request).base.ref == 'main'", "звено `base`"},
		{"группа, затем индекс", "(github.event.pull_request)['base'].ref == 'main'", "звено `base`"},
		{"группа с ИЛИ, затем точка",
			"(github.event.pull_request || github.event.merge_group).base.ref == 'main'", "звено `base`"},
		{"вызов от целого объекта запроса", "fromJSON(toJSON(github.event.pull_request)).base.ref == 'main'",
			"звено `base`"},
		{"вызов от целого события", "fromJSON(toJSON(github.event)).pull_request.base.ref == 'main'",
			"звено `base`"},
		{"вызов от выхода задания", "fromJSON(needs.prep.outputs.event).pull_request.base.ref == 'main'",
			"звено `base`"},
		{"группа у корня события", "(github.event).pull_request.base.ref == 'main'", "звено `base`"},
		{"группа кончается на base", "(github.event.pull_request.base).ref == 'main'", "звено `base`"},
		{"группа вокруг всего пути", "(github.event.pull_request.base.ref) == 'main'", "звено `base`"},
		{"фильтр перед base", "contains(github.event.*.base.ref, 'main')", "звено `base`"},
		{"база внутри индекса-выражения", "github.event.pull_request.labels[github.base_ref].name == 'x'",
			"звено `base_ref`"},
		// ── окружение и псевдоним со словом base ───────────────────────────
		{"окружение", "env.GITHUB_BASE_REF == 'main'", "звено `GITHUB_BASE_REF`"},
		{"выход задания верблюжьей записью", "needs.prep.outputs.baseRef == 'main'", "звено `baseRef`"},
		{"выход задания через дефис", "needs.prep.outputs.pr-base == 'main'", "звено `pr-base`"},
		// ── звено НЕ названо в тексте: фильтр и индекс выражением ──────────
		{"фильтр `.*` на месте base", "contains(github.event.pull_request.*.ref, 'main')",
			"неизвестное звено `*` у `pull_request`"},
		{"фильтр `[*]` на месте base", "contains(github.event.pull_request[*].ref, 'main')",
			"неизвестное звено `[*]` у `pull_request`"},
		{"фильтр у корня", "contains(github.*, 'main')", "неизвестное звено `*` у `github`"},
		{"фильтр у окружения", "contains(env.*, 'main')", "неизвестное звено `*` у `env`"},
		{"фильтр у очереди слияния", "contains(github.event.merge_group.*, 'refs/heads/main')",
			"неизвестное звено `*` у `merge_group`"},
		{"фильтр у элемента списка запросов",
			"contains(github.event.workflow_run.pull_requests[0].*.ref, 'main')",
			"неизвестное звено `*` у `pull_requests`"},
		{"индекс выражением", "github.event.pull_request[matrix.side].ref == 'main'",
			"неизвестное звено `[matrix.side]` у `pull_request`"},
		{"индекс вызовом", "github.event.pull_request[format('{0}', 'base')].ref == 'main'",
			"неизвестное звено `[format('{0}', 'base')]` у `pull_request`"},
		{"индекс группой литерала", "github.event.pull_request[('base')].ref == 'main'",
			"неизвестное звено `[('base')]` у `pull_request`"},
		{"индекс выражением у группы", "(github.event.pull_request)[matrix.k].ref == 'main'",
			"неизвестное звено `[matrix.k]` у результата группы или вызова"},
		{"фильтр у группы", "contains((github.event.pull_request).*.ref, 'main')",
			"неизвестное звено `*` у результата группы или вызова"},
		{"индекс за индексом выражением", "github.event[matrix.a][matrix.b].ref == 'main'",
			"неизвестное звено `[matrix.b]` у неизвестного звена"},
		// ── круг 4: перечень держит МОЛЧАЩИХ, всякий другой объект краснеет ──
		{"правка запроса поимённо", "github.event.changes.base.ref.from == 'main'", "звено `base`"},
		{"фильтр у правки запроса", "contains(github.event.changes.*.ref.from, 'main')",
			"неизвестное звено `*` у `changes`"},
		{"индекс выражением у правки запроса", "github.event.changes[matrix.k].ref.from == 'main'",
			"неизвестное звено `[matrix.k]` у `changes`"},
		{"фильтр у выходов задания", "contains(needs.prep.outputs.*, 'main')",
			"неизвестное звено `*` у `outputs`"},
		{"индекс выражением у выходов задания", "needs.prep.outputs[matrix.k] == 'main'",
			"неизвестное звено `[matrix.k]` у `outputs`"},
		{"фильтр у выходов шага", "contains(steps.prep.outputs.*, 'main')", "неизвестное звено `*` у `outputs`"},
		{"фильтр у события", "contains(github.event.*, 'refs/heads/main')", "неизвестное звено `*` у `event`"},
		{"фильтр у входов", "contains(inputs.*, 'main')", "неизвестное звено `*` у `inputs`"},
		{"объект, неизвестный разбору", "fromJSON(needs.prep.outputs.event).pr[matrix.k].ref == 'main'",
			"неизвестное звено `[matrix.k]` у `pr`"},
		{"`steps` полем, а не корнем", "contains(fromJSON(needs.prep.outputs.cfg).steps.*, 'main')",
			"неизвестное звено `*` у `steps`"},
		{"итог задания, затем неизвестные звенья", "needs[matrix.job][matrix.key][matrix.out] == 'main'",
			"неизвестное звено `[matrix.key]` у неизвестного звена"},
	}
	for _, tc := range red {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := withConditionJob(t, tc.cond)
			require.Lenf(t, got, 1, "условие %q читает базу, а гейт молчит", tc.cond)
			require.Contains(t, got[0], "задание onlymain:")
			require.Contains(t, got[0], "читает БАЗУ")
			require.Containsf(t, got[0], tc.link, "находка обязана назвать звено, которое читает базу")
		})
	}

	// Круг 3: та же группа в условии ШАГА. Ось 4 судит оба этажа одним
	// распознавателем, и форма, слепая у задания, была слепа и у шага.
	t.Run("группа с ИЛИ в условии шага", func(t *testing.T) {
		t.Parallel()
		got := withConditionStep(t, "(github.event.pull_request || github.event.merge_group).base.ref == 'main'")
		require.Len(t, got, 1, "условие шага читает базу, а гейт молчит")
		require.Contains(t, got[0], "задание onlymain, шаг 1:")
		require.Contains(t, got[0], "звено `base`")
	})

	// ЗАКОННЫЕ БЛИЗНЕЦЫ: та же форма записи, база НЕ читается. Каждый меняет
	// против своей красной подпробы один факт.
	for _, tc := range []struct {
		name, cond, why string
	}{
		{"head через точку", "github.event.pull_request.head.ref == 'lane'",
			"голова запроса одинакова на запросе в ствол и в линию"},
		{"github.head_ref", "github.head_ref == 'lane'", "`head_ref` — слово head, не base"},
		{"индекс на head вместо base", "github.event.pull_request['head'].ref == 'lane'",
			"та же запись с индексом, но читает голову"},
		{"группа, затем head", "(github.event.pull_request).head.ref == 'lane'",
			"близнец круга 3: группа слева, звено справа — head"},
		{"группа, затем индекс head", "(github.event.pull_request)['head'].ref == 'lane'",
			"близнец круга 3 с индексом"},
		{"группа с ИЛИ, затем head",
			"(github.event.pull_request || github.event.merge_group).head.ref == 'lane'",
			"близнец круга 3 с ИЛИ"},
		{"вызов от целого объекта, затем head", "fromJSON(toJSON(github.event.pull_request)).head.ref == 'lane'",
			"близнец круга 3 с вызовом"},
		{"числовой индекс не на base", "github.event.pull_request.labels[0].name == 'ci'",
			"индекс числом по меткам"},
		{"фильтр у меток", "contains(github.event.pull_request.labels.*.name, 'ci')",
			"`*` у меток: у метки нет поля базы"},
		{"фильтр у элемента меток", "contains(github.event.pull_request.labels[0].*, 'ci')",
			"близнец фильтра у элемента списка запросов"},
		{"индекс выражением у меток", "github.event.pull_request.labels[matrix.i].name == 'ci'",
			"близнец индекса выражением: объект — метки"},
		{"текст маркера в строковом литерале",
			"contains(github.event.pull_request.title, 'pull_request.base')",
			"`pull_request.base` здесь — текст, с которым сравнивают"},
		{"литерал с удвоенной кавычкой и индексом внутри",
			"contains(github.event.pull_request.title, 'it''s [''base'']')",
			"`['base']` стоит внутри литерала: удвоенная кавычка литерал не закрывает"},
		{"ключ индекса с удвоенной кавычкой", "github.event.pull_request['head''s'].ref == 'lane'",
			"удвоенная кавычка — часть ключа `head's`, а не конец литерала: индекс не выражение"},
		{"имя, содержащее base_ref подстрокой", "vars.DATABASE_REF == 'x'",
			"`database` — другое слово"},
		{"выход задания head верблюжьей записью", "needs.prep.outputs.headRef == 'lane'",
			"близнец `baseRef`"},
		{"условие по событию", "github.event_name == 'pull_request'",
			"событие одинаково у запроса в ствол и в линию"},
		{"фильтр по итогам заданий", "contains(needs.*.result, 'failure')",
			"корень `needs`: звено выбирает итог задания, а не значение"},
		{"индекс выражением по заданиям", "needs[matrix.job].result == 'success'",
			"близнец итога задания под неизвестным звеном"},
		{"фильтр по итогам шагов", "contains(steps.*.outcome, 'failure')",
			"корень `steps`: близнец `steps` полем"},
	} {
		t.Run("близнец: "+tc.name, func(t *testing.T) {
			t.Parallel()
			require.Emptyf(t, withConditionJob(t, tc.cond), "условие %q объявлено читающим базу: %s",
				tc.cond, tc.why)
		})
	}

	t.Run("близнец: группа с ИЛИ, затем head, в условии шага", func(t *testing.T) {
		t.Parallel()
		require.Empty(t, withConditionStep(t,
			"(github.event.pull_request || github.event.merge_group).head.ref == 'lane'"))
	})
}

// withJobs — копия ci.yml, где перед `trunkverdict` вставлены задания как
// есть; третье — отказ разбора, если он был (для половины «отказывает»).
func withJobs(t *testing.T, jobs string) ([]string, check.ReviewTriggerCensus, error) {
	t.Helper()
	corpus := trunkCorpusSource(t)
	raw, ok := corpus[reviewInjectRel]
	require.Truef(t, ok, "инъекция беспредметна: %s не прочитан", reviewInjectRel)
	corpus[reviewInjectRel] = injectOnce(t, raw, "\n  trunkverdict:\n", "\n"+jobs+"  trunkverdict:\n")
	return check.AuditReviewTriggers(corpus)
}

// aliasedCondJob — задание, чьё условие (или условие его шага) записано
// псевдонимом `*onlymain` на якорь в `env:` того же задания. Меняется один
// факт — текст под якорем.
func aliasedCondJob(anchored string, onStep bool) string {
	head := "  onlymain:\n    runs-on: ubuntu-latest\n    env:\n      ONLY_MAIN: &onlymain " + anchored + "\n"
	if onStep {
		return head + "    steps:\n      - if: *onlymain\n        run: echo ok\n"
	}
	return head + "    if: *onlymain\n    steps:\n      - run: echo ok\n"
}

// TestReviewTriggerGateResolvesYAMLAliases — псевдоним YAML разрешается ДО
// суждения, у всех узлов, которые судит ось 4, и у фильтров осей 1–3.
//
// Круг 4: `if: *onlymain` на якорь в `env:` зеленел — узел псевдонима хранит
// имя якоря, и судилось имя; задание, `steps` и шаг под псевдонимом
// пропускались вовсе и в перепись не попадали. Провайдер все эти записи
// исполняет (@actions/workflow-parser 0.3.61, замер: `job.if = success() &&
// (github.base_ref == 'main')`). Якорь стоит в блочной записи `env:`: запись
// `{ONLY_MAIN: &onlymain ${{ … }}}` в строку не разбирается ни провайдером
// (`Unexpected flow-map-start`), ни yaml.v3.
func TestReviewTriggerGateResolvesYAMLAliases(t *testing.T) {
	t.Parallel()
	_, control, err := check.AuditReviewTriggers(trunkCorpusSource(t))
	require.NoError(t, err)
	require.Zero(t, control.Aliases, "в дереве псевдонимов нет — счёт ниже меряется от нуля")

	const readsBase = "${{ github.base_ref == 'main' }}"
	const readsHead = "${{ github.head_ref == 'lane' }}"

	for _, tc := range []struct {
		name   string
		onStep bool
		where  string
	}{
		{"условие задания псевдонимом", false, "задание onlymain:"},
		{"условие шага псевдонимом", true, "задание onlymain, шаг 1:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, census, err := withJobs(t, aliasedCondJob(readsBase, tc.onStep))
			require.NoError(t, err)
			require.Lenf(t, got, 1, "условие под псевдонимом читает базу, а гейт молчит")
			require.Contains(t, got[0], tc.where)
			require.Contains(t, got[0], "звено `base_ref`")
			require.Equal(t, control.Aliases+1, census.Aliases, "перепись обязана назвать разрешённый псевдоним")
		})
		t.Run("близнец: "+tc.name+", под якорем голова", func(t *testing.T) {
			t.Parallel()
			got, census, err := withJobs(t, aliasedCondJob(readsHead, tc.onStep))
			require.NoError(t, err)
			require.Empty(t, got, "условие под псевдонимом базу не читает")
			require.Equal(t, control.Conditions+1, census.Conditions, "условие под псевдонимом не осмотрено")
		})
	}

	// Задание, `steps` и шаг под псевдонимом: вторая находка — у копии. Без
	// разрешения копия пропускалась, и находка была бы одна.
	for _, tc := range []struct {
		name, jobs string
		where      []string
	}{
		{"задание псевдонимом",
			"  onlymain: &job\n    runs-on: ubuntu-latest\n    if: COND\n    steps:\n      - run: echo ok\n" +
				"  onlymaincopy: *job\n",
			[]string{"задание onlymain:", "задание onlymaincopy:"}},
		{"steps псевдонимом",
			"  onlymain:\n    runs-on: ubuntu-latest\n    steps: &steps\n      - if: COND\n        run: echo ok\n" +
				"  onlymaincopy:\n    runs-on: ubuntu-latest\n    steps: *steps\n",
			[]string{"задание onlymain, шаг 1:", "задание onlymaincopy, шаг 1:"}},
		{"шаг псевдонимом",
			"  onlymain:\n    runs-on: ubuntu-latest\n    steps:\n      - &step\n        if: COND\n        run: echo ok\n" +
				"  onlymaincopy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n      - *step\n",
			[]string{"задание onlymain, шаг 1:", "задание onlymaincopy, шаг 2:"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, census, err := withJobs(t, strings.ReplaceAll(tc.jobs, "COND", readsBase))
			require.NoError(t, err)
			require.Lenf(t, got, len(tc.where), "копия под псевдонимом не судится: %v", got)
			for i, w := range tc.where {
				require.Contains(t, got[i], w)
			}
			require.Equal(t, control.Aliases+1, census.Aliases)
		})
		t.Run("близнец: "+tc.name+", условие по голове", func(t *testing.T) {
			t.Parallel()
			got, census, err := withJobs(t, strings.ReplaceAll(tc.jobs, "COND", readsHead))
			require.NoError(t, err)
			require.Empty(t, got)
			require.Equal(t, control.Conditions+2, census.Conditions,
				"условие копии под псевдонимом обязано попасть в перепись")
		})
	}

	// Оси 1–3: фильтр баз, чей элемент — псевдоним на ветку ствола из `push`.
	// Прочитанный по имени якоря, он дал бы «лишние {`trunk`}».
	aliasedBases := func(t *testing.T, review string) ([]string, check.ReviewTriggerCensus) {
		t.Helper()
		return reviewAudit(t, func(raw string) string {
			raw = injectOnce(t, raw, pushBlock, "  push:\n    branches: [&trunk main]\n")
			return injectOnce(t, raw, reviewBlock, review)
		})
	}
	t.Run("база запроса псевдонимом, линия снята", func(t *testing.T) {
		t.Parallel()
		got, census := aliasedBases(t, "  pull_request:\n    branches:\n      - *trunk\n")
		require.Len(t, got, 1)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
		require.NotContains(t, got[0], "лишние", "псевдоним прочитан по имени якоря, а не по значению")
		require.Equal(t, control.Aliases+1, census.Aliases)
	})
	t.Run("близнец: база запроса псевдонимом, линия на месте", func(t *testing.T) {
		t.Parallel()
		got, census := aliasedBases(t, "  pull_request:\n    branches:\n      - *trunk\n      - '[0-9]+'\n")
		require.Empty(t, got)
		require.Equal(t, census.OnReview, census.ReviewAtLine)
	})
}

// TestReviewTriggerGateRefusesAYAMLFormTheProviderRejects — запись, которой
// провайдер не принимает, — ОТКАЗ разбора, а не молчание и не пропуск.
//
// Каждая форма сверена с @actions/workflow-parser 0.3.61 — ровно этими
// заданиями: ключ слияния (`Unexpected value '<<'`), ключ-псевдоним
// (`Unexpected value 'undefined'`), псевдоним внутрь собственного якоря
// (`Expected mapping end`), `if:` отображением (`A mapping was not
// expected`), задание, `steps` и шаг скаляром (`Unexpected value 'echo'`);
// то же задание без дефекта — ноль ошибок. Близнец отказа — вся
// TestReviewTriggerGateResolvesYAMLAliases: законный псевдоним вердикт даёт.
func TestReviewTriggerGateRefusesAYAMLFormTheProviderRejects(t *testing.T) {
	t.Parallel()
	const job = "  onlymain: &job\n    runs-on: ubuntu-latest\n    if: ${{ github.head_ref == 'lane' }}\n" +
		"    steps:\n      - run: echo ok\n"
	for _, tc := range []struct {
		name, jobs, why string
	}{
		{"ключ слияния", job + "  onlymaincopy:\n    <<: *job\n", "ключ слияния `<<`"},
		{"ключ-псевдоним",
			"  onlymain:\n    runs-on: ubuntu-latest\n    env:\n      K: &ifkey if\n" +
				"    *ifkey : ${{ github.base_ref == 'main' }}\n    steps:\n      - run: echo ok\n",
			"ключ отображения записан псевдонимом `*ifkey`"},
		{"псевдоним внутрь собственного якоря",
			"  onlymain: &job\n    runs-on: ubuntu-latest\n    services: *job\n    steps:\n      - run: echo ok\n",
			"ведёт внутрь собственного якоря"},
		{"условие отображением",
			"  onlymain:\n    runs-on: ubuntu-latest\n    if: {base: main}\n    steps:\n      - run: echo ok\n",
			"задание onlymain: условие `if:` не скаляр"},
		{"задание скаляром", "  onlymain: echo\n", "задание onlymain не отображение"},
		{"steps скаляром", "  onlymain:\n    runs-on: ubuntu-latest\n    steps: echo\n",
			"задание onlymain: `steps` не последовательность"},
		{"шаг скаляром", "  onlymain:\n    runs-on: ubuntu-latest\n    steps:\n      - echo\n",
			"задание onlymain, шаг 1 не отображение"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := withJobs(t, tc.jobs)
			require.Errorf(t, err, "форма, которой провайдер не принимает, прошла разбор молча")
			require.Contains(t, err.Error(), reviewInjectRel)
			require.Contains(t, err.Error(), tc.why)
		})
	}
}

// TestReviewTriggerGateKnowsEveryLawfulEventForm — распознаватель обязан знать
// ВСЕ законные записи события: форма вне наблюдения даёт не красное и не
// зелёное, а молчание.
func TestReviewTriggerGateKnowsEveryLawfulEventForm(t *testing.T) {
	t.Parallel()

	const jobs = "jobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
	withProcess := func(t *testing.T, raw string) ([]string, check.ReviewTriggerCensus, check.ReviewTriggerCensus) {
		t.Helper()
		base := trunkCorpusSource(t)
		_, before, err := check.AuditReviewTriggers(base)
		require.NoError(t, err)
		base["newflow.yml"] = raw
		findings, after, err := check.AuditReviewTriggers(base)
		require.NoError(t, err)
		return findings, before, after
	}

	t.Run("on: pull_request скаляром — любая база", func(t *testing.T) {
		got, before, after := withProcess(t, "name: новый\non: pull_request\n"+jobs)
		require.Len(t, got, 1)
		require.Contains(t, got[0], "newflow.yml")
		require.Contains(t, got[0], "в ЛЮБУЮ")
		require.Equal(t, before.OnReview+1, after.OnReview)
	})

	t.Run("on: [push, pull_request] последовательностью — обе оси", func(t *testing.T) {
		got, _, _ := withProcess(t, "name: новый\non: [push, pull_request]\n"+jobs)
		require.Len(t, got, 2)
		joined := strings.Join(got, "\n")
		require.Contains(t, joined, "в ЛЮБУЮ")
		require.Contains(t, joined, "`push` не сужен по ветке")
	})

	t.Run("branches одиночным скаляром — множество из одного", func(t *testing.T) {
		got, _, _ := withProcess(t, "name: новый\non:\n  pull_request:\n    branches: main\n"+jobs)
		require.Len(t, got, 1)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ: процесс, не идущий на запросе, предметом не является —
	// он не идёт ни на запросе в ствол, ни на запросе в линию, то есть состав
	// обоих запросов одинаков. Перепись обязана его ПОСЧИТАТЬ, а не пропустить.
	t.Run("процесс без запроса — не находка, но в переписи", func(t *testing.T) {
		got, before, after := withProcess(t, "name: новый\non: workflow_dispatch\n"+jobs)
		require.Empty(t, got)
		require.Equal(t, before.Files+1, after.Files)
		require.Equal(t, before.OnReview, after.OnReview)
	})
}

// TestReviewTriggerGateRefusesAVacuousInput — беспредметный вход есть отказ,
// а не вердикт.
func TestReviewTriggerGateRefusesAVacuousInput(t *testing.T) {
	t.Parallel()

	_, _, err := check.AuditReviewTriggers(map[string]string{})
	require.Error(t, err, "пустой корпус принят за чистый: «ноль прочитанного» стало вердиктом")

	_, _, err = check.AuditReviewTriggers(map[string]string{"a.yml": "{ обрезано"})
	require.Error(t, err, "неразобранное объявление принято за чистое")

	_, _, err = check.AuditReviewTriggers(map[string]string{"a.yml": "name: без триггера\njobs: {}\n"})
	require.Error(t, err, "объявление без `on:` принято за чистое")

	_, _, err = check.AuditReviewTriggers(map[string]string{"a.yml": "name: вручную\non: workflow_dispatch\n"})
	require.Error(t, err, "корпус без единого процесса на запросе принят за чистый: детектор "+
		"события молчал бы, и его ноль читался бы как «сужений нет»")
}
