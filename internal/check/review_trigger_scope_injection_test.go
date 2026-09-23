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

// TestReviewTriggerGateKnowsEveryLawfulBaseReadingForm — ось 4 обязана знать
// ВСЕ законные записи чтения базы в выражении провайдера, а не одну.
//
// Круг 1 искал подстроки `base_ref` и `pull_request.base`, и запись с индексом —
// `github.event.pull_request['base'].ref` — проходила зелёным: выражение читает
// ту же базу, а подстроки в тексте нет. Каждая форма ниже — отдельная подпроба,
// и находка обязана назвать путь ПРИВЕДЁННЫМ, через точку: по нему видно, что
// распознаватель прочёл именно базу, а не совпал с текстом.
func TestReviewTriggerGateKnowsEveryLawfulBaseReadingForm(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, cond, path string
	}{
		{"индекс на одном звене", "github.event.pull_request['base'].ref == 'main'",
			"github.event.pull_request.base.ref"},
		{"индекс на каждом звене", "github.event['pull_request']['base']['ref'] == 'main'",
			"github.event.pull_request.base.ref"},
		{"индекс у base_ref", "github['base_ref'] == 'main'", "github.base_ref"},
		{"регистр имён свойств", "GITHUB.EVENT.PULL_REQUEST.BASE.REF == 'main'",
			"github.event.pull_request.base.ref"},
		{"регистр ключа индекса и обрамление ${{ }}",
			"${{ github.event['pull_request']['BASE']['ref'] == 'main' }}",
			"github.event.pull_request.base.ref"},
		{"пробелы внутри индекса и между индексами",
			"github.event[ 'pull_request' ] [ 'base' ].ref == 'main'",
			"github.event.pull_request.base.ref"},
		{"фильтр объекта `*` на месте base", "contains(github.event.pull_request.*.ref, 'main')",
			"github.event.pull_request.*.ref"},
		{"индекс выражением — звено неизвестно, значит может быть base",
			"github.event.pull_request[matrix.side].ref == 'main'",
			"github.event.pull_request.*.ref"},
		{"чтение у результата функции", "fromJSON(needs.prep.outputs.event).pull_request.base.ref == 'main'",
			"*.pull_request.base.ref"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := withConditionJob(t, tc.cond)
			require.Lenf(t, got, 1, "условие %q читает базу, а гейт молчит", tc.cond)
			require.Contains(t, got[0], "задание onlymain")
			require.Contains(t, got[0], "читает БАЗУ")
			require.Containsf(t, got[0], "`"+tc.path+"`",
				"находка обязана назвать прочитанный путь приведённым к записи через точку")
		})
	}

	// ЗАКОННЫЕ БЛИЗНЕЦЫ: та же форма записи, база НЕ читается. Каждый меняет
	// против красной подпробы один факт.
	for _, tc := range []struct {
		name, cond, why string
	}{
		{"индекс на head вместо base", "github.event.pull_request['head'].ref == 'lane'",
			"та же запись с индексом, но читает голову запроса — её состав одинаков на запросе в ствол и в линию"},
		{"числовой индекс не на base", "github.event.pull_request.labels[0].name == 'ci'",
			"индекс числом по меткам — путь расходится с базой на четвёртом звене"},
		{"текст маркера в строковом литерале",
			"contains(github.event.pull_request.title, 'pull_request.base')",
			"`pull_request.base` здесь — текст, с которым сравнивают, а не путь, который читают"},
		{"имя, содержащее base_ref подстрокой", "vars.DATABASE_REF == 'x'",
			"`database_ref` — другое слово; поиск по подстроке краснел бы здесь"},
	} {
		t.Run("близнец: "+tc.name, func(t *testing.T) {
			t.Parallel()
			require.Emptyf(t, withConditionJob(t, tc.cond), "условие %q объявлено читающим базу: %s",
				tc.cond, tc.why)
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
