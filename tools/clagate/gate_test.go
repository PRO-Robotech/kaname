// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clagate_test

// gate_test.go — гейт доказывается инъекцией в ОБЕ стороны и объявляет объём
// осмотренного.
//
// Каждая инъекция меняет РОВНО ОДИН факт против своего положительного близнеца:
// иначе неизвестно, какой из двух дал красное, и вердикт недействителен, хотя
// выглядит как обычный зелёный.
//
// Форм подтверждения две (подпись коммита и запись в ведомости), форм вклада
// тоже две (автор коммита и соавтор в трейлере) — и каждая доказывается своей
// парой. Форма, о которой распознаватель не знает, даёт не красное и не зелёное,
// а МОЛЧАНИЕ: вклад в ней просто не попадает под наблюдение.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"

	"github.com/PRO-Robotech/kaname/internal/treeroot"
	"github.com/PRO-Robotech/kaname/tools/clagate"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// ledgerRel — ведомость, объявляющая своих, подписавших и машинные личности.
//
// Координата от корня ПЛАТФОРМЫ; к посадке её приводит резолвер, а не подъём
// каталогами: число шагов вверх верно ровно для одной посадки, и в
// самостоятельном клоне тот же подъём выводит ВЫШЕ корня клона.
const ledgerRel = "services/iam/cla-ledger.yaml"

// TestGate_IamHistoryIsConfirmed — боевой прогон по истории домена.
//
// Перепись здесь не украшение, а отдельное утверждение: «ноль находок» обязано
// быть отличимо от «ноль прочитанного». Поэтому проверяются ОБЕ величины —
// сколько осмотрено и сколько найдено.
func TestGate_IamHistoryIsConfirmed(t *testing.T) {
	// Корень обхода истории — САМ репозиторий, в котором идёт прогон, а
	// ведомость адресуется от него же: в монорепо это `services/iam/…`, в
	// клоне — `cla-ledger.yaml` от его корня.
	root, prefix := platformtree.RequireCorpus(t)
	ledger := platformtree.Under(prefix, strings.TrimPrefix(ledgerRel, "services/iam/"))
	rep, err := clagate.Inspect(root, ledger, "HEAD")
	require.NoError(t, err)

	// ПРЕДПОСЫЛКА ГЕЙТА — ИСТОРИЯ ДОМЕНА, и она есть не у всякого дерева.
	//
	// Ведомость объявляет ОБЛАСТЬ (`scope`) ОТНОСИТЕЛЬНО СЕБЯ (`.`), и к корню
	// судимого дерева её сводит `Inspect`. Область поэтому резолвится в ОБЕИХ
	// посадках — и ровно с этого начинается предмет: пока она резолвилась только
	// в монорепо, «условие не создано» опознавалось по НЕРЕЗОЛВУ ОБЛАСТИ, то есть
	// побочным следствием, а не предметом. Область резолвится — предмет пропал, и
	// дерево БЕЗ истории домена стало красным вместо третьего исхода.
	//
	// Опознаётся он теперь ПРЯМО: дерево, в котором обход области не дал истории
	// домена, вердикта о соглашении не выносит ни в одну сторону. Разводит исходы
	// `clagate.Classify` — она же держит несущее свойство: в дереве платформы
	// пропуск НЕДОСТИЖИМ, поэтому короткий обход остаётся там находкой и гейт
	// нельзя снять поломкой ведомости.
	//
	// Посадку называет РЕЗОЛВЕР, а не проба: приставка модуля в составе непуста
	// только тогда, когда рядом лежит дерево платформы.
	inPlatformTree := prefix != ""
	switch outcome, why := clagate.Classify(rep, inPlatformTree); outcome {
	case clagate.OutcomeUnmetPremise:
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): %s.\n"+
			"Посадка: %s. Осмотрено коммитов: %d.", why, root, rep.CommitsExamined)
	case clagate.OutcomeBlindWalk:
		t.Fatalf("гейт слеп, и это находка о нём: %s.\n"+
			"Посадка: %s. Осмотрено коммитов: %d.", why, root, rep.CommitsExamined)
	case clagate.OutcomeJudge:
		// Предмет есть — судим ниже.
	}

	require.GreaterOrEqual(t, rep.IdentitiesSeen, 2,
		"обход увидел %d личностей — при одной вердикт о РАЗЛИЧЕНИИ своего и стороннего вакуумен",
		rep.IdentitiesSeen)
	require.Empty(t, rep.Findings,
		"вклад стороннего автора без подтверждения соглашения: %s\n\n"+
			"Открытие репозитория без подтверждения закрывает двойное лицензирование\n"+
			"НАВСЕГДА: вернуться можно только собрав подписи каждого стороннего автора\n"+
			"поимённо. Либо автор подтверждает соглашение (см. services/iam/CLA.md),\n"+
			"либо его личность объявляется в ведомости с названной причиной.",
		rep.Summary(10))

	// Ветка освобождения обязана ИСПОЛНЯТЬСЯ: объявленное, но ни разу не
	// пройденное исключение оставляет о себе вердикт неизвестным.
	require.Greater(t, rep.Waived, 0,
		"ни одна объявленная машинная личность не встретилась: ветка исключения не исполнялась")

	require.Empty(t, rep.UnusedEntries,
		"записи ведомости, которым больше нечего покрывать: %v — исключение живёт, пока у него есть предмет",
		rep.UnusedEntries)

	// Посадка печатается ВМЕСТЕ с числами: те же величины в двух посадках
	// означают разное, и вердикт, не назвавший посадки, сказан неизвестно о чём.
	t.Logf("посадка: %s (дерево платформы: %t); осмотрено: коммитов=%d, "+
		"вкладов(коммит×личность)=%d, личностей=%d; свои=%d, подписью=%d, ведомостью=%d, освобождено=%d",
		root, inPlatformTree, rep.CommitsExamined, rep.ContributionsInspected, rep.IdentitiesSeen,
		rep.ByOwners, rep.ConfirmedBySignOff, rep.ConfirmedByLedger, rep.Waived)
}

// --- Форма вклада 1: АВТОР коммита -----------------------------------------

// TestGate_ExternalAuthorWithoutConfirmationIsAFinding — инъекция.
//
// Против близнеца ниже отличается РОВНО ОДНИМ фактом: в сообщении коммита нет
// строки подтверждения.
func TestGate_ExternalAuthorWithoutConfirmationIsAFinding(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Гость", email: "guest@example.org", message: "feat: правка стороннего автора"},
	})

	rep := inspectFixture(t, dir, minimalLedger)

	require.Len(t, rep.Findings, 1, "сторонний вклад без подтверждения обязан быть находкой")
	require.Contains(t, rep.Findings[0].Identity, "guest@example.org",
		"находка обязана НАЗЫВАТЬ личность — иначе по ней нечего делать")
	require.NotEmpty(t, rep.Findings[0].Commit, "находка обязана называть коммит")
	require.Contains(t, rep.Findings[0].String(), "guest@example.org")
}

// TestGate_ExternalAuthorWithSignOffIsSilent — законный близнец (форма
// подтверждения 1: подпись коммита).
func TestGate_ExternalAuthorWithSignOffIsSilent(t *testing.T) {
	dir := writeRepo(t, []commit{
		{
			name: "Гость", email: "guest@example.org",
			message: "feat: правка стороннего автора\n\nSigned-off-by: Гость <guest@example.org>",
		},
	})

	rep := inspectFixture(t, dir, minimalLedger)

	require.Empty(t, rep.Findings, "подпись автора подтверждает соглашение")
	require.Equal(t, 1, rep.ConfirmedBySignOff)
	require.Equal(t, 0, rep.ConfirmedByLedger)
}

// TestGate_SignOffKeyIsCaseInsensitive — та же форма, записанная иначе.
// Распознаватель обязан знать ВСЕ законные написания ключа: форма, о которой он
// не знает, молча выводит вклад из-под наблюдения.
func TestGate_SignOffKeyIsCaseInsensitive(t *testing.T) {
	dir := writeRepo(t, []commit{
		{
			name: "Гость", email: "guest@example.org",
			message: "feat: правка\n\nsigned-off-by: Гость <GUEST@Example.ORG>",
		},
	})

	rep := inspectFixture(t, dir, minimalLedger)
	require.Empty(t, rep.Findings)
	require.Equal(t, 1, rep.ConfirmedBySignOff)
}

// TestGate_SignOffByAnotherIdentityDoesNotConfirm — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на
// слабый предикат.
//
// «В сообщении есть Signed-off-by» и «вкладчик подтвердил соглашение» — разные
// утверждения. Подписаться за другого нельзя: подтверждает тот, чья личность в
// подписи совпадает с личностью вкладчика.
//
// Это не выдуманный край: ровно такой коммит есть в истории домена — машинная
// личность подписывает служебным адресом, отличным от авторского.
func TestGate_SignOffByAnotherIdentityDoesNotConfirm(t *testing.T) {
	dir := writeRepo(t, []commit{
		{
			name: "Гость", email: "guest@example.org",
			message: "feat: правка\n\nSigned-off-by: Кто-то Другой <someone@example.net>",
		},
	})

	rep := inspectFixture(t, dir, minimalLedger)

	require.Len(t, rep.Findings, 1,
		"подпись ЧУЖОЙ личностью подтверждением не является — иначе подписаться можно за любого")
	require.Contains(t, rep.Findings[0].Identity, "guest@example.org")
	require.Equal(t, 0, rep.ConfirmedBySignOff)
}

// TestGate_SignOffOutsideTrailerBlockDoesNotConfirm — объявленная ГРАНИЦА.
//
// Подпись читается из завершающего блока трейлеров, а не откуда угодно в теле:
// иначе процитированная в прозе строка (разбор чужого коммита, откат) начала бы
// подтверждать соглашение задним числом.
func TestGate_SignOffOutsideTrailerBlockDoesNotConfirm(t *testing.T) {
	dir := writeRepo(t, []commit{
		{
			name: "Гость", email: "guest@example.org",
			message: "revert: откат\n\nОткатывается коммит, чьё сообщение несло строку\n" +
				"Signed-off-by: Гость <guest@example.org>\nи ничего более.\n\nСсылка: #1",
		},
	})

	rep := inspectFixture(t, dir, minimalLedger)
	require.Len(t, rep.Findings, 1,
		"строка подписи вне блока трейлеров подтверждением не является")
}

// --- Форма вклада 2: СОАВТОР в трейлере -------------------------------------

// TestGate_CoAuthorIsAContributorToo — инъекция во ВТОРУЮ форму вклада.
//
// Гейт, смотрящий только на автора коммита, соавтора не видит вовсе — и это
// молчание, а не пропуск: вклад существует, наблюдения за ним нет. Автор здесь
// свой, поэтому красное может прийти ТОЛЬКО от соавтора.
func TestGate_CoAuthorIsAContributorToo(t *testing.T) {
	dir := writeRepo(t, []commit{
		{
			name: "Свой", email: "owner@example.com",
			message: "feat: правка\n\nCo-authored-by: Гость <guest@example.org>",
		},
	})

	rep := inspectFixture(t, dir, minimalLedger)

	require.Len(t, rep.Findings, 1, "соавтор — тоже вкладчик")
	require.Contains(t, rep.Findings[0].Identity, "guest@example.org")
	require.Equal(t, 2, rep.ContributionsInspected,
		"вкладов в коммите два: автор и соавтор")
}

// TestGate_CoAuthorWithOwnSignOffIsSilent — законный близнец предыдущего:
// отличается РОВНО ОДНИМ фактом — у соавтора есть своя подпись.
func TestGate_CoAuthorWithOwnSignOffIsSilent(t *testing.T) {
	dir := writeRepo(t, []commit{
		{
			name: "Свой", email: "owner@example.com",
			message: "feat: правка\n\nCo-authored-by: Гость <guest@example.org>\n" +
				"Signed-off-by: Гость <guest@example.org>",
		},
	})

	rep := inspectFixture(t, dir, minimalLedger)
	require.Empty(t, rep.Findings)
	require.Equal(t, 1, rep.ConfirmedBySignOff)
	require.Equal(t, 1, rep.ByOwners)
}

// --- Форма подтверждения 2: запись в ведомости ------------------------------

// TestGate_ExternalAuthorInLedgerIsSilent — законный близнец инъекции автора:
// отличается РОВНО ОДНИМ фактом — личность объявлена подписавшей.
func TestGate_ExternalAuthorInLedgerIsSilent(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Гость", email: "guest@example.org", message: "feat: правка стороннего автора"},
	})

	rep := inspectFixture(t, dir, minimalLedger+`
signatories:
  - email: guest@example.org
    note: соглашение принято вне коммита — PR #1, 2026-09-05
`)

	require.Empty(t, rep.Findings, "объявленная подпись подтверждает соглашение")
	require.Equal(t, 1, rep.ConfirmedByLedger)
	require.Equal(t, 0, rep.ConfirmedBySignOff)
}

// TestGate_OwnAuthorIsSilent — свой автор находкой не является: правообладатель
// не заключает соглашения сам с собой.
func TestGate_OwnAuthorIsSilent(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "feat: правка своего автора"},
	})

	rep := inspectFixture(t, dir, minimalLedger)
	require.Empty(t, rep.Findings)
	require.Equal(t, 1, rep.ByOwners)
}

// --- Дисциплина самой ведомости ---------------------------------------------

// TestGate_WaiverNeedsANamedReason — «не спрашиваем» без основания и есть
// искомый дефект: освобождение без причины освобождением не является.
func TestGate_WaiverNeedsANamedReason(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Робот", email: "bot@example.org", message: "chore: машинная правка"},
	})

	withReason := inspectFixture(t, dir, minimalLedger+`
waivers:
  - email: bot@example.org
    note: машинная личность — содержимое вклада не является авторским произведением
`)
	require.Empty(t, withReason.Findings, "освобождение с названной причиной принимается")
	require.Equal(t, 1, withReason.Waived)

	// Тот же мир, РОВНО ОДИН изменённый факт: причина снята.
	noReason := inspectFixture(t, dir, minimalLedger+`
waivers:
  - email: bot@example.org
    note: ""
`)
	require.Len(t, noReason.Findings, 1, "освобождение без причины освобождением не является")
	require.Equal(t, 0, noReason.Waived)
}

// TestGate_StaleLedgerEntryIsReported — запись, которой больше нечего
// покрывать: вкладчик из истории исчез, а объявленное послабление осталось и
// молча покроет следующего с тем же адресом.
func TestGate_StaleLedgerEntryIsReported(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "feat: правка"},
	})

	rep := inspectFixture(t, dir, minimalLedger+`
signatories:
  - email: nobody@example.org
    note: подписал в 2020-м и с тех пор ничего не вложил
`)

	require.Empty(t, rep.Findings)
	require.Len(t, rep.UnusedEntries, 1)
	require.Contains(t, rep.UnusedEntries[0], "nobody@example.org")
}

// --- Предпосылка гейта ------------------------------------------------------

// TestGate_ScopePointingNowhereIsAPremiseFailure — область, объявленная мимо
// дерева, даёт ПУСТОЙ обход: ноль коммитов, ноль находок, вид исправной работы.
// Это единственный способ ослепить гейт молча, поэтому он проверяется отдельно.
func TestGate_ScopePointingNowhereIsAPremiseFailure(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Гость", email: "guest@example.org", message: "feat: правка стороннего автора"},
	})

	rep := inspectFixture(t, dir, `scope:
  - services/nonexistent
owners:
  - email: owner@example.com
    note: правообладатель
`)

	require.Empty(t, rep.Findings, "находок нет — и именно поэтому нужна предпосылка")
	require.NotEmpty(t, rep.PremiseFailures,
		"пустой обход обязан быть отличим от чистого дерева")
	require.Contains(t, strings.Join(rep.PremiseFailures, "\n"), "services/nonexistent")
}

// TestGate_EmptyOwnersIsAPremiseFailure — ведомость без своих личностей делает
// вердикт бессмысленным: различать станет нечего.
func TestGate_EmptyOwnersIsAPremiseFailure(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "feat: правка"},
	})

	rep := inspectFixture(t, dir, "scope:\n  - src\nowners: []\n")
	require.NotEmpty(t, rep.PremiseFailures)
}

// TestGate_MissingLedgerIsAnError — отсутствие ведомости не «пустая ведомость»:
// молчаливое умолчание здесь означало бы «своих нет, все находки», либо, при
// обратном умолчании, «все свои». Ни то, ни другое не выводится — это отказ.
func TestGate_MissingLedgerIsAnError(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "feat: правка"},
	})

	_, err := clagate.Inspect(dir, "cla-ledger.yaml", "HEAD")
	require.Error(t, err)
}

// --- Фикстура ---------------------------------------------------------------

// minimalLedger — минимальная годная ведомость: область и один свой автор.
// Все инъекции строятся ОТ НЕЁ, чтобы отличие было ровно одно.
const minimalLedger = `scope:
  - src
owners:
  - email: owner@example.com
    note: правообладатель — соглашение к нему не применяется
`

type commit struct {
	name    string
	email   string
	message string
}

// inspectFixture кладёт ведомость в синтетический репозиторий и судит его.
func inspectFixture(t *testing.T, dir, ledger string) clagate.Report {
	t.Helper()
	path := filepath.Join(dir, "cla-ledger.yaml")
	require.NoError(t, os.WriteFile(path, []byte(ledger), 0o600))

	rep, err := clagate.Inspect(dir, "cla-ledger.yaml", "HEAD")
	require.NoError(t, err)
	return rep
}

// writeRepo поднимает ИЗОЛИРОВАННЫЙ репозиторий в собственном каталоге пробы.
//
// Изоляция здесь несущая, а не аккуратность: проба, заводящая репозиторий без
// неё, пишет в индекс и настройки того дерева, из которого запущена, — и дальше
// проверки, читающие дерево, выдумывают красные вердикты на целом коде.
//
// СОБСТВЕННЫЙ КАТАЛОГ ЭТОГО НЕ ОБЕСПЕЧИВАЕТ. `cmd.Dir` не выбирает репозиторий,
// когда в окружении есть `GIT_DIR`: переменная сильнее рабочего каталога.
// Прежняя редакция строила окружение от `os.Environ()` — то есть возвращала
// снятые переменные обратно и писала бы `init`, `add` и `commit` в чужую копию,
// сохраняя вид изоляции. Основа берётся у `gitenv.Env()`, а свои величины
// ДОПИСЫВАЮТСЯ.
func writeRepo(t *testing.T, commits []commit) string {
	t.Helper()
	dir := t.TempDir()
	home := t.TempDir()

	env := append(gitenv.Env(),
		"HOME="+home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, "gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
	)
	run := func(extraEnv []string, args ...string) {
		t.Helper()
		cmd := gitenv.Command(dir, args...)
		cmd.Env = append(env, extraEnv...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)
	}

	run(nil, "-c", "init.defaultBranch=main", "init", "-q")
	run(nil, "config", "commit.gpgsign", "false")
	run(nil, "config", "user.name", "fixture")
	run(nil, "config", "user.email", "fixture@example.invalid")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o750))
	for i, c := range commits {
		file := filepath.Join(dir, "src", "f.txt")
		require.NoError(t, os.WriteFile(file, []byte(strings.Repeat("x", i+1)), 0o600))
		run(nil, "add", "src/f.txt")
		run([]string{
			"GIT_AUTHOR_NAME=" + c.name,
			"GIT_AUTHOR_EMAIL=" + c.email,
			"GIT_COMMITTER_NAME=fixture",
			"GIT_COMMITTER_EMAIL=fixture@example.invalid",
		}, "commit", "-q", "--no-verify", "-m", c.message)
	}
	return dir
}

// TestGate_SummaryNamesCoordinatesEvenWhenFindingsAreMany — диагностика есть
// часть свойства, а не украшение.
//
// Заведено инъекцией на живом дереве: снятие своей личности из ведомости дало
// 928 находок, и текст отказа схлопнулся в пустоту — гейт краснел, не называя
// ни коммита, ни личности. Проба закрепляет обе половины: объём ограничен, а
// остаток назван числом, а не отброшен.
func TestGate_SummaryNamesCoordinatesEvenWhenFindingsAreMany(t *testing.T) {
	var many []commit
	for i := 0; i < 40; i++ {
		many = append(many, commit{name: "Гость", email: "guest@example.org", message: "feat: правка"})
	}
	dir := writeRepo(t, many)

	rep := inspectFixture(t, dir, minimalLedger)
	require.Len(t, rep.Findings, 40)

	got := rep.Summary(3)
	require.Contains(t, got, "находок 40", "отказ обязан называть ПОЛНОЕ число находок")
	require.Contains(t, got, "ниже первые 3", "усечение обязано быть названо, а не молчаливо")
	require.Contains(t, got, "guest@example.org", "отказ обязан называть личность")
	require.Contains(t, got, "личностей без подтверждения: 1")
	require.Contains(t, got, rep.Findings[0].Commit[:12], "отказ обязан называть координату коммита")

	// Законный близнец: на чистом дереве диагностика не выдумывает находок.
	clean := inspectFixture(t, writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "feat: правка"},
	}), minimalLedger)
	require.Equal(t, "находок нет", clean.Summary(3))
}

// TestGate_LedgerOutsideTheJudgedTreeIsRefused — ведомость, лежащая ВНЕ дерева,
// которое гейту велено судить, не читается.
//
// Предмет — не гипотетическая атака: `ledgerRel` приезжает в Inspect строкой, и
// до этой пробы ЕДИНСТВЕННЫМ, что удерживало чтение внутри дерева, была
// добросовестность вызывающего. Гейт, читающий файл за корнем, выносит вердикт
// о дереве по документу, которого в этом дереве нет, — и вердикт выглядит
// обычным.
//
// Инъекция меняет РОВНО ОДИН факт против положительного близнеца ниже: имя
// ведомости. Ведомость при этом ГОДНАЯ и ЧИТАЕМАЯ — иначе «отказано» было бы
// неотличимо от «не найдено», то есть проба зеленела бы на пустом месте.
func TestGate_LedgerOutsideTheJudgedTreeIsRefused(t *testing.T) {
	outer := t.TempDir()
	dir := filepath.Join(outer, "tree")
	require.NoError(t, os.MkdirAll(dir, 0o700))

	// Годная ведомость лежит СНАРУЖИ судимого дерева и вполне читаема.
	outside := filepath.Join(outer, "cla-ledger.yaml")
	require.NoError(t, os.WriteFile(outside, []byte(minimalLedger), 0o600))
	require.FileExists(t, outside)

	_, err := clagate.Inspect(dir, filepath.Join("..", "cla-ledger.yaml"), "HEAD")
	require.Error(t, err, "ведомость за корнем судимого дерева прочитана — "+
		"вердикт вынесен по документу, которого в этом дереве нет")
	require.Contains(t, err.Error(), "вне судимого дерева",
		"отказ не называет своей причины: читатель не отличит выход за корень от отсутствия файла")
}

// TestGate_LedgerInsideTheJudgedTreeIsRead — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ инъекции выше.
//
// Отличается ровно одним фактом — ведомость лежит ВНУТРИ дерева. Без него отказ
// зеленел бы и на проверке, отвергающей всякий путь.
func TestGate_LedgerInsideTheJudgedTreeIsRead(t *testing.T) {
	outer := t.TempDir()
	dir := filepath.Join(outer, "tree")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cla-ledger.yaml"),
		[]byte(minimalLedger), 0o600))

	_, err := clagate.Inspect(dir, "cla-ledger.yaml", "HEAD")
	// Отказ здесь БУДЕТ — каталог не репозиторий, и обход истории до него не
	// доходит. Утверждается не отсутствие отказа, а его ПРИЧИНА: ведомость,
	// лежащая внутри дерева, внешней объявлена быть не может.
	if err != nil && strings.Contains(err.Error(), "вне судимого дерева") {
		t.Fatalf("ведомость ВНУТРИ дерева отвергнута как внешняя: %v", err)
	}
}

// --- Резолв посадки: инъекция в обе стороны ---------------------------------

// TestPlacement_ModuleInsideAForeignRepositoryIsRefused — ИНЪЕКЦИЯ.
//
// Клон модуля положен внутрь ПОСТОРОННЕГО репозитория, и по вычисляемому пути
// там лежит вполне годная ведомость. Прежний резолв (подъём на четыре уровня)
// нашёл бы её и вынес бы зелёный вердикт о ЧУЖОЙ истории — отличить его от
// настоящего нечем. Здесь предпосылка проверяется, и отказ НАЗЫВАЕТ её.
//
// Против положительного близнеца ниже отличается РОВНО ОДНИМ фактом: каталог
// модуля этим репозиторием не отслеживается.
func TestPlacement_ModuleInsideAForeignRepositoryIsRefused(t *testing.T) {
	foreign := writeRepo(t, []commit{
		{name: "Чужой", email: "stranger@example.org", message: "feat: чужое дерево"},
	})

	// Модуль распакован ВНУТРЬ чужого дерева и им не отслеживается.
	mod := filepath.Join(foreign, "unpacked-module")
	require.NoError(t, os.MkdirAll(mod, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(mod, "go.mod"),
		[]byte("module example.org/unpacked\n\ngo 1.24\n"), 0o600))
	// Ведомость лежит по тому пути, который дал бы подъём литералом.
	// Имя ведомости ВЫВОДИТСЯ из объявленной координаты, а не пишется вторым
	// литералом: два места об одном имени разошлись бы молча, и фикстура тогда
	// клала бы файл мимо того пути, который резолв ищет.
	require.NoError(t, os.WriteFile(
		filepath.Join(mod, filepath.Base(ledgerRel)), []byte(minimalLedger), 0o600))

	_, err := treeroot.Locate(mod)
	require.Error(t, err, "резолв принял ЧУЖОЕ дерево за своё — вердикт был бы о его истории")
	require.Contains(t, err.Error(), "не отслеживает каталог",
		"отказ не называет предпосылки: читатель не отличит чужое дерево от отсутствия дерева")
}

// TestPlacement_ModuleTrackedByItsOwnRepositoryIsAccepted — ПОЛОЖИТЕЛЬНЫЙ
// БЛИЗНЕЦ. Отличие ровно одно: каталог модуля этим репозиторием отслеживается.
//
// Без него отказ выше зеленел бы и на резолве, отвергающем всякое дерево.
func TestPlacement_ModuleTrackedByItsOwnRepositoryIsAccepted(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "feat: своё дерево"},
	})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.org/own\n\ngo 1.24\n"), 0o600))

	pl, err := treeroot.Locate(dir)
	require.NoError(t, err, "своё дерево отвергнуто: резолв отвергает всякое, и инъекция вакуумна")
	require.Equal(t, ".", pl.ModuleDir,
		"модуль сам является корнем — путь в дереве обязан выводиться в «.», а не выписываться")
}

// TestPlacement_DirectoryOutsideAnyRepositoryIsNotAFinding — третий исход.
//
// Каталог вне всякого репозитория — «проверка НЕ ИСПОЛНЯЛАСЬ», а не находка о
// дереве: истории здесь нет by construction, и красное у всякого, кто
// распакует архив, вердиктом о продукте не является.
func TestPlacement_DirectoryOutsideAnyRepositoryIsNotAFinding(t *testing.T) {
	dir := t.TempDir()
	// Предпосылка пробы: временный каталог сам не лежит внутри репозитория.
	// Если лежит — условие не создано, и это ПРОПУСК с названной причиной, а не
	// красное: вердикт был бы о том дереве.
	for cur := dir; ; {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): временный каталог лежит внутри "+
				"репозитория %s — назовите TMPDIR вне всякого дерева", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.org/loose\n\ngo 1.24\n"), 0o600))

	_, err := treeroot.Locate(dir)
	require.ErrorIs(t, err, treeroot.ErrTreeNotResolved,
		"каталог без репозитория обязан давать «проверка НЕ ИСПОЛНЯЛАСЬ», а не находку")
}

// --- Три исхода боевого прогона: инъекция в обе стороны по каждой оси -------
//
// Ветвление живёт в `clagate.Classify`, а не в боевой пробе, ровно ради этого
// раздела: проба идёт в том дереве, в котором её запустили, поэтому доказать
// она может только ту сторону, что случилась. Здесь обе величины — посадка и
// глубина обхода — приходят аргументами, и каждая ось судится в обе стороны.
//
// Каждая инъекция ниже отличается от своего положительного близнеца РОВНО
// ОДНИМ фактом; отличие названо в заголовке пробы.

// domainHistory — отчёт дерева, историю домена НЕСУЩЕГО. Все инъекции ниже
// строятся ОТ НЕГО, чтобы отличие было ровно одно.
func domainHistory() clagate.Report {
	return clagate.Report{
		LedgerPath:      "cla-ledger.yaml",
		Scope:           []string{"."},
		RevRange:        "HEAD",
		CommitsExamined: clagate.HistoryFloorCommits + 1,
	}
}

// TestClassify_DomainHistoryIsJudgedInBothPostures — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, и
// он несущий.
//
// Без него всё, что ниже, зеленело бы на `Classify`, которая не выносит
// вердикта НИКОГДА: «пропуск там, где надо» и «пропуск всегда» неотличимы, пока
// не показано, что вердикт вообще бывает. Вторая половина — про арендатора:
// настоящий клон истории домена НЕ ЛИШЁН, и гейт обязан работать в нём как в
// монорепо, иначе третий исход съел бы ровно ту посадку, ради которой цель
// перестала быть помеченной `[монорепо]`.
func TestClassify_DomainHistoryIsJudgedInBothPostures(t *testing.T) {
	for _, inPlatformTree := range []bool{true, false} {
		outcome, why := clagate.Classify(domainHistory(), inPlatformTree)
		require.Equal(t, clagate.OutcomeJudge, outcome,
			"дерево с историей домена (посадка платформы: %t) обязано ДАВАТЬ вердикт: %s",
			inPlatformTree, why)
		require.Empty(t, why, "у вынесенного вердикта нет причины отказа — иначе она вводит в заблуждение")
	}
}

// TestClassify_ShallowWalkInThePlatformTreeIsAFinding — ИНЪЕКЦИЯ.
//
// Отличие от близнеца выше РОВНО ОДНО: обход дал ровно порог вместо порога+1.
// В дереве платформы история есть by construction, поэтому короткий обход
// означает слепоту САМОГО ОБХОДА — находку, а не свойство поставки.
func TestClassify_ShallowWalkInThePlatformTreeIsAFinding(t *testing.T) {
	rep := domainHistory()
	rep.CommitsExamined = clagate.HistoryFloorCommits

	outcome, why := clagate.Classify(rep, true)

	require.Equal(t, clagate.OutcomeBlindWalk, outcome,
		"короткий обход в дереве платформы обязан быть находкой, иначе гейт снимается срезом истории")
	require.Contains(t, why, "500", "находка обязана называть порог")
	require.Contains(t, why, "[.]", "находка обязана называть область — иначе искать нечего")
	require.Contains(t, why, "HEAD", "находка обязана называть диапазон обхода")
}

// TestClassify_ShallowWalkInAStandaloneCloneIsNotAFinding — тот же отчёт,
// отличие РОВНО ОДНО: посадка.
//
// Это и есть предмет починки: фикстура гейта самостоятельных целей — состав
// коммита, пересобранный `git init`-ом в один коммит. Истории домена у неё нет,
// и красное у неё было бы красным у всякого, кто распакует поставку.
func TestClassify_ShallowWalkInAStandaloneCloneIsNotAFinding(t *testing.T) {
	rep := domainHistory()
	rep.CommitsExamined = clagate.HistoryFloorCommits

	outcome, why := clagate.Classify(rep, false)

	require.Equal(t, clagate.OutcomeUnmetPremise, outcome,
		"дерево без истории домена обязано давать ТРЕТИЙ исход, а не вердикт о продукте")
	require.Contains(t, why, "САМОСТОЯТЕЛЬНАЯ",
		"пропуск обязан НАЗЫВАТЬ непостроенную предпосылку — иначе он неотличим от заглушенной пробы")
}

// TestClassify_BrokenPremiseInThePlatformTreeIsAFinding — ИНЪЕКЦИЯ по ВТОРОЙ
// оси: основание гейта не построено (ведомость без своих, область мимо дерева).
//
// Отличие от `domainHistory` ровно одно: непустой перечень отказов основания.
// Прежняя редакция пропускала такой прогон БЕЗУСЛОВНО — то есть гейт снимался
// поломкой собственной ведомости, молча и в монорепо.
func TestClassify_BrokenPremiseInThePlatformTreeIsAFinding(t *testing.T) {
	rep := domainHistory()
	rep.PremiseFailures = []string{`область "services/nonexistent" в дереве не разрешается`}

	outcome, why := clagate.Classify(rep, true)

	require.Equal(t, clagate.OutcomeBlindWalk, outcome,
		"поломка основания в дереве платформы обязана быть находкой, иначе гейт снимается правкой ведомости")
	require.Contains(t, why, "services/nonexistent",
		"находка обязана называть координату — иначе читатель ищет не там")
}

// TestClassify_BrokenPremiseInAStandaloneCloneIsNotAFinding — тот же отчёт,
// отличие РОВНО ОДНО: посадка.
func TestClassify_BrokenPremiseInAStandaloneCloneIsNotAFinding(t *testing.T) {
	rep := domainHistory()
	rep.PremiseFailures = []string{"у объявленных областей [.] нет ни одного коммита во всей истории"}

	outcome, why := clagate.Classify(rep, false)

	require.Equal(t, clagate.OutcomeUnmetPremise, outcome)
	require.Contains(t, why, "нет ни одного коммита",
		"пропуск обязан называть, ЧЕГО не хватило")
}

// TestClassify_TheSkipBranchIsUnreachableInThePlatformTree — НЕСУЩЕЕ
// утверждение, из которого следует «в монорепо пропущено ноль».
//
// Оно проверяется перебором форм отчёта, а не доверием к автору ветвления:
// пропуск, достижимый в дереве платформы, был бы маской — гейт снимался бы
// правкой ведомости или срезом истории, и отличить это от исправной работы
// нечем.
func TestClassify_TheSkipBranchIsUnreachableInThePlatformTree(t *testing.T) {
	shallow := domainHistory()
	shallow.CommitsExamined = 0

	broken := domainHistory()
	broken.PremiseFailures = []string{"ведомость не называет ни одной своей личности"}

	both := shallow
	both.PremiseFailures = broken.PremiseFailures

	forms := map[string]clagate.Report{
		"история домена":            domainHistory(),
		"пустой обход":              shallow,
		"основание не построено":    broken,
		"и то и другое сразу":       both,
		"область не объявлена":      {RevRange: "HEAD", PremiseFailures: []string{"ведомость не называет области"}},
		"отчёт в нулевом состоянии": {},
	}

	for name, rep := range forms {
		outcome, why := clagate.Classify(rep, true)
		require.NotEqual(t, clagate.OutcomeUnmetPremise, outcome,
			"форма отчёта %q дала в дереве платформы ПРОПУСК: %s", name, why)
	}
	require.Len(t, forms, 6, "перебор усечён — перепись форм обязана быть названа числом")
}

// TestClassify_ASnapshotRepositoryIsNotDomainHistory — та же пара, но на
// НАСТОЯЩЕМ отчёте настоящего репозитория, а не на собранном руками.
//
// Синтетический репозиторий из одного коммита — ровно то, что строит фикстура
// гейта самостоятельных целей: состав коммита, распакованный и пересобранный
// `git init`-ом. Отличие двух вызовов ниже — РОВНО ОДНО: посадка.
func TestClassify_ASnapshotRepositoryIsNotDomainHistory(t *testing.T) {
	dir := writeRepo(t, []commit{
		{name: "Свой", email: "owner@example.com", message: "самостоятельная посадка модуля"},
	})

	rep := inspectFixture(t, dir, minimalLedger)

	require.Empty(t, rep.PremiseFailures,
		"область снимка резолвится и история у него есть — предмет починки именно в этом: "+
			"нерезолв области предметом БОЛЬШЕ НЕ является")
	require.Equal(t, 1, rep.CommitsExamined,
		"снимок обязан давать ровно один коммит — иначе фикстура перестала изображать поставку")

	standalone, why := clagate.Classify(rep, false)
	require.Equal(t, clagate.OutcomeUnmetPremise, standalone,
		"снимок в самостоятельной посадке обязан давать третий исход: %s", why)

	platform, _ := clagate.Classify(rep, true)
	require.Equal(t, clagate.OutcomeBlindWalk, platform,
		"тот же отчёт в дереве платформы обязан быть НАХОДКОЙ — иначе дискриминатором служит не посадка")
}
