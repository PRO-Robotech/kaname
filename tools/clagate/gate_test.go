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

	"github.com/PRO-Robotech/kacho-iam/tools/clagate"
)

// repoRoot — корень дерева продукта (пакет лежит в services/iam/tools/clagate).
const repoRoot = "../../../.."

// ledgerPath — ведомость, объявляющая своих, подписавших и машинные личности.
const ledgerPath = "services/iam/cla-ledger.yaml"

// TestGate_IamHistoryIsConfirmed — боевой прогон по истории домена.
//
// Перепись здесь не украшение, а отдельное утверждение: «ноль находок» обязано
// быть отличимо от «ноль прочитанного». Поэтому проверяются ОБЕ величины —
// сколько осмотрено и сколько найдено.
func TestGate_IamHistoryIsConfirmed(t *testing.T) {
	rep, err := clagate.Inspect(repoRoot, ledgerPath, "HEAD")
	require.NoError(t, err)

	require.Empty(t, rep.PremiseFailures,
		"предпосылка гейта перестала быть верной: %v", rep.PremiseFailures)

	require.Greater(t, rep.CommitsExamined, 500,
		"осмотрено %d коммитов — это не похоже на историю домена: обход усечён или область объявлена мимо дерева",
		rep.CommitsExamined)
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

	t.Logf("осмотрено: коммитов=%d, вкладов(коммит×личность)=%d, личностей=%d; "+
		"свои=%d, подписью=%d, ведомостью=%d, освобождено=%d",
		rep.CommitsExamined, rep.ContributionsInspected, rep.IdentitiesSeen,
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
