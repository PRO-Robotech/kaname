// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// Доказательство способности гейта датировки УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем дереве, и это не говорит ничего о том, умеет ли
// он краснеть. Здесь ему подаются СИНТЕТИЧЕСКИЕ тексты: по одному дефекту на
// каждую ось, и рядом с каждым — законный близнец, на котором гейт обязан
// молчать. Инъекция снимает РОВНО одно свойство: остальные оси в каждой пробе
// целы, иначе красное приходило бы от соседнего требования.

const (
	// synthDated — законное объявление: ревизия названа хешем.
	synthDated = "## 4. Полосы\n\n**Замер на ревизии `1234abc`** (единица счёта — вызовы):\n\n" +
		"```sh\ngit grep -c foo -- 'services/iam/**'   # 7\n```\n"
	// synthUndated — тот же замер, датированный самоссылкой.
	synthUndated = "## 4. Полосы\n\n**Замер на ревизии записи** (единица счёта — вызовы):\n\n" +
		"```sh\ngit grep -c foo -- 'services/iam/**'   # 7\n```\n"
	// synthForeign — ревизия названа, но в историю дерева не входит.
	synthForeign = "Замер на ревизии `deadbee` — таких мест **2**.\n"
	// synthQuoted — ПРОЗА О ФОРМЕ: законный близнец, замером не является.
	synthQuoted = "> Здесь стояло «замер на ревизии записи» — самоссылкой, восстановимой\n" +
		"> только раскопками. Оборот «замер на ревизии записи» назван, чтобы его узнавали.\n"
	// synthNoMarker — соседний документ без предмета.
	synthNoMarker = "## 1. Норма\n\nПеречень выводится из дерева, а не выписывается.\n"

	// synthCalloutDeclaration — НОВАЯ ФОРМА, которой образец прежде НЕ ВИДЕЛ:
	// объявление замера внутри выноски. Знак `>` уводил такую строку в счётчик
	// прозы, и находка внутри неё была невидима — ни красного, ни зелёного.
	// Датирована ЧУЖОЙ линией: снято РОВНО одно свойство — видимость формы.
	synthCalloutDeclaration = "> [!note] Разбор расхождения\n" +
		"> Замер на ревизии `deadbee` (единица счёта — вызовы): таких мест **2**.\n"

	// synthCalloutLawful — ЗАКОННЫЙ БЛИЗНЕЦ той же формы: та же выноска, тот же
	// знак `>`, ревизия названа хешем и в историю входит. Гейт обязан молчать —
	// иначе он ловит выноску, а не негодную датировку.
	synthCalloutLawful = "> [!note] Разбор расхождения\n" +
		"> Замер на ревизии `1234abc` (единица счёта — вызовы): таких мест **2**.\n"

	// synthCalloutProse — ЗАКОННЫЙ БЛИЗНЕЦ второго рода: та же выноска, но оборот
	// взят в ёлочки, то есть это разговор О ФОРМЕ. Величина переписи, не находка.
	synthCalloutProse = "> [!note] Здесь стояло «замер на ревизии записи» — самоссылкой,\n" +
		"> восстановимой только раскопками по истории.\n"
)

// ancestryAll — все ревизии в истории (законное дерево).
func ancestryAll(string) ancestryVerdict { return ancestryYes }

// ancestryForeign — `deadbee` резолвится, но предком не является: ровно тот
// случай, на котором предикат «резолвится» отвечает «да», а годный — «нет».
func ancestryForeign(hash string) ancestryVerdict {
	if hash == "deadbee" {
		return ancestryNo
	}
	return ancestryYes
}

func synthDocs() map[string]string {
	return map[string]string{
		"architecture/known-divergences.md": synthDated,
		"acceptance/roles.md":               synthNoMarker,
	}
}

// TestDatingGateIsSilentOnTheLawfulCorpus — положительный контроль.
// Без него отрицания ниже зеленели бы на чём угодно.
func TestDatingGateIsSilentOnTheLawfulCorpus(t *testing.T) {
	findings, c := auditMeasurementDating(synthDocs(), map[string]string{}, ancestryAll)

	require.Empty(t, findings, "гейт краснеет на законном корпусе — отрицания ниже ничего не докажут")
	require.Equal(t, 2, c.docsRead)
	require.Equal(t, 1, c.markers, "объявление замера обязано быть найдено")
	require.Equal(t, 1, c.dated)
	require.Zero(t, c.undated)
	require.Zero(t, c.foreign)
}

// TestDatingGateRedsOnSelfReference — ось «самоссылка».
func TestDatingGateRedsOnSelfReference(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthUndated

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAll)

	require.Len(t, findings, 1, "недатированный замер оставил гейт зелёным")
	require.Contains(t, findings[0], "САМОССЫЛКА")
	require.Contains(t, findings[0], "architecture/known-divergences.md")
	require.Equal(t, 1, c.undated)
	require.Zero(t, c.dated, "вторая ось цела: красное пришло РОВНО от снятого")
}

// TestDatingGateRedsOnAForeignLineRevision — ось «резолвится, но не предок».
// Это и есть предмет находки B задачи #1805.
func TestDatingGateRedsOnAForeignLineRevision(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthForeign

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryForeign)

	require.Len(t, findings, 1, "ревизия чужой линии оставила гейт зелёным")
	require.Contains(t, findings[0], "ЧУЖАЯ ЛИНИЯ")
	require.Contains(t, findings[0], "deadbee")
	require.Equal(t, 1, c.foreign)
	require.Zero(t, c.undated, "вторая ось цела")
}

// TestDatingGateIsSilentOnProseAboutTheForm — ЗАКОННЫЙ БЛИЗНЕЦ.
// Проверка, краснеющая на собственном объяснении, и есть ловимый здесь класс.
func TestDatingGateIsSilentOnProseAboutTheForm(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthNoMarker + synthQuoted

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAll)

	require.Empty(t, findings, "гейт покраснел на прозе О ФОРМЕ — он судит слово, а не объявление")
	require.Equal(t, 2, c.quoted, "цитаты обязаны быть СОСЧИТАНЫ, а не невидимы")
	require.Equal(t, 1, c.markers, "объявление соседнего документа осталось видимым")
}

// TestDatingGateForgivesOnlyWhatTheLedgerNames — ведомость применяется.
func TestDatingGateForgivesOnlyWhatTheLedgerNames(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthUndated
	ledger := map[string]string{"acceptance/roles.md": "APPROVED-приёмка, задача #0000"}

	findings, c := auditMeasurementDating(docs, ledger, ancestryAll)

	require.Empty(t, findings, "запись ведомости не применилась к своему предмету")
	require.Equal(t, 1, c.ledgerApplied)
	require.Equal(t, 1, c.undated)
}

// TestDatingLedgerSelfExpires — послабление обязано ИСТЕЧЬ САМО.
// Запись, которой больше нечего прощать, — находка, а не тишина.
func TestDatingLedgerSelfExpires(t *testing.T) {
	ledger := map[string]string{"acceptance/roles.md": "APPROVED-приёмка, задача #0000"}

	findings, c := auditMeasurementDating(synthDocs(), ledger, ancestryAll)

	require.Len(t, findings, 1, "ведомость пережила свой предмет молча")
	require.Contains(t, findings[0], "ВЕДОМОСТИ НЕЧЕГО ПРОЩАТЬ")
	require.Zero(t, c.ledgerApplied)
	require.Equal(t, 1, c.ledgerEntries)
}

// TestDatingGateCountsUnjudgedAncestrySeparately — ТРЕТЬЯ КАТЕГОРИЯ.
// «Не выполнилось» не вычитается из вердикта и не зачитывается в успех.
func TestDatingGateCountsUnjudgedAncestrySeparately(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthForeign

	findings, c := auditMeasurementDating(docs, map[string]string{},
		func(string) ancestryVerdict { return ancestryUnjudged })

	require.Empty(t, findings, "невынесенный вердикт о предке подан как находка")
	require.Equal(t, 1, c.ancestryUnjudged, "невынесенный вердикт обязан быть НАЗВАН, а не проглочен")
	require.Equal(t, 1, c.dated, "хеш назван — эта ось пройдена независимо от вердикта о предке")
}

// --- Слепая зона выноски: расширение образца доказывается тремя прогонами ---
//
// Прежний образец выводил из-под суда ВСЯКУЮ строку, открытую знаком `>`.
// Выноска — обычная форма этого корпуса, поэтому объявление внутри неё было
// невидимо: не находка и не тишина, а отсутствие вопроса. Ниже — контроль,
// инъекция и законный близнец той же формы.

// TestDatingGateIsSilentOnALawfulCalloutDeclaration — КОНТРОЛЬ.
// Объявление в выноске, датированное годно, обязано быть УВИДЕНО и пропущено.
func TestDatingGateIsSilentOnALawfulCalloutDeclaration(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthNoMarker + synthCalloutLawful

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAll)

	require.Empty(t, findings, "гейт краснеет на годном объявлении в выноске")
	require.Equal(t, 2, c.markers, "объявление в выноске обязано быть УВИДЕНО, а не сочтено прозой")
	require.Equal(t, 2, c.dated)
	require.Zero(t, c.quoted, "ёлочек здесь нет — прозой это не является")
}

// TestDatingGateRedsOnAForeignRevisionInsideACallout — ИНЪЕКЦИЯ НОВОЙ ФОРМЫ.
// Ровно тот случай, что жил в дереве незамеченным: приёмка ролей манифеста
// датировала замер ревизией чужой линии внутри выноски.
func TestDatingGateRedsOnAForeignRevisionInsideACallout(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthNoMarker + synthCalloutDeclaration

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryForeign)

	require.Len(t, findings, 1, "объявление внутри выноски осталось невидимым — слепая зона вернулась")
	require.Contains(t, findings[0], "ЧУЖАЯ ЛИНИЯ")
	require.Contains(t, findings[0], "acceptance/roles.md", "находка обязана НАЗВАТЬ координату")
	require.Contains(t, findings[0], "deadbee")
	require.Equal(t, 1, c.foreign)
	require.Zero(t, c.undated, "соседние оси целы: красное пришло РОВНО от снятого")
}

// TestDatingGateIsSilentOnProseInsideACallout — ЗАКОННЫЙ БЛИЗНЕЦ.
// Та же выноска, тот же знак `>` — но оборот в ёлочках. Проверка, краснеющая на
// собственном объяснении, и есть ловимый здесь класс.
func TestDatingGateIsSilentOnProseInsideACallout(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthNoMarker + synthCalloutProse

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAll)

	require.Empty(t, findings, "гейт покраснел на прозе О ФОРМЕ — он судит знак цитаты, а не объявление")
	require.Equal(t, 1, c.quoted, "цитата обязана быть СОСЧИТАНА, а не невидима")
	require.Equal(t, 1, c.markers, "объявление соседнего документа осталось видимым")
}

// --- Историй ДВЕ: своя и предшественника -------------------------------------
//
// Ось заведена задачей #2554. Прежняя редакция знала два положения хеша вместо
// четырёх и сваливала «не резолвится вовсе» в «резолвится, но не предок», печатая
// про первое текст второго. Ниже — контроль, инъекция по каждому новому положению
// и законный близнец на каждой оси.

const (
	// synthInherited — ЗАКОННАЯ датировка ревизией предшественника: история названа
	// ВМЕСТЕ с ревизией, поэтому читателю сказано, где число перемерить.
	synthInherited = "**Замер на ревизии `PRO-Robotech/kacho@2171a6690a`** — в МОНОРЕПО " +
		"(предикат называет путь `services/iam/**`): таких мест **2**.\n"

	// synthUndeclaredHistory — ИНЪЕКЦИЯ: та же форма, но назван репозиторий, который
	// предшественником этой службы не объявлен. Отличается от близнеца выше РОВНО
	// ОДНИМ фактом — именем репозитория.
	synthUndeclaredHistory = "**Замер на ревизии `Some-Other/repo@2171a6690a`** — в чужом " +
		"дереве: таких мест **2**.\n"
)

// ancestryAbsentFor — `deadbee` не резолвится ВОВСЕ, а история дерева при этом наша.
// Положение, которого прежняя редакция не различала.
func ancestryAbsentFor(hash string) ancestryVerdict {
	if hash == "deadbee" {
		return ancestryAbsent
	}
	return ancestryYes
}

// TestDatingGateCountsAnInheritedDatingSeparately — КОНТРОЛЬ новой оси.
//
// Утверждение `dated == 0` здесь несущее: им доказывается, что образцы простого и
// квалифицированного хеша НЕ ПЕРЕСЕКАЮТСЯ. Пересекись они — квалифицированная
// цитата ушла бы в половину «предок», и своё дерево спрашивали бы о ревизии, которой
// в нём нет by construction, то есть находка приходила бы на законном входе.
func TestDatingGateCountsAnInheritedDatingSeparately(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthInherited

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAbsentFor)

	require.Empty(t, findings, "гейт краснеет на законной датировке ревизией предшественника")
	require.Equal(t, 1, c.markers, "объявление обязано быть УВИДЕНО, а не пропущено")
	require.Equal(t, 1, c.inherited, "унаследованная датировка обязана быть СОСЧИТАНА, а не невидима")
	require.Zero(t, c.dated, "квалифицированная цитата ушла в половину «предок» — образцы пересеклись")
	require.Zero(t, c.absent, "своё дерево спросили о ревизии чужой истории")
	require.Zero(t, c.undated, "квалифицированная цитата принята за самоссылку")
}

// TestDatingGateRedsOnAnUndeclaredHistory — ИНЪЕКЦИЯ: предшественник объявлен ОДИН.
// Иначе форма стала бы способом сослаться куда угодно и тем снять вопрос.
func TestDatingGateRedsOnAnUndeclaredHistory(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthUndeclaredHistory

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAbsentFor)

	require.Len(t, findings, 1, "цитата необъявленной истории оставила гейт зелёным")
	require.Contains(t, findings[0], "НЕОБЪЯВЛЕННАЯ ИСТОРИЯ")
	require.Contains(t, findings[0], "architecture/known-divergences.md", "находка обязана НАЗВАТЬ координату")
	require.Contains(t, findings[0], "Some-Other/repo")
	require.Zero(t, c.inherited, "чужая история зачтена как история предшественника")
	require.Zero(t, c.undated, "соседние оси целы: красное пришло РОВНО от снятого")
}

// TestDatingGateRedsOnARevisionAbsentFromThisHistory — ИНЪЕКЦИЯ нового положения:
// хеш назван, история дерева наша, а такой точки в ней нет вовсе.
func TestDatingGateRedsOnARevisionAbsentFromThisHistory(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthForeign

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAbsentFor)

	require.Len(t, findings, 1, "отсутствующая в истории ревизия оставила гейт зелёным")
	require.Contains(t, findings[0], "РЕВИЗИИ НЕТ В ЭТОЙ ИСТОРИИ")
	require.Contains(t, findings[0], "deadbee")
	require.Contains(t, findings[0], "PRO-Robotech/kacho@", "находка обязана сказать, КАК записать чужую ревизию")
	require.Equal(t, 1, c.absent)
	require.Zero(t, c.foreign, "два положения слились обратно в одно")
	require.Zero(t, c.undated, "соседние оси целы")
}

// TestDatingGateTellsAbsentApartFromAForeignLine — НЕСУЩЕЕ про ДИАГНОСТИКУ.
//
// Один и тот же текст, две РАЗНЫЕ причины: сообщение обязано называть ту, которая
// случилась. Прежняя редакция печатала «которая РЕЗОЛВИТСЯ» на обеих, и читатель
// сверял предка вместо того, чтобы увидеть чужой репозиторий.
func TestDatingGateTellsAbsentApartFromAForeignLine(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthForeign

	foreignFindings, _ := auditMeasurementDating(docs, map[string]string{}, ancestryForeign)
	absentFindings, _ := auditMeasurementDating(docs, map[string]string{}, ancestryAbsentFor)

	require.Len(t, foreignFindings, 1)
	require.Len(t, absentFindings, 1)
	require.NotEqual(t, foreignFindings[0], absentFindings[0],
		"два разных положения дали ОДИН текст — диагностика называет причину, которой не было")
	require.Contains(t, foreignFindings[0], "РЕЗОЛВИТСЯ")
	require.NotContains(t, absentFindings[0], "которая РЕЗОЛВИТСЯ",
		"на не резолвящейся ревизии напечатано, что она резолвится")
}

// --- Ось «предок» на НАСТОЯЩЕМ git: прежде не покрыта ни одной стороной -------
//
// Десять проб выше подают ПОДДЕЛЬНЫЙ предикат, поэтому о `gitAncestry` они не
// утверждают ничего. Ниже настоящая функция гоняется на синтетических деревьях.
//
// Пропуска здесь НЕТ намеренно: репозиторий заводится своим `git init`, поэтому
// объемлющее дерево на исход не влияет, а ветвь пропуска, которая не может
// понадобиться, сама была бы маской.

// synthRepo — синтетическое дерево: три коммита на `main` и один В СТОРОНЕ.
type synthRepo struct {
	dir    string
	root   string // первый коммит: им объявляется «история этого дерева»
	middle string // коммит внутри истории HEAD
	head   string // вершина `main`
	aside  string // резолвится, предком HEAD НЕ является
}

// absentRevision — правильной формы хеш, которого нет ни в одном дереве.
const absentRevision = "0123456789abcdef0123456789abcdef01234567"

func buildSynthRepo(t *testing.T, dir string) synthRepo {
	t.Helper()
	env := append(gitenv.Env(),
		"GIT_AUTHOR_NAME=probe", "GIT_AUTHOR_EMAIL=probe@invalid",
		"GIT_COMMITTER_NAME=probe", "GIT_COMMITTER_EMAIL=probe@invalid")
	git := func(args ...string) string {
		c := gitenv.Command(dir, args...)
		c.Env = env
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(name, body string) string {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		git("add", name)
		git("commit", "--quiet", "-m", name+":"+body)
		return git("rev-parse", "HEAD")
	}

	git("init", "--quiet", "-b", "main")
	r := synthRepo{dir: dir}
	r.root = commit("a.txt", "1")
	r.middle = commit("a.txt", "2")
	git("checkout", "--quiet", "-b", "side")
	r.aside = commit("b.txt", "s")
	git("checkout", "--quiet", "main")
	r.head = commit("a.txt", "3")
	return r
}

// TestGitAncestry_JudgesFourPositionsOnATreeCarryingTheDeclaredHistory — КОНТРОЛЬ.
// Дерево несёт объявленную историю, и все четыре положения РАЗЛИЧАЮТСЯ.
func TestGitAncestry_JudgesFourPositionsOnATreeCarryingTheDeclaredHistory(t *testing.T) {
	r := buildSynthRepo(t, t.TempDir())
	ancestry := gitAncestry(t, r.dir, r.root)

	require.Equal(t, ancestryYes, ancestry(r.middle), "коммит внутри истории HEAD не признан предком")
	require.Equal(t, ancestryYes, ancestry(r.head), "вершина не признана предком самой себя")
	require.Equal(t, ancestryNo, ancestry(r.aside),
		"коммит в стороне признан предком — предикат «резолвится» подменил предикат «входит в историю»")
	require.Equal(t, ancestryAbsent, ancestry(absentRevision),
		"не резолвящаяся ревизия не отличена от резолвящейся: диагностика назовёт ложную причину")
}

// TestGitAncestry_RendersNoVerdictWithoutTheDeclaredHistory — ИНЪЕКЦИЯ.
// Отличается от близнеца выше РОВНО ОДНИМ фактом: какая история объявлена. Дерево
// то же, коммиты те же — объявленного корня в нём нет, и это поставка модуля.
func TestGitAncestry_RendersNoVerdictWithoutTheDeclaredHistory(t *testing.T) {
	r := buildSynthRepo(t, t.TempDir())
	ancestry := gitAncestry(t, r.dir, absentRevision)

	require.Equal(t, ancestryUnjudged, ancestry(absentRevision),
		"дерево без объявленной истории вынесло вердикт об отсутствующей ревизии — "+
			"каждый замер стал бы находкой у каждого, кто склонирует поставку")
}

// TestGitAncestry_AResolvingRevisionIsJudgedEvenWithoutTheDeclaredHistory —
// ЗАКОННЫЙ БЛИЗНЕЦ инъекции выше: новое различение НИЧЕГО НЕ ОТНИМАЕТ у прежней
// половины. Объявленной истории в дереве нет, но резолвящийся коммит в стороне
// по-прежнему находка — иначе починка одной оси погасила бы соседнюю молча.
func TestGitAncestry_AResolvingRevisionIsJudgedEvenWithoutTheDeclaredHistory(t *testing.T) {
	r := buildSynthRepo(t, t.TempDir())
	ancestry := gitAncestry(t, r.dir, absentRevision)

	require.Equal(t, ancestryNo, ancestry(r.aside),
		"прежняя половина «резолвится, но не предок» погасла вместе с объявлением истории")
	require.Equal(t, ancestryYes, ancestry(r.middle),
		"предок перестал быть предком из-за того, что история не объявлена")
}

// TestDeclaredServiceHistoryRootIsCarriedByThisTree — объявленный факт НЕ ГНИЁТ.
//
// Константа с одним держателем всё равно стареет молча, если её никто не сверяет с
// деревом. Оба исхода законны — но обязаны РАЗЛИЧАТЬСЯ и быть НАЗВАННЫМИ: дерево
// либо несёт объявленную историю (и тогда гейт вооружён), либо не несёт (поставка,
// усечённый клон), и тогда он вердикта не выносит и говорит это в переписи.
func TestDeclaredServiceHistoryRootIsCarriedByThisTree(t *testing.T) {
	root := monorepoRoot(t)
	git := func(args ...string) (string, error) {
		out, err := gitenv.Command(root, args...).Output()
		return strings.TrimSpace(string(out)), err
	}

	if _, err := git("cat-file", "-e", serviceHistoryRoot+"^{commit}"); err != nil {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): объявленный корень %s в этом дереве не "+
			"резолвится — поставка модуля либо усечённый клон. Гейт датировки вердикта об "+
			"отсутствующей ревизии здесь не выносит, и это сказано в его переписи",
			serviceHistoryRoot)
	}

	parents, err := git("show", "-s", "--format=%P", serviceHistoryRoot)
	require.NoError(t, err, "проба НЕ ИСПОЛНЯЛАСЬ")
	require.Empty(t, parents,
		"объявленный корень истории имеет родителя (%q) — значит корнем он не является, "+
			"и довод «неизменяем by construction» под ним не стоит", parents)

	_, err = git("merge-base", "--is-ancestor", serviceHistoryRoot, "HEAD")
	require.NoError(t, err,
		"объявленный корень %s резолвится, но предком HEAD не является — дерево несёт ЧУЖУЮ "+
			"историю, и гейт датировки здесь молча разоружён", serviceHistoryRoot)
	t.Logf("объявленная история сверена с деревом: корень %s не имеет родителей и является предком HEAD, "+
		"вердикт об отсутствующей ревизии ВЫНОСИТСЯ", serviceHistoryRoot)
}
