// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// history_question_vertex_test.go — ГЕЙТ КЛАССА: вопрос об истории задаётся
// СТВОЛУ, а не рабочей вершине (задача PRO-Robotech/kaname#63).
//
// Предмет, перечень глаголов и границы разбора — в шапке
// `history_question_vertex.go`; здесь они не пересказываются.
//
// # ЧТО ТРЕБУЕТ ГЕЙТ
//
// Вопрос об истории, чья вершина НЕ СТВОЛ, обязан нести записанный довод. Два
// состояния, оба требуют записи, и второе не мягче первого:
//
//   - вершина названа рабочей (`HEAD`) — вердикт до вливания и после него
//     относится к РАЗНЫМ деревьям;
//   - вершина не названа литералом (переменная либо умолчание: `git log` без
//     ревизии есть `git log HEAD`) — тогда «судит ствол или вершину» вообще
//     никем не сказано, и молчание здесь стоит дороже находки.
//
// # ПЕРЕПИСЬ ЗАДАЧИ #63 — ОНА ЖЕ ВЕДОМОСТЬ, А НЕ ВТОРОЕ МЕСТО О НЕЙ
//
// Задача просит переписи: «по каждой сказано, судит она ствол или рабочую
// вершину, и если вторую — назван довод». Перепись прозой разошлась бы с деревом
// молча, поэтому она записана ВЕДОМОСТЬЮ ниже: каждая запись держит свой довод,
// своё точное число вызовов и самоистекает — запись, которой нечего прощать,
// находка.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// history_question_vertex_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// historyTrunkRefs — имена, объявленные в этом дереве СТВОЛОМ.
//
// Перечень один на гейт и совпадает с тем, что объявляют сами проверки
// (`serviceTrunkRef`, `trunkRefName`). Второй копией это не становится: там
// объявлено, ЧЕМ судить, здесь — что считать стволом при чтении; разойтись они
// не могут, потому что расхождение и есть находка этого гейта.
var historyTrunkRefs = []string{"origin/main"}

// historyCorpusSuffixes — языки, в которых вызов git в этом дереве встречается.
// Перечень ВЫПИСАН, а не выведен: обход отвечает «что там лежит», а вопрос здесь
// обратный — «где мы вообще смотрим». Пустой каталог обход прошёл бы молча.
var historyCorpusSuffixes = []string{".go", ".sh", ".py", ".yml", ".yaml", ".mk", "Makefile"}

// vertexWaiver — запись ведомости: почему вопрос задан ИМЕННО этой вершине.
type vertexWaiver struct {
	// Why — довод. Не «так исторически», а свойство ПРЕДМЕТА вопроса.
	Why string
	// Issue — номер задачи, если это НЕ довод, а отсрочка: вершина выбрана
	// неверно, предмет заведён, правка идёт своим изменением. Ноль означает
	// довод; ненулевое печатается переписью ОТДЕЛЬНОЙ величиной, чтобы
	// отсрочка не пряталась среди доводов.
	Issue int
	// Calls — сколько вызовов запись прощает. ТОЧНОЕ число, а не потолок:
	// потолок не краснеет никогда и потому не истекает. Появился в файле новый
	// вызов тем же глаголом — число разошлось, и адъюдикация названа устаревшей.
	Calls int
}

// vertexLedger — ПЕРЕПИСЬ задачи #63, машинно удерживаемая.
//
// Ключ — `файл#глагол`: он переживает движение строк, а номер строки не
// переживает. Файл с двумя вызовами одного глагола прощается ОДНОЙ записью с
// числом 2 — и третий вызов сделает число неверным.
func vertexLedger() map[string]vertexWaiver {
	return map[string]vertexWaiver{
		// ── ВЕРШИНА НАЗВАНА РАБОЧЕЙ ────────────────────────────────────────────
		"internal/check/docs_measurement_dating_injection_test.go#merge-base": {Calls: 1,
			Why: "предмет вопроса — САМО ДЕРЕВО ПРОГОНА: несёт ли этот чекаут объявленную " +
				"историю службы. Корень истории предок и ствола, и рабочей вершины в любом " +
				"клоне этого репозитория; спрашивать ствол значило бы требовать ссылки на " +
				"origin там, где вопрос про локальный состав объектов"},
		"internal/check/docs_measurement_dating_test.go#rev-list": {Calls: 1,
			Why: "граница усечения — свойство ЭТОГО клона, а не посадки: `--max-parents=0 HEAD` " +
				"ищет самую старую доступную точку выборки. У ствола она та же либо недостижима"},
		"internal/check/migration_not_a_writer_of_module_role_test.go#diff": {Calls: 1,
			Why: "предмет — САМО ИЗМЕНЕНИЕ (`<ствол>...HEAD`), а не дерево. Состав добавленного " +
				"живёт между стволом и рабочей вершиной by construction; вершина здесь — второй " +
				"операнд диапазона, и стволом он быть не может, иначе диапазон пуст всегда"},

		// ── ВЕРШИНА ЛИТЕРАЛОМ НЕ НАЗВАНА ──────────────────────────────────────
		"internal/check/acceptance_edit_after_verdict.go#log": {Calls: 3,
			Why: "вершина умолчания (`git log` без ревизии), и это ВЕРНО: вопрос сравнивает " +
				"ПОРЯДОК ДВУХ правок внутри одной истории, а не принадлежность названной " +
				"ревизии. Схлопывание двигает оба операнда вместе, поэтому зелёное полосы " +
				"красным ствола не становится НИ В ОДНОЙ посадке — замерено тремя посадками " +
				"(`TestSquashNeverTurnsAGreenLaneIntoARedTrunk`). Обратное направление " +
				"названо там же и прощено: документ, рождённый полосой, после схлопывания " +
				"получает одну отметку на оба операнда, и находка исчезает — цена того, что " +
				"предикат сравнивает отметки, а не ревизии"},
		"internal/check/docs_measurement_dating_test.go#merge-base": {Calls: 2,
			Why: "вершина — ПАРАМЕТР `trunk`, и её единственный держатель `serviceTrunkRef` " +
				"объявлен стволом. Параметром она стала намеренно: иначе ось «ствол или вершина» " +
				"нечем подать синтетике, и она осталась бы без доказательства падучести"},
		"internal/check/docs_measurement_dating_test.go#cat-file": {Calls: 1,
			Why: "вопрос о РЕЗОЛВЕ объекта, а не о вхождении: вершины у него нет by construction. " +
				"Вхождение спрашивается следующим оператором — у `merge-base` выше"},
		"internal/check/docs_measurement_dating_test.go#rev-parse": {Calls: 1,
			Why: "`--verify` над самой ссылкой ствола: это и есть проверка, разрешается ли ствол " +
				"в этом клоне. Аргумент — постоянная `serviceTrunkRef` со склейкой `^{commit}`"},
		"internal/check/docs_measurement_dating_injection_test.go#cat-file": {Calls: 1,
			Why: "тот же резолв объявленного корня истории, что и у гейта: предпосылка, а не " +
				"вхождение"},
		"internal/check/history_question_vertex_injection_test.go#log": {Calls: 3,
			Why: "вершина — СИНТЕТИЧЕСКИЙ репозиторий, который фикстура строит сама, и ставит " +
				"её она переключением ветки: сперва полоса, затем ствол после схлопывания. " +
				"Вершина здесь и есть предмет замера, а ствола `origin/main` в таком дереве " +
				"нет вовсе — спрашивать о нём было бы вопросом к тому, чего фикстура не заводит",
		},
		// ── ЗАПИСИ РЕВЬЮ: предмет вопроса — ветка PR и её сливаемость в линию ────
		"docs/specs/reviews/passwordless-login-with-access-key/833470690aff167314d54fec332810f34c3aab2e4574a0e3e871ee9184841099.yaml#diff": {Calls: 1,
			Why: "рецензент сверяет ДВЕ РЕДАКЦИИ одного документа внутри ветки PR (прежняя " +
				"голова → новая): оба операнда — ревизии полосы by construction, ствол ни " +
				"одной из них не является — в стволе этой редакции ещё нет"},
		"docs/specs/reviews/passwordless-login-with-access-key/833470690aff167314d54fec332810f34c3aab2e4574a0e3e871ee9184841099.yaml#merge-base": {Calls: 1,
			Why: "вопрос о СЛИВАЕМОСТИ ветки PR в накопительную линию: оба операнда названы " +
				"(`origin/release/iam-lines`, ветка приёмки) и стволом быть не могут — база " +
				"PR здесь линия, не ствол, по решению владельца об одном MR"},
		// ── ЗАПИСИ РЕВЬЮ: предмет вопроса — ДЕЛЬТА ДВУХ РЕДАКЦИЙ ОДНОЙ ВЕТКИ ─────
		"docs/specs/reviews/login-lane-issues-our-session-and-logout-ends-it-server-side/4ee03c398152d87b4cdb74646b2ca34a513476d8d4e31799fec4f453d541cd22.yaml#diff": {Calls: 1,
			Why: "рецензент сверяет ДВЕ РЕДАКЦИИ одного документа внутри ветки PR (прежняя " +
				"голова → новая): оба операнда — ревизии полосы by construction, и ствол ни " +
				"одной из них быть не может — в стволе этой редакции ещё нет. Схлопывание " +
				"переносит обе в один коммит, и вопрос теряет предмет вместе с ветвью, а не " +
				"меняет ответ"},
		// ── ЗАПИСИ РЕВЬЮ: предмет вопроса — ЛЕЖИТ ЛИ РЕДАКЦИЯ В НАКОПИТЕЛЬНОЙ ЛИНИИ ──
		"docs/specs/reviews/second-factor-totp-and-recovery-codes/06984af979a6d7a1ca384e5d356d075627cb9a2c56a42942dff75a17a5fae1ad.yaml#merge-base": {Calls: 2,
			Why: "рецензент устанавливает, что редакция 6 (769aa56a) и её реализация (вливание " +
				"92695c64 PR kaname#228) лежат в накопительной линии `origin/release/iam-lines` — " +
				"базе ветки полосы по решению владельца об одном MR. Ствол операндом быть не " +
				"может: в стволе этой редакции ещё нет (тот же документ там — редакция 5, " +
				"b71c3ff7…), и вопрос стволу отвечен в той же записи отдельной строкой (→ 1). " +
				"Два вызова — два предмета: редакция и её реализация"},
		"docs/specs/reviews/second-factor-totp-and-recovery-codes/6bc95772bcb5b9f2f2db0789aefca17513a4d21e626b5827011094313f9176ea.yaml#merge-base": {Calls: 2,
			Why: "рецензент круга 4 устанавливает провенанс редакции 7 (74a0f1a1): она лежит " +
				"ПОВЕРХ головы накопительной линии `origin/release/iam-lines` (7c3b493d — её " +
				"предок) и в самой линии ещё не лежит (PR не открыт). Ни один из двух вопросов " +
				"стволу не задаётся by construction: ствол несёт редакцию 5, линия — редакцию 6, " +
				"а редакция 7 — только ветка задачи; вопрос стволу отвечен в той же записи " +
				"отдельной строкой (→ 1). Два вызова — два предмета: база и линия"},
		"internal/check/probe_home.go#cat-file": {Calls: 1,
			Why: "судится ЧУЖОЙ дом по НАЗВАННОЙ ревизии, и вершина приходит параметром. " +
				"Умолчание параметра — ствол чужого дома (`HomeRef` возвращает `origin/main`), " +
				"то есть вопрос и так задан стволу, только не своему"},
	}
}

// TestHistoryQuestionsAreAskedOfTheTrunk — несущее утверждение.
func TestHistoryQuestionsAreAskedOfTheTrunk(t *testing.T) {
	t.Parallel()

	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	corpus := readHistoryCorpus(t, corpusRoot, ownDir)
	if len(corpus) == 0 {
		t.Fatalf("обход дерева %s пуст — вердикт беспредметен: «ноль находок» означало бы "+
			"«ноль прочитанного»", ownDir)
	}

	questions, c := check.ScanHistoryQuestions(corpus, historyTrunkRefs)
	findings, applied, stale := judgeHistoryVertices(questions, vertexLedger())

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: файлов прочитано %d · Go разобрано %d · не разобрано %d · "+
		"строк комментария снято %d · глагол вне запускателя %d · вопросов об истории %d · "+
		"ствол %d · рабочая вершина %d · вершина не названа %d · по глаголам %s · "+
		"записей ведомости %d (применено %d, из них отсрочек %d) · находок %d",
		c.FilesRead, c.GoParsed, len(c.GoUnparsed), c.LinesStripped, c.VerbOutsideRunner,
		c.Questions, c.Trunk, c.Head, c.Unnamed, censusByVerb(c), len(vertexLedger()), applied,
		countDeferrals(vertexLedger()), len(findings))

	// ПРЕДПОСЫЛКИ ГЕЙТА — каждая своим утверждением, а не одной строкой.
	if len(c.GoUnparsed) > 0 {
		t.Fatalf("файлов Go не разобрано %d (%s) — неразобранный файл НЕВИДИМ, и его молчание "+
			"неотличимо от чистоты", len(c.GoUnparsed), strings.Join(c.GoUnparsed, ", "))
	}
	if c.Questions == 0 {
		t.Fatal("вопросов об истории не найдено НИ ОДНОГО — разбор перестал видеть предмет, " +
			"и его молчание сказано ни о чём")
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ ОБЯЗАН ПРИСУТСТВОВАТЬ: вопрос, заданный СТВОЛУ, в дереве
	// есть и находкой быть не должен. Не встретив ни одного, гейт доказывает лишь
	// то, что умеет краснеть, — и ничего о том, что умеет молчать.
	if c.Trunk == 0 {
		t.Fatal("гейт не встретил НИ ОДНОГО вопроса, заданного стволу, а они в дереве есть. " +
			"Значит он либо не дочитал, либо не отличает ствол от вершины — и его молчание о " +
			"находках ничего не стоит")
	}

	for _, s := range stale {
		t.Errorf("запись ведомости ПЕРЕЖИЛА свой предмет: %s. Прощать нечего — снимите запись", s)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// judgeHistoryVertices — вердикт по вопросам и ведомости. Вынесено ЧИСТОЙ
// функцией затем, чтобы падучесть доказывалась подачей входа, а не чтением.
func judgeHistoryVertices(questions []check.HistoryQuestion,
	ledger map[string]vertexWaiver) (findings []string, applied int, stale []string) {

	// Сколько вызовов в дереве приходится на каждый ключ ведомости.
	got := map[string]int{}
	first := map[string]check.HistoryQuestion{}
	for _, q := range questions {
		if q.Vertex == check.VertexTrunk {
			continue
		}
		key := q.File + "#" + q.Verb
		got[key]++
		if _, ok := first[key]; !ok {
			first[key] = q
		}
	}

	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		q := first[key]
		w, forgiven := ledger[key]
		switch {
		case !forgiven:
			findings = append(findings, fmt.Sprintf(
				"%s:%d: вопрос об истории задан НЕ СТВОЛУ (вершина: %s, глагол %s, вызовов %d).\n"+
					"    Здесь вливают схлопыванием: коммит полосы предком ствола не становится "+
					"никогда, поэтому вердикт «по рабочей вершине» описывает дерево, которого "+
					"после посадки не будет.\n"+
					"    Исходов два: перевести вершину на ствол (%s) — либо записать в ведомость "+
					"`vertexLedger` довод, почему для ЭТОГО вопроса вершина верна, с точным числом "+
					"вызовов.",
				q.File, q.Line, q.Vertex, q.Verb, got[key], strings.Join(historyTrunkRefs, ", ")))
		case strings.TrimSpace(w.Why) == "":
			findings = append(findings, fmt.Sprintf(
				"%s: запись ведомости БЕЗ ДОВОДА — послабление без предиката снятия не истечёт "+
					"никогда", key))
		case w.Calls != got[key]:
			findings = append(findings, fmt.Sprintf(
				"%s:%d: запись ведомости прощает %d вызов(ов), а их в файле %d — адъюдикация "+
					"устарела, и новый вызов прошёл бы под чужим доводом",
				q.File, q.Line, w.Calls, got[key]))
		default:
			applied++
		}
	}

	for key := range ledger {
		if got[key] == 0 {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return findings, applied, stale
}

// countDeferrals — записей, которые доводом НЕ являются: вершина выбрана неверно,
// предмет заведён задачей. Печатается отдельной величиной намеренно — отсрочка,
// сосчитанная вместе с доводами, невидима.
func countDeferrals(ledger map[string]vertexWaiver) int {
	n := 0
	for _, w := range ledger {
		if w.Issue != 0 {
			n++
		}
	}
	return n
}

// censusByVerb — перепись по глаголам в устойчивом порядке.
func censusByVerb(c check.HistoryCensus) string {
	verbs := make([]string, 0, len(c.ByVerb))
	for v := range c.ByVerb {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	parts := make([]string, 0, len(verbs))
	for _, v := range verbs {
		parts = append(parts, fmt.Sprintf("%s %d", v, c.ByVerb[v]))
	}
	return strings.Join(parts, " · ")
}

// readHistoryCorpus — корпус из ИНДЕКСА git, а не обходом диска: вердикт обязан
// быть свойством коммита, а не рабочего каталога.
func readHistoryCorpus(t *testing.T, corpusRoot, ownDir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, suffix := range historyCorpusSuffixes {
		paths, err := treecorpus.UnderWithSuffix(ownDir, suffix)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева (%s) не прочитан: %v", suffix, err)
		}
		for _, abs := range paths {
			rel, rerr := filepath.Rel(corpusRoot, abs)
			if rerr != nil {
				t.Fatalf("относительный путь для %s: %v", abs, rerr)
			}
			b, readErr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
			if readErr != nil {
				t.Fatalf("чтение %s: %v", rel, readErr)
			}
			out[filepath.ToSlash(rel)] = b
		}
	}
	return out
}
