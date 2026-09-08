// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Число, датированное САМОССЫЛКОЙ, проверить нельзя; ревизия, проверенная
// РЕЗОЛВОМ, проверена негодно. Гейт задачи #1805.
//
// # ДВЕ ПОЛОВИНЫ, И НИ ОДНА НЕ ВЫВОДИТСЯ ИЗ ДРУГОЙ
//
//   - «датировано» — у объявленного замера названа ревизия ХЕШЕМ. Оборот «замер
//     на ревизии записи» ревизии не называет: восстановить её можно только
//     раскопками по истории (`git log -S`), то есть дороже, чем стоит сама
//     проверка;
//   - «датировано ГОДНО» — названный хеш ВХОДИТ В ИСТОРИЮ этого дерева. Предикат
//     «резолвится ли ревизия» на этот вопрос НЕ отвечает: у рабочих копий одного
//     клона общая база объектов, поэтому `git cat-file -t` говорит «да» о
//     коммите ЧУЖОЙ линии. Здесь это не гипотеза: §19 датировали хешем
//     `ee2370e18`, он резолвится и предком этой линии НЕ ЯВЛЯЕТСЯ — сюда его
//     содержимое приехало схлопыванием, под другим хешем.
//
// # ЧТО ГЕЙТ НЕ СУДИТ — НАЗВАНО, ЧТОБЫ ЕГО НЕ ЧИТАЛИ ШИРЕ
//
//   - ИСТИННОСТЬ самих чисел. Перемерить произвольный предикат из прозы машинно
//     нельзя; гейт держит ДАТИРОВКУ — то есть возможность перемерить;
//   - ПРОЗУ О ФОРМЕ. Оборот, взятый в кавычки-ёлочки («замер на ревизии»),
//     замером не является: проверка, краснеющая на собственном объяснении, —
//     ровно тот класс, который здесь и ловится. Такие вхождения считаются
//     отдельной величиной переписи, а не находкой.
//
// # ЧЕМ ПРОЗА ОТЛИЧАЕТСЯ ОТ ОБЪЯВЛЕНИЯ — КАВЫЧКАМИ, А НЕ БЛОКОМ ЦИТАТЫ
//
// Прежняя редакция считала прозой ВСЯКУЮ строку, открытую знаком `>`, и это была
// СЛЕПАЯ ЗОНА, а не решение: выноска (`> [!note]`) — обычная форма этого корпуса,
// и объявление замера внутри неё уходило в счётчик `quoted` вместо суда.
//
// Цена измерена, а не предположена. На ревизии ствола `2171a6690a` прогон печатал
// «объявлений замера 4 · процитировано прозой 3 · находок 2», и среди этих трёх
// «цитат» пряталось НАСТОЯЩЕЕ объявление: приёмка ролей манифеста датировала
// замер ревизией `ebd6122895`, в историю ствола не входящей. То есть находка того
// самого класса, ради которого гейт заведён, была невидима ВНУТРИ него — не
// красное и не зелёное, а отсутствие вопроса. Расширение сместило ровно её:
// объявлений 4 → 5, прозы 3 → 2; полоса прежней формы не изменилась.
//
// Поэтому разделяет теперь ЯВНАЯ ЦИТАТА (ёлочки), а не членство в блоке: строка,
// которая ОТКРЫВАЕТСЯ оборотом, есть объявление, где бы она ни стояла. Способность
// образца видеть новую форму и молчать на её законном близнеце держат три пробы
// рядом (`...IsSilentOnALawfulCalloutDeclaration`, `...RedsOnAForeignRevisionInsideACallout`,
// `...IsSilentOnProseInsideACallout`), а не эта строка.
//
// # ВЕДОМОСТЬ И ЕЁ САМОИСТЕЧЕНИЕ
//
// Два документа приёмки несут недатированный замер и здесь НЕ правятся: на их
// тексте стоит вердикт рецензента, и правка идёт своим заходом (задача названа в
// причине). Ведомость прощает им ТОЛЬКО отсутствие даты и самоистекает: запись,
// которой больше нечего прощать, — находка, а не тишина.

const iamDocsRelDir = "services/iam/docs"

// reDatingMarker — ОБЪЯВЛЕНИЕ замера, а не упоминание слова.
//
// Судится начало строки (допускаются знак цитаты, маркер списка и жирное
// начертание), потому что объявление замера в этом корпусе всегда ОТКРЫВАЕТ
// строку. Знак `>` больше не выводит строку из-под суда: выноска — обычная форма
// этого корпуса, и объявление внутри неё остаётся объявлением.
var reDatingMarker = regexp.MustCompile(`(?m)^[ \t]*(?:>[ \t]*)*(?:[*+\-][ \t]+|\d+\.[ \t]+)?\*{0,2}Замер на ревизии[^\n]*`)

// reQuotedMarker — тот же оборот, взятый в ЯВНЫЕ кавычки-ёлочки: разговор о
// форме, а не объявление. Величина переписи, не находка.
var reQuotedMarker = regexp.MustCompile(`(?mi)«[^»\n]*замер на ревизии`)

// reInlineHash — хеш ревизии в обратных кавычках.
var reInlineHash = regexp.MustCompile("`([0-9a-f]{7,40})`")

// datingCensus — объём осмотренного. Печатается всегда: «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
type datingCensus struct {
	docsRead         int // файлов документации прочитано
	markers          int // объявлений замера найдено
	dated            int // из них датированы хешем
	undated          int // из них датированы самоссылкой
	foreign          int // хеш назван, но в историю дерева не входит
	quoted           int // оборот процитирован прозой — не замер
	ledgerEntries    int // записей ведомости
	ledgerApplied    int // записей, которым было что прощать
	ancestryUnjudged int // «НЕ ВЫПОЛНИЛОСЬ»: вердикт о предке не выносился
}

// ancestryVerdict — исход вопроса «входит ли ревизия в историю дерева».
// Третье состояние обязательно: недоступность истории не есть «да».
type ancestryVerdict int

const (
	ancestryNo       ancestryVerdict = iota // не предок — находка
	ancestryYes                             // предок — законно
	ancestryUnjudged                        // не выполнилось: истории нет или она усечена
)

// auditMeasurementDating — чистое ядро обеих проб: решает по текстам, а не по
// дереву. Ключ ведомости — имя файла, значение — причина с номером задачи.
func auditMeasurementDating(
	docs map[string]string,
	ledger map[string]string,
	ancestry func(hash string) ancestryVerdict,
) ([]string, datingCensus) {
	var findings []string
	c := datingCensus{docsRead: len(docs), ledgerEntries: len(ledger)}
	forgiven := map[string]bool{}

	names := make([]string, 0, len(docs))
	for name := range docs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		body := docs[name]
		c.quoted += len(reQuotedMarker.FindAllString(body, -1))

		for _, line := range reDatingMarker.FindAllString(body, -1) {
			c.markers++
			hash := reInlineHash.FindStringSubmatch(line)
			if hash == nil {
				c.undated++
				if _, ok := ledger[name]; ok {
					forgiven[name] = true
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"САМОССЫЛКА: %s датирует замер без хеша (%q) — восстановить ревизию можно только "+
						"раскопками по истории, то есть дороже, чем стоит проверка числа",
					name, strings.TrimSpace(line)))
				continue
			}
			c.dated++
			switch ancestry(hash[1]) {
			case ancestryNo:
				c.foreign++
				findings = append(findings, fmt.Sprintf(
					"ЧУЖАЯ ЛИНИЯ: %s датирует замер ревизией %s, которая РЕЗОЛВИТСЯ, но в историю этого "+
						"дерева не входит — числа верны для дерева, которого здесь нет (%q)",
					name, hash[1], strings.TrimSpace(line)))
			case ancestryUnjudged:
				c.ancestryUnjudged++
			case ancestryYes:
			}
		}
	}

	ledgerNames := make([]string, 0, len(ledger))
	for name := range ledger {
		ledgerNames = append(ledgerNames, name)
	}
	sort.Strings(ledgerNames)
	for _, name := range ledgerNames {
		if forgiven[name] {
			c.ledgerApplied++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"ВЕДОМОСТИ НЕЧЕГО ПРОЩАТЬ: запись про %s (%s) пережила свой предмет — "+
				"недатированного замера в этом документе больше нет, запись снимается",
			name, ledger[name]))
	}
	return findings, c
}

// datingLedger — прощённые записи. Каждая несёт причину и номер задачи;
// самоистечение держит ядро выше.
//
// СЕГОДНЯ ВЕДОМОСТЬ ПУСТА, и это ИСХОД, а не забывчивость: две APPROVED-приёмки,
// стоявшие здесь по задаче #2043, датированы хешем своим заходом, и гейт назвал
// обе записи находкой («ведомости нечего прощать») в ту же минуту. Пустая
// ведомость — цель, поэтому проба на ней ПРОХОДИТ: отказ на достижении цели
// подталкивал бы держать запись ради зелёного.
func datingLedger() map[string]string {
	return map[string]string{}
}

// readMarkdownTree читает дерево документации целиком.
//
// Состав берётся ИЗ ИНДЕКСА git (`treecorpus`), а не обходом диска: обход читал
// бы игнорируемое — распаковки, отчёты прогонов, рабочие копии, — и вердикт стал
// бы свойством рабочего каталога, а не коммита. Тот же вызов отказывает на
// кешируемом прогоне: состав дерева берётся подпроцессом, и `go test` о нём не
// знает, поэтому над красным деревом печаталось бы `ok (cached)`.
func readMarkdownTree(t *testing.T, docsDir string) map[string]string {
	t.Helper()
	paths, err := treecorpus.UnderWithSuffix(docsDir, ".md")
	require.NoError(t, err)

	out := map[string]string{}
	for _, path := range paths {
		raw, readErr := os.ReadFile(path) // #nosec G304 -- путь пришёл из индекса git собственного каталога документации
		require.NoError(t, readErr)
		rel, relErr := filepath.Rel(docsDir, path)
		require.NoError(t, relErr)
		out[filepath.ToSlash(rel)] = string(raw)
	}
	return out
}

// gitAncestry — годный предикат: ВХОЖДЕНИЕ В ИСТОРИЮ, а не резолв объекта.
//
// # ПОЧЕМУ УСЕЧЁННАЯ ИСТОРИЯ НЕ ПРОСТО ВЫКЛЮЧАЕТ ПОЛОВИНУ
//
// Неполный клон делает `merge-base` лжецом ТОЛЬКО В ОДНУ СТОРОНУ: ответ «предок»
// он даёт, найдя путь, и путь этот настоящий; ответ «не предок» на усечённой
// истории бывает ложным — путь мог остаться за границей выборки.
//
// Поэтому «не предок» принимается за вердикт лишь тогда, когда он ДОКАЗУЕМ:
// коммит МОЛОЖЕ границы усечения, значит весь путь от него до HEAD целиком
// внутри выбранного куска, и его отсутствие — факт, а не следствие усечения.
// Во всех прочих положениях исход — НЕ ВЫПОЛНИЛОСЬ, и он не вычитается из
// вердикта и не зачитывается в успех.
func gitAncestry(t *testing.T, root string, hashes []string) func(string) ancestryVerdict {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Logf("git недоступен — половина «предок» НЕ ВЫПОЛНЯЛАСЬ")
		return func(string) ancestryVerdict { return ancestryUnjudged }
	}
	// Вызов идёт через общий помощник, а НЕ через exec.Command напрямую:
	// `cmd.Dir` не выбирает репозиторий, когда в окружении есть GIT_DIR —
	// переменная сильнее рабочего каталога, и проба писала бы в чужую копию.
	git := func(args ...string) (string, error) {
		out, err := gitenv.Command(root, args...).Output()
		return strings.TrimSpace(string(out)), err
	}
	shallowOut, err := git("rev-parse", "--is-shallow-repository")
	if err != nil {
		t.Logf("история недоступна — половина «предок» НЕ ВЫПОЛНЯЛАСЬ")
		return func(string) ancestryVerdict { return ancestryUnjudged }
	}
	shallow := shallowOut == "true"

	// boundary — время самой старой доступной точки истории.
	var boundary string
	if shallow {
		roots, rootsErr := git("rev-list", "--max-parents=0", "HEAD")
		if rootsErr != nil || roots == "" {
			t.Logf("граница усечения не определяется — половина «предок» НЕ ВЫПОЛНЯЛАСЬ")
			return func(string) ancestryVerdict { return ancestryUnjudged }
		}
		boundary, _ = git("show", "-s", "--format=%ct", strings.Fields(roots)[0])
		t.Logf("история УСЕЧЕНА: «не предок» принимается только для ревизий моложе границы (%s)", boundary)
	}

	// РЕПОЗИТОРИЙ БЕЗ ЭТОЙ ИСТОРИИ ВЕРДИКТА НЕ ВЫНОСИТ ВОВСЕ.
	//
	// Поставка модуля историю НЕ несёт: `git archive` отдаёт состав коммита, и у
	// арендатора получается свежий репозиторий с одним коммитом. В нём не
	// резолвится НИ ОДНА названная ревизия — не потому, что документы врут, а
	// потому что судить не в чем. Прежняя редакция отвечала на это «не предок»,
	// и каждый замер становился находкой у КАЖДОГО, кто склонирует.
	//
	// Различает не число коммитов, а ОДНО наблюдение: знает ли дерево хоть одну
	// из названных ревизий. Знает — значит история та, и не резолвящаяся ревизия
	// есть находка (описка в хеше, ссылка на снятую линию). Не знает ни одной —
	// значит история чужая, и вердикт не выносится ни по одной.
	knowsAny := false
	for _, h := range hashes {
		if _, e := git("cat-file", "-e", h+"^{commit}"); e == nil {
			knowsAny = true
			break
		}
	}
	if !knowsAny {
		t.Logf("история этого дерева не знает НИ ОДНОЙ из %d названных ревизий — "+
			"вердикт о предке НЕ ВЫНОСИТСЯ (поставка модуля историю не несёт)", len(hashes))
		return func(string) ancestryVerdict { return ancestryUnjudged }
	}

	return func(hash string) ancestryVerdict {
		if _, e := git("cat-file", "-e", hash+"^{commit}"); e != nil {
			if shallow {
				// Объекта нет: на усечённой истории это неотличимо от «не довезли».
				return ancestryUnjudged
			}
			return ancestryNo
		}
		if _, e := git("merge-base", "--is-ancestor", hash, "HEAD"); e == nil {
			return ancestryYes
		}
		if !shallow {
			return ancestryNo
		}
		when, e := git("show", "-s", "--format=%ct", hash)
		if e != nil || boundary == "" || len(when) < len(boundary) ||
			(len(when) == len(boundary) && when <= boundary) {
			return ancestryUnjudged
		}
		return ancestryNo
	}
}

// TestMeasurementRevisionsAreDatedByHashAndBelongToThisHistory — несущее утверждение.
func TestMeasurementRevisionsAreDatedByHashAndBelongToThisHistory(t *testing.T) {
	root := monorepoRoot(t)
	docs := readMarkdownTree(t, platformtree.RequirePath(t, iamDocsRelDir))

	require.NotZerof(t, len(docs), "обход документации пуст — вердикт беспредметен (%s)", iamDocsRelDir)

	// Перечень названных ревизий собирается ДО вердикта: он и есть предпосылка
	// половины «предок» — дерево, не знающее ни одной из них, судить о них не
	// может (см. шапку `gitAncestry`).
	var named []string
	for _, body := range docs {
		for _, m := range reInlineHash.FindAllStringSubmatch(body, -1) {
			named = append(named, m[1])
		}
	}

	findings, c := auditMeasurementDating(docs, datingLedger(), gitAncestry(t, root, named))

	t.Logf("перепись: документов прочитано %d · объявлений замера %d · датировано хешем %d · "+
		"самоссылкой %d · чужой линией %d · процитировано прозой %d · записей ведомости %d "+
		"(применено %d) · вердикт о предке НЕ ВЫНОСИЛСЯ %d · находок %d",
		c.docsRead, c.markers, c.dated, c.undated, c.foreign, c.quoted,
		c.ledgerEntries, c.ledgerApplied, c.ancestryUnjudged, len(findings))

	require.NotZerof(t, c.markers,
		"объявлений замера не найдено ни одного — отрицания гейта стали вакуумными: "+
			"либо корпус сменил форму датировки, либо образец её больше не узнаёт")

	require.Emptyf(t, findings,
		"датировка чисел в документации iam негодна:\n%s", strings.Join(findings, "\n"))
}
