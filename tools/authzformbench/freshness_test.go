// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

// freshness_test.go — ГЕЙТ СВЕЖЕСТИ ОТЧЁТОВ ПРИБОРА.
//
// # Что он сторожит
//
// На числах этого прибора стоит обоснование под-фазы отказа от внешнего движка:
// окно отзыва, первый ответ и — важнее — единственное измеренное место, где
// новая форма ПРОИГРЫВАЕТ старой. Карантин, объявивший несвежими отчёты
// `scalegrid`, накрыл три отчёта из четырёх СВОЕГО вида и не задал вопроса о
// свежести этим числам: прибор заведён позже и в другом каталоге, в предмет
// того гейта не входит, и его несвежесть была невыразима.
//
// # ДВЕ ПОЛОСЫ, потому что отчёты бывают двух видов, и смешивать их нельзя
//
//	(A) отчёт СО ШТАМПОМ — судится четырьмя плечами, как у `scalegrid`;
//	(B) отчёт ДОШТАМПОВОЙ эпохи — их десять, и накрыть их отпечатком задним
//	    числом НЕЛЬЗЯ (почему — ниже). Они стоят в ВЕДОМОСТИ, которая не может
//	    вырасти молча и истекает сама.
//
// # ПОЧЕМУ РЕТРО-ШТАМПОВКА ОТВЕРГНУТА, а не «пока не сделана»
//
// Соблазн очевиден: у четырёх машинных отчётов в шапке стоит ревизия, все
// четыре разрешаются, и отпечаток прибора НА ТОЙ ревизии вычислим. Но
// `REPORT-226-pagecost-2026-08-12` снят на `687500f5` ПЛЮС наложенную правку —
// это сказано в соседнем отчёте перезамера. Отпечаток коммита для него был бы
// ЛОЖЕН и при этом неотличим от истинного: правдоподобное значение, прячущее
// ровно тот дефект, ради которого его ставят. Пять из десяти отчётов — разбор,
// написанный человеком, и ревизии в них нет вовсе.
//
// Поэтому граница ПЕЧАТАЕТСЯ, а не подделывается: по каждому доштамповому
// отчёту гейт называет ревизию и то, НА СКОЛЬКО файлов прибор с тех пор
// сдвинулся. Это утверждение о прошлом остаётся утверждением о прошлом.
//
// # Почему сдвиг прибора НЕ роняет полосу B
//
// Замер: за 30 дней .go прибора трогали 12 коммитов. Гейт, требующий по такому
// поводу править четыре числа ведомости, был бы снят первым же месяцем — и унёс
// бы с собой полосу A. Сдвиг печатается на КАЖДОМ прогоне и потому не теряется;
// роняет же полоса B то, что действительно можно и нужно чинить: НОВЫЙ отчёт,
// не накрытый ничем, и запись, которой больше нечего исключать.
//
// # ЧЕГО ЭТОТ ГЕЙТ НЕ ЛОВИТ — названо здесь, чтобы его зелёное не читали шире
//
// Отпечаток берётся с КОДА прибора. Значит гейт отвечает на вопрос «изменилось
// ли то, чем мерили» — и НЕ отвечает на вопрос «изменилось ли то, НА ЧЁМ
// мерили». Пример не гипотетический, он лежит в этом же каталоге: отношение
// «1.45×» — частное ДВУХ величин стенда, и отчёт перезамера показывает, что оно
// уехало на 26 % при НЕПОДВИЖНОМ числителе (форма E: 237.7…248.0 мс по пяти
// прогонам, разброс 4.3 %; движок: 206.4 → 171.5 мс). Прибор при этом мог не
// сдвинуться ни на строку.
//
// Отсюда граница, которую гейт печатает на каждом прогоне: он сторожит СВЕЖЕСТЬ
// ПРЕДМЕТА ЗАМЕРА, а не воспроизводимость самой величины. Утверждение
// «миллисекунда — свойство кода» этим гейтом не закрывается и закрыто быть не
// может: закрывается оно переводом предиката допуска на величину, не зависящую
// от стенда (строки, стейтменты, обращения), — что приёмка Ф6 уже и сделала.
//
// # Способность упасть ДОКАЗАНА, а не заявлена
//
// Вердикт полосы A вынесен ЧИСТОЙ функцией (`judgeBenchReport`), поэтому её
// можно накормить синтетикой: инъекция ниже проверяет обе стороны — по плечу на
// каждое расхождение и ЗАКОННЫЙ БЛИЗНЕЦ (свежий отчёт, неподвижный прибор) на
// молчание. Полоса B проверена своей инъекцией — на синтетическом каталоге.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// benchReportMaxAge — предел возраста отчёта.
//
// Величина взята у гейта `scalegrid` ДОСЛОВНО (60 дней, ратифицирована
// владельцем). Своё число здесь было бы вторым умолчанием об одном предмете, и
// разошлись бы они молча.
const benchReportMaxAge = 60 * 24 * time.Hour

// benchReportDateMarks — приставки строки даты. Их ДВЕ, потому что писателей
// отчёта два, и каждый печатает свою; формат у обоих RFC3339.
var benchReportDateMarks = []string{"when         ", "дата                "}

// benchReportRevMarks — приставки строки ревизии, по тем же двум писателям.
var benchReportRevMarks = []string{"tree         ", "ревизия дерева      "}

// benchRunHint — КАК ПЕРЕСНЯТЬ. Отдельной строкой: сообщение отказа обязано
// говорить, что делать, а не только что не так.
const benchRunHint = "AUTHZFORMBENCH=1 go test -C services/iam ./tools/authzformbench/ " +
	"-run TestMatrix -count=1 -v -timeout 120m  (поднимает контейнеры)"

// ── ПОЛОСА A: ВЕРДИКТ ПО ОТЧЁТУ СО ШТАМПОМ, ЧИСТОЙ ФУНКЦИЕЙ ─────────────────

// judgeBenchReport — четыре плеча над (текст отчёта, отпечаток прибора, часы).
//
// Часы ПАРАМЕТРОМ, а не `time.Now()` внутри: гейт, читающий системные часы, на
// синтетике не проверяется вовсе — «прошло 61 день» иначе не воспроизвести.
func judgeBenchReport(text string, fp Fingerprint,
	contentOf func(rel string) string, now time.Time) []string {
	var findings []string

	// (в) предпосылка: предмет существует.
	if len(fp.Files) == 0 {
		return append(findings, "множество файлов под отпечатком ПУСТО — у предиката исчез "+
			"предмет; «совпало» здесь означает «не с чем сравнивать», и гейт сторожил бы пустоту.\n"+
			"  предикат: "+predicateOfBench(fp))
	}

	recordedComposition := benchValueAfter(text, MarkerComposition)
	recordedContent := benchValueAfter(text, MarkerContent)
	recordedFiles := benchRecordedFileHashes(text)

	if recordedComposition == "" || recordedContent == "" {
		return append(findings, "в шапке отчёта нет строк отпечатка прибора — сверять нечего, "+
			"и молчание гейта означало бы, что прибор неподвижен, чего никто не проверял")
	}

	// (г) состав множества.
	if recordedComposition != fp.Composition {
		added, removed := benchDiffSets(benchKeysOf(recordedFiles), fp.Files)
		findings = append(findings, fmt.Sprintf(
			"СОСТАВ прибора изменился: в отчёте %s, по дереву %s\n"+
				"  добавлено: %s\n  снято:     %s\n"+
				"  Содержимое прежних файлов от появления нового не меняется, поэтому плечо (а) "+
				"этого не ловит by construction",
			recordedComposition, fp.Composition, benchJoinOrDash(added), benchJoinOrDash(removed)))
	}

	// (а) содержимое — с ИМЕНЕМ виновника.
	if recordedContent != fp.Content {
		var moved []string
		for _, rel := range fp.Files {
			was, known := recordedFiles[rel]
			if cur := contentOf(rel); known && was != cur {
				moved = append(moved, fmt.Sprintf("%s (было %s, стало %s)", rel, was, cur))
			}
		}
		sort.Strings(moved)
		findings = append(findings, fmt.Sprintf(
			"ПРИБОР СДВИНУЛСЯ: отпечаток содержимого в отчёте %s, по дереву %s\n"+
				"  сдвинули его: %s\n"+
				"  Отчёт продолжает утверждать о числах, снятых прибором, которого в дереве больше нет",
			recordedContent, fp.Content, benchJoinOrDash(moved)))
	}

	// (б) возраст.
	when, err := benchReportDate(text)
	if err != nil {
		findings = append(findings, fmt.Sprintf(
			"дата замера из шапки не прочитана (%v): возраст неизвестен, а «неизвестен» "+
				"здесь неотличимо от «свеж»", err))
		return findings
	}
	if elapsed := now.Sub(when); elapsed > benchReportMaxAge {
		findings = append(findings, fmt.Sprintf(
			"отчёт СТАРШЕ предела: снят %s, прошло %.0f дней при пределе %.0f — прибор и модель "+
				"за это время двигались, и числа описывают прошлое",
			when.Format("2006-01-02"), elapsed.Hours()/24, benchReportMaxAge.Hours()/24))
	}
	return findings
}

func predicateOfBench(fp Fingerprint) string {
	if fp.Predicate == "" {
		return FingerprintPredicate
	}
	return fp.Predicate
}

// ── ПОЛОСА B: ВЕДОМОСТЬ ДОШТАМПОВЫХ ОТЧЁТОВ ─────────────────────────────────

// preStampReport — отчёт, снятый ДО того, как прибор научился штамповать себя.
type preStampReport struct {
	// file — имя файла в каталоге прибора.
	file string
	// rev — ревизия из шапки; пусто означает «строки ревизии в файле нет»,
	// и это тоже проверяется, а не подразумевается.
	rev string
	// why — почему отпечаток не может быть проставлен задним числом.
	why string
}

// preStampLedger — ВСЕ отчёты доштамповой эпохи, поимённо.
//
// Ведомость, а не «всё, у чего нет штампа»: перечень по признаку молча вобрал бы
// в себя следующий незаштампованный отчёт и объявил его законным. Здесь новый
// отчёт без штампа — находка, а не запись.
func preStampLedger() []preStampReport {
	const noRev = "ревизии в шапке нет — это разбор, написанный человеком, а не вывод прибора"
	const patched = "снят на ревизии ПЛЮС наложенную правку (сказано в отчёте перезамера): " +
		"отпечаток коммита был бы ложен и неотличим от истинного"
	const machine = "машинный вывод прибора доштамповой эпохи: шапка несёт ревизию, но не отпечаток"
	return []preStampReport{
		{file: "REPORT-226-pagecost-2026-08-12.raw.txt",
			rev: "687500f50d6549a9145db94b89d6f4bf9baa2d37", why: patched},
		{file: "REPORT-226-pagecost-2026-08-12.txt", why: noRev},
		{file: "REPORT-XC-10-2026-08-10.classified.txt", why: noRev},
		{file: "REPORT-XC-10-2026-08-10.raw.txt",
			rev: "9f8879709c73b44a650659dfa153a0eb5b314cb6", why: machine},
		{file: "REPORT-XC-10-2026-08-10.volume-decomposition.csv", why: noRev},
		{file: "REPORT-XC-10-fullmodel-2026-08-11.txt", why: noRev},
		{file: "REPORT-XC-12-F5-labelpath-2026-08-12.raw.txt",
			rev: "9487bf6d395f222f0d535770bd4501a7c8faed37", why: machine},
		{file: "REPORT-XC-12-F5-labelpath-2026-08-12.txt", why: noRev},
		{file: "REPORT-XC-12-F5-remeasure-2026-08-14.raw.txt",
			rev: "7f52eb25ba1043d97d9e8f5bc987bf956e32ca93", why: machine},
		{file: "REPORT-XC-12-F5-remeasure-2026-08-14.txt", why: noRev},
	}
}

// judgeLedger — вердикт полосы B над (что лежит в каталоге, что записано в
// ведомости, у каких файлов есть штамп).
//
// Чистой функцией по той же причине, что и полоса A: иначе её способность упасть
// проверяется только правкой настоящего каталога.
func judgeLedger(present []string, ledger []preStampReport,
	stamped map[string]bool, revOf func(file string) string) []string {
	var findings []string

	if len(present) == 0 {
		return append(findings, "в каталоге прибора НОЛЬ отчётов: у гейта исчез предмет, "+
			"и его молчание означало бы свежесть, которой никто не проверял")
	}

	inLedger := map[string]preStampReport{}
	for _, e := range ledger {
		inLedger[e.file] = e
	}
	isPresent := map[string]bool{}
	for _, f := range present {
		isPresent[f] = true
	}

	// (1) отчёт, не накрытый НИЧЕМ — ни штампом, ни ведомостью.
	var uncovered []string
	for _, f := range present {
		if stamped[f] {
			continue
		}
		if _, ok := inLedger[f]; !ok {
			uncovered = append(uncovered, f)
		}
	}
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		findings = append(findings, fmt.Sprintf(
			"отчёт прибора не накрыт НИЧЕМ — ни отпечатком, ни ведомостью: %s\n"+
				"  Отчёт без отпечатка утверждает о числах, снятых неизвестно чем. Исходов два:\n"+
				"  переснять прибором, который себя штампует (%s), либо — если это разбор,\n"+
				"  написанный человеком, — внести в `preStampLedger` с причиной",
			strings.Join(uncovered, ", "), benchRunHint))
	}

	// (2) запись, которой больше нечего исключать — файла нет.
	var vanished []string
	for _, e := range ledger {
		if !isPresent[e.file] {
			vanished = append(vanished, e.file)
		}
	}
	if len(vanished) > 0 {
		sort.Strings(vanished)
		findings = append(findings, fmt.Sprintf(
			"запись ведомости без предмета: %s\n"+
				"  Файла в каталоге нет. Послабление обязано истекать САМО — иначе следующая "+
				"слепая зона унаследует эту запись",
			strings.Join(vanished, ", ")))
	}

	// (3) запись, чей файл ТЕПЕРЬ со штампом — исключать тоже нечего.
	var nowStamped []string
	for _, e := range ledger {
		if isPresent[e.file] && stamped[e.file] {
			nowStamped = append(nowStamped, e.file)
		}
	}
	if len(nowStamped) > 0 {
		sort.Strings(nowStamped)
		findings = append(findings, fmt.Sprintf(
			"запись ведомости на отчёт, который УЖЕ несёт отпечаток: %s\n"+
				"  Он судится полосой A; запись здесь выводит его из-под неё",
			strings.Join(nowStamped, ", ")))
	}

	// (4) ведомость разошлась с артефактом по ревизии.
	var drifted []string
	for _, e := range ledger {
		if !isPresent[e.file] || stamped[e.file] {
			continue
		}
		if got := revOf(e.file); got != e.rev {
			drifted = append(drifted, fmt.Sprintf("%s (в ведомости %q, в шапке %q)",
				e.file, benchOrDash(e.rev), benchOrDash(got)))
		}
	}
	if len(drifted) > 0 {
		sort.Strings(drifted)
		findings = append(findings, fmt.Sprintf(
			"ведомость разошлась с шапкой отчёта по ревизии: %s\n"+
				"  Ведомость описывает артефакты; разойдясь с ними, она начинает описывать то, "+
				"чего нет",
			strings.Join(drifted, "; ")))
	}
	return findings
}

// ── ГЕЙТ НАД НАСТОЯЩИМ КАТАЛОГОМ ────────────────────────────────────────────

// TestBenchReportsAreFreshAndTheirInstrumentHasNotMoved — гейт свежести.
func TestBenchReportsAreFreshAndTheirInstrumentHasNotMoved(t *testing.T) {
	root := benchRepoRoot(t)
	dir := filepath.Join(root, benchDir)

	present, err := benchReportFiles(dir)
	if err != nil {
		t.Fatalf("состав каталога отчётов не прочитан (%v): «ноль находок» здесь было бы "+
			"неотличимо от «ноль прочитанного»", err)
	}

	fp, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток прибора по текущему дереву не вычислен: %v", err)
	}

	stamped := map[string]bool{}
	texts := map[string]string{}
	for _, f := range present {
		body, rerr := os.ReadFile(filepath.Join(dir, f)) // #nosec G304 -- f получен обходом СОБСТВЕННОГО каталога прибора, не из запроса и не от пользователя
		if rerr != nil {
			t.Fatalf("отчёт %s не прочитан (%v): непрочитанный отчёт нельзя ни судить, ни "+
				"объявить свежим", f, rerr)
		}
		texts[f] = string(body)
		stamped[f] = benchValueAfter(texts[f], MarkerContent) != ""
	}

	// ── ОБЪЁМ ОСМОТРЕННОГО — отдельное утверждение, печатается ВСЕГДА ──
	nStamped := 0
	for _, f := range present {
		if stamped[f] {
			nStamped++
		}
	}
	t.Logf("прогон прибора не исполнял. Отчётов в каталоге %d: со штампом %d (полоса A), "+
		"доштамповых %d (полоса B, ведомость на %d записей). Файлов под отпечатком прибора %d, "+
		"предикат: %s",
		len(present), nStamped, len(present)-nStamped, len(preStampLedger()), len(fp.Files),
		fp.Predicate)
	t.Logf("ГРАНИЦА ПРЕДМЕТА: сторожится свежесть ПРИБОРА (кода), а не воспроизводимость " +
		"ВЕЛИЧИНЫ. Отношение двух стендовых величин может уехать при неподвижном приборе — " +
		"этот гейт такого не поймает by construction, и его зелёное этого не утверждает")

	// ── ГРАНИЦА ПРЕДМЕТА: печатается по КАЖДОМУ доштамповому отчёту ──
	//
	// Не находка (переснять их нельзя без стенда и часов), но и не молчание:
	// число сдвинувшихся файлов прибора говорит, насколько числа отчёта отстали.
	for _, e := range preStampLedger() {
		if !benchContains(present, e.file) || stamped[e.file] {
			continue
		}
		if e.rev == "" {
			t.Logf("ГРАНИЦА: %s — ревизии в шапке нет; отпечатком не накрыт. %s", e.file, e.why)
			continue
		}
		moved, mErr := benchInstrumentFilesMovedSince(root, e.rev)
		switch {
		case mErr != nil:
			t.Logf("ГРАНИЦА: %s — ревизия %s не сверена с деревом (%v); отпечатком не накрыт",
				e.file, e.rev[:8], mErr)
		default:
			t.Logf("ГРАНИЦА: %s — снят на %s; прибор с тех пор СДВИНУЛСЯ на %d .go-файлов "+
				"(%s). Отпечатком не накрыт: %s",
				e.file, e.rev[:8], len(moved), benchJoinOrDash(moved), e.why)
		}
	}

	// ── ПОЛОСА B ──
	for _, f := range judgeLedger(present, preStampLedger(), stamped, func(file string) string {
		return benchRecordedRev(texts[file])
	}) {
		t.Errorf("%s", f)
	}

	// ── ПОЛОСА A ──
	for _, f := range present {
		if !stamped[f] {
			continue
		}
		t.Run(f, func(t *testing.T) {
			findings := judgeBenchReport(texts[f], fp, func(rel string) string {
				return ContentOf(root, rel)
			}, time.Now())
			for _, x := range findings {
				t.Errorf("%s\n  Пересними: %s", x, benchRunHint)
			}
		})
	}
}

// ── ИНЪЕКЦИЯ: ОБЕ ПОЛОСЫ СПОСОБНЫ УПАСТЬ И СПОСОБНЫ СМОЛЧАТЬ ────────────────

// TestBenchFreshnessGateCanFailAndCanStaySilent — контроль в обе стороны.
func TestBenchFreshnessGateCanFailAndCanStaySilent(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-3 * 24 * time.Hour)

	fp := Fingerprint{
		Composition: "COMPOSITION00001",
		Content:     "CONTENT000000001",
		Files:       []string{benchDir + "/measure.go", benchDir + "/run_test.go"},
		Predicate:   FingerprintPredicate,
	}
	content := map[string]string{
		benchDir + "/measure.go":  "HASHA00000000001",
		benchDir + "/run_test.go": "HASHB00000000002",
	}
	contentOf := func(rel string) string { return content[rel] }

	report := func(when time.Time, comp, cont string, files map[string]string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "%s%s\n", benchReportDateMarks[0], when.Format(time.RFC3339))
		fmt.Fprintf(&b, "%s%s\n", MarkerComposition, comp)
		fmt.Fprintf(&b, "%s%s\n", MarkerContent, cont)
		fmt.Fprintf(&b, "%s%s\n", MarkerPredicate, FingerprintPredicate)
		fmt.Fprintf(&b, "%s\n", MarkerFileList)
		for _, rel := range benchKeysOf(files) {
			fmt.Fprintf(&b, "%s%s  %s\n", MarkerFile, files[rel], rel)
		}
		return b.String()
	}

	t.Run("полоса A", func(t *testing.T) {
		// ЗАКОННЫЙ БЛИЗНЕЦ: свежий отчёт, прибор неподвижен — гейт обязан МОЛЧАТЬ.
		// Без него всякое «покраснел» ниже зеленело бы и на исправном дереве.
		if got := judgeBenchReport(report(fresh, fp.Composition, fp.Content, content),
			fp, contentOf, now); len(got) != 0 {
			t.Fatalf("законный близнец покраснел: свежий отчёт с неподвижным прибором обязан "+
				"проходить молча, иначе гейт краснеет на достижении собственной цели.\n%s",
				strings.Join(got, "\n"))
		}

		cases := []struct {
			name, expect string
			text         string
			fp           Fingerprint
		}{
			{
				name: "(а) файл прибора правлен — гейт называет виновника",
				text: report(fresh, fp.Composition, "OTHERCONTENT0001", map[string]string{
					benchDir + "/measure.go":  "WASA000000000001",
					benchDir + "/run_test.go": "HASHB00000000002"}),
				fp:     fp,
				expect: benchDir + "/measure.go (было WASA000000000001, стало HASHA00000000001)",
			},
			{
				name:   "(б) отчёт старше 60 дней",
				text:   report(now.Add(-61*24*time.Hour), fp.Composition, fp.Content, content),
				fp:     fp,
				expect: "СТАРШЕ предела",
			},
			{
				name:   "(в) множество под отпечатком пусто",
				text:   report(fresh, fp.Composition, fp.Content, content),
				fp:     Fingerprint{Composition: fp.Composition, Content: fp.Content},
				expect: "ПУСТО",
			},
			{
				name: "(г) состав прибора изменился, содержимое прежних НЕ двигалось",
				text: report(fresh, "OLDCOMPOSITION01", fp.Content, content),
				fp: Fingerprint{
					Composition: fp.Composition, Content: fp.Content,
					Files: []string{benchDir + "/labelcost.go", benchDir + "/measure.go",
						benchDir + "/run_test.go"},
				},
				expect: "добавлено: " + benchDir + "/labelcost.go",
			},
			{
				name:   "шапка без строк отпечатка",
				text:   benchReportDateMarks[0] + fresh.Format(time.RFC3339) + "\n",
				fp:     fp,
				expect: "нет строк отпечатка",
			},
			{
				name:   "дата не читается",
				text:   report(fresh, fp.Composition, fp.Content, content)[strings.Index(report(fresh, fp.Composition, fp.Content, content), "\n")+1:],
				fp:     fp,
				expect: "возраст неизвестен",
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got := judgeBenchReport(c.text, c.fp, contentOf, now)
				if len(got) == 0 {
					t.Fatalf("гейт СМОЛЧАЛ на инъекции %q: значит это плечо не способно упасть "+
						"и его зелёное ничего не означает", c.name)
				}
				if joined := strings.Join(got, "\n"); !strings.Contains(joined, c.expect) {
					t.Errorf("гейт покраснел, но НЕ НАЗВАЛ предмет: ожидалось вхождение %q.\n%s",
						c.expect, joined)
				}
			})
		}
	})

	t.Run("полоса B", func(t *testing.T) {
		ledger := []preStampReport{
			{file: "REPORT-one.raw.txt", rev: "aaaaaaaa", why: "машинный доштамповый"},
			{file: "REPORT-two.txt", why: "разбор человека"},
		}
		present := []string{"REPORT-one.raw.txt", "REPORT-two.txt"}
		stampedNone := map[string]bool{}
		revOf := func(file string) string {
			if file == "REPORT-one.raw.txt" {
				return "aaaaaaaa"
			}
			return ""
		}

		// ЗАКОННЫЙ БЛИЗНЕЦ: ведомость сходится с каталогом — МОЛЧАНИЕ.
		if got := judgeLedger(present, ledger, stampedNone, revOf); len(got) != 0 {
			t.Fatalf("законный близнец покраснел: сошедшаяся ведомость обязана проходить "+
				"молча.\n%s", strings.Join(got, "\n"))
		}

		// ЗАКОННЫЙ БЛИЗНЕЦ 2: ведомость ПУСТА, все отчёты со штампом — тоже
		// молчание. Пустая ведомость есть ЦЕЛЬ, а не поломка.
		if got := judgeLedger(present, nil, map[string]bool{
			"REPORT-one.raw.txt": true, "REPORT-two.txt": true}, revOf); len(got) != 0 {
			t.Fatalf("пустая ведомость при полностью заштампованных отчётах покраснела — "+
				"гейт краснеет на достижении собственной цели.\n%s", strings.Join(got, "\n"))
		}

		cases := []struct {
			name, expect string
			present      []string
			ledger       []preStampReport
			stamped      map[string]bool
		}{
			{
				name:    "новый отчёт не накрыт ни штампом, ни ведомостью",
				present: append(append([]string{}, present...), "REPORT-three.raw.txt"),
				ledger:  ledger, stamped: stampedNone,
				expect: "не накрыт НИЧЕМ — ни отпечатком, ни ведомостью: REPORT-three.raw.txt",
			},
			{
				name:    "записи ведомости больше нечего исключать — файла нет",
				present: []string{"REPORT-one.raw.txt"},
				ledger:  ledger, stamped: stampedNone,
				expect: "запись ведомости без предмета: REPORT-two.txt",
			},
			{
				name:    "файл ведомости УЖЕ несёт отпечаток",
				present: present, ledger: ledger,
				stamped: map[string]bool{"REPORT-two.txt": true},
				expect:  "который УЖЕ несёт отпечаток: REPORT-two.txt",
			},
			{
				name:    "ведомость разошлась с шапкой по ревизии",
				present: present,
				ledger: []preStampReport{
					{file: "REPORT-one.raw.txt", rev: "bbbbbbbb", why: "машинный доштамповый"},
					{file: "REPORT-two.txt", why: "разбор человека"}},
				stamped: stampedNone,
				expect:  `в ведомости "bbbbbbbb", в шапке "aaaaaaaa"`,
			},
			{
				name:    "в каталоге ноль отчётов — у предиката исчез предмет",
				present: nil, ledger: nil, stamped: stampedNone,
				expect: "НОЛЬ отчётов",
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got := judgeLedger(c.present, c.ledger, c.stamped, revOf)
				if len(got) == 0 {
					t.Fatalf("полоса B СМОЛЧАЛА на инъекции %q: плечо не способно упасть", c.name)
				}
				if joined := strings.Join(got, "\n"); !strings.Contains(joined, c.expect) {
					t.Errorf("покраснела, но НЕ НАЗВАЛА предмет: ожидалось %q.\n%s",
						c.expect, joined)
				}
			})
		}
	})
}

// ── вспомогательное ─────────────────────────────────────────────────────────

func benchRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("корень дерева не установлен (%v): гейту негде искать отчёты, и его молчание "+
			"не означало бы свежести", err)
	}
	return root
}

// benchReportFiles — отчёты каталога прибора.
func benchReportFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "REPORT-") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// benchInstrumentFilesMovedSince — .go прибора, различающиеся между ревизией и
// РАБОЧИМ ДЕРЕВОМ.
//
// Рабочим, а не `HEAD`: правка, ещё не закоммиченная, — тоже сдвиг прибора, и
// граница, считающая её неподвижностью, лгала бы ровно в момент правки.
func benchInstrumentFilesMovedSince(root, rev string) ([]string, error) {
	cmd := gitenv.Command(root, "diff", "--name-only", rev, "--", benchDir)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var moved []string
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasSuffix(ln, ".go") {
			moved = append(moved, strings.TrimPrefix(ln, benchDir+"/"))
		}
	}
	sort.Strings(moved)
	return moved, nil
}

func benchRecordedRev(text string) string {
	for _, m := range benchReportRevMarks {
		if v := benchValueAfter(text, m); v != "" {
			return v
		}
	}
	return ""
}

func benchReportDate(text string) (time.Time, error) {
	var raw string
	for _, m := range benchReportDateMarks {
		if v := benchValueAfter(text, m); v != "" {
			raw = v
			break
		}
	}
	if raw == "" {
		return time.Time{}, fmt.Errorf("строки даты в шапке нет")
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05 MST"} {
		if when, err := time.Parse(layout, raw); err == nil {
			return when, nil
		}
	}
	return time.Time{}, fmt.Errorf("дата %q не разобрана ни одним известным форматом", raw)
}

func benchValueAfter(text, marker string) string {
	i := strings.Index(text, marker)
	if i < 0 {
		return ""
	}
	rest := text[i+len(marker):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func benchRecordedFileHashes(text string) map[string]string {
	out := map[string]string{}
	i := strings.Index(text, MarkerFileList)
	if i < 0 {
		return out
	}
	for _, line := range strings.Split(text[i+len(MarkerFileList):], "\n") {
		if !strings.HasPrefix(line, MarkerFile) {
			if strings.TrimSpace(line) == "" {
				continue
			}
			break
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		out[fields[1]] = fields[0]
	}
	return out
}

func benchKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func benchDiffSets(was, now []string) (added, removed []string) {
	inWas := map[string]bool{}
	for _, s := range was {
		inWas[s] = true
	}
	inNow := map[string]bool{}
	for _, s := range now {
		inNow[s] = true
		if !inWas[s] {
			added = append(added, s)
		}
	}
	for _, s := range was {
		if !inNow[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func benchJoinOrDash(v []string) string {
	if len(v) == 0 {
		return "—"
	}
	return strings.Join(v, ", ")
}

func benchOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func benchContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestStampedHeaderIsReadBackByTheGate — ПИСАТЕЛЬ И ЧИТАТЕЛЬ ОТПЕЧАТКА СОШЛИСЬ.
//
// Полоса A сегодня судит НОЛЬ настоящих отчётов: все десять сняты до штампа.
// Значит её плечи проверены только синтетикой, а синтетику писал тот же человек,
// что и разбор шапки, — и если писатель штампа печатает не те приставки, обе
// стороны согласятся друг с другом и разойдутся с действительностью.
//
// Поэтому здесь шапку печатает НАСТОЯЩИЙ писатель (`FingerprintHeader`), а читает
// НАСТОЯЩИЙ разбор гейта. Проба падает ровно тогда, когда следующий отчёт
// приедет со штампом, которого гейт не увидит, — то есть ДО того, как это станет
// незаметным зелёным.
func TestStampedHeaderIsReadBackByTheGate(t *testing.T) {
	root := benchRepoRoot(t)

	fp, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток прибора не вычислен: %v", err)
	}
	if len(fp.Files) == 0 {
		t.Fatalf("под отпечатком НОЛЬ файлов прибора: сверять нечего, и «совпало» означало бы "+
			"«не с чем сравнивать» (предикат: %s)", fp.Predicate)
	}

	// Шапка — та самая, что уедет в настоящий отчёт, плюс строка даты, которую
	// печатает провенанс каждого писателя.
	header := benchReportDateMarks[0] + time.Now().Format(time.RFC3339) + "\n" + FingerprintHeader()

	t.Logf("шапка писателя: файлов под отпечатком %d, состав %s, содержимое %s",
		len(fp.Files), fp.Composition, fp.Content)

	// ЗАКОННЫЙ БЛИЗНЕЦ: шапка, снятая сейчас, на неподвижном дереве — МОЛЧАНИЕ.
	if got := judgeBenchReport(header, fp, func(rel string) string {
		return ContentOf(root, rel)
	}, time.Now()); len(got) != 0 {
		t.Fatalf("гейт НЕ ПРОЧИТАЛ шапку, напечатанную писателем прибора: приставки писателя и "+
			"разбор гейта разошлись, и следующий отчёт со штампом читался бы как беcштамповый.\n%s",
			strings.Join(got, "\n"))
	}

	// И обратная сторона: та же шапка против СДВИНУВШЕГОСЯ прибора обязана
	// покраснеть — иначе молчание выше означало бы, что разбор ничего не читает.
	moved := fp
	moved.Content = "MOVED00000000001"
	got := judgeBenchReport(header, moved, func(rel string) string { return "MOVEDFILEHASH001" }, time.Now())
	if len(got) == 0 {
		t.Fatalf("гейт СМОЛЧАЛ на шапке писателя при сдвинувшемся приборе: значит он её не " +
			"разбирает вовсе, и молчание законного близнеца ничего не означало")
	}
	if !strings.Contains(strings.Join(got, "\n"), "ПРИБОР СДВИНУЛСЯ") {
		t.Errorf("покраснел не тем плечом: %s", strings.Join(got, "\n"))
	}
}
