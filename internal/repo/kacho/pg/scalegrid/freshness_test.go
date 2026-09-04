// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package scalegrid_test

// freshness_test.go — ГЕЙТ СВЕЖЕСТИ ПОЛНОГО ЗАМЕРА.
//
// # Что он сторожит
//
// Полная сетка прибора порядков (до 10⁶ по четырём осям) в конвейере НЕ
// гоняется: она сажает миллион объектов и миллион выдач. В конвейере идёт малая
// сетка, полная — ручным прогоном, чей отчёт лежит артефактом дерева.
//
// Послабление обязано ИСТЕКАТЬ САМО. Отчёт, снятый год назад на дереве, которого
// больше нет, — утверждение о прошлом, поданное как утверждение о настоящем; по
// самому отчёту это неразличимо, он выглядит одинаково в обоих случаях.
//
// # Почему отпечаток, а не «ревизия отчёта — предок вершины»
//
// Здесь вливают СХЛОПЫВАНИЕМ: squash рождает новый хеш, и записанная в шапке
// ревизия предком вершины не становится НИКОГДА. Гейт с таким плечом краснел бы
// на КАЖДОМ вливании, включая то, которым отчёт и приезжает, — то есть был бы
// снят первым же срабатыванием, унеся с собой и плечо возраста.
//
// # Почему гейт живёт ЗДЕСЬ, а не в internal/repohygiene
//
// Первая редакция стояла там и НЕ СОБРАЛАСЬ: `services/iam/internal/...` —
// внутренний пакет сервиса, и корневому `internal/repohygiene` язык его
// импортировать не даёт. Это не препятствие, а верная граница: гейт сверяет
// отпечаток, который считает ТА ЖЕ функция, что пишет его в шапку. Вторая её
// реализация ради переезда разошлась бы с первой молча — и разошлась бы там,
// где обе печатают «совпало».
//
// # Четыре плеча, и каждое ловит своё
//
//	(а) содержимое — файл под отпечатком правлен; гейт НАЗЫВАЕТ виновника;
//	(б) возраст    — отчёт старше 60 дней (величина ратифицирована владельцем);
//	(в) пустота    — у предиката исчез предмет, и «совпало» тогда означает
//	                 «не с чем сравнивать»;
//	(г) состав     — файл добавлен или снят, даже если прежние неподвижны.
//
// Плечо (г) не покрывается плечом (а) BY CONSTRUCTION: содержимое прежних файлов
// от появления нового не меняется.
//
// # Способность упасть ДОКАЗАНА, а не заявлена
//
// Вердикт вынесен ЧИСТОЙ функцией (`judgeReport`), поэтому её можно накормить
// настоящим отчётом и синтетическим. Инъекция ниже проверяет обе стороны: по
// плечу на каждое расхождение — красное с координатой, и ЗАКОННЫЙ БЛИЗНЕЦ
// (свежий отчёт, неподвижный предмет) — молчание.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/internal/gitenv"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/scalegrid"
)

// scaleGridReportMaxAge — В8, величина ратифицирована владельцем.
const scaleGridReportMaxAge = 60 * 24 * time.Hour

// scaleGridReportDateMark — строка даты в шапке отчёта.
const scaleGridReportDateMark = "  снято               "

// scaleGridRunHint — КАК ПЕРЕСНЯТЬ. Отдельной строкой: сообщение отказа обязано
// говорить, что делать, а не только что не так.
const scaleGridRunHint = "KACHO_SCALEGRID_FULL=1 go test " +
	"./services/iam/internal/repo/kacho/pg/relverdict/ -run TestScaleGrid_FullGridReport " +
	"-count=1 -v -timeout 120m"

// ── ВЕРДИКТ: ЧИСТАЯ ФУНКЦИЯ ─────────────────────────────────────────────────

// judgeReport — четыре плеча над (текст отчёта, отпечаток дерева, часы).
//
// Часы ПАРАМЕТРОМ, а не `time.Now()` внутри: гейт, читающий системные часы, на
// синтетике не проверяется вовсе — «прошло 61 день» на нём не воспроизвести
// иначе как ожиданием.
func judgeReport(text string, fp scalegrid.Fingerprint,
	contentOf func(rel string) string, now time.Time) []string {
	var findings []string

	// (в) предпосылка: предмет существует.
	if len(fp.Files) == 0 {
		return append(findings, "множество файлов под отпечатком ПУСТО — у предиката исчез "+
			"предмет; «совпало» здесь означает «не с чем сравнивать», и гейт сторожил бы пустоту.\n"+
			"  предикат: "+predicateOf(fp))
	}
	if len(fp.Tables) == 0 {
		return append(findings, "из кода вердикта не выведено НИ ОДНОГО имени таблицы — "+
			"множество миграций под отпечатком пусто by construction.\n"+
			"  предикат: "+predicateOf(fp))
	}

	recordedComposition := valueAfter(text, scalegrid.MarkerComposition)
	recordedContent := valueAfter(text, scalegrid.MarkerContent)
	recordedFiles := recordedFileHashes(text)

	if recordedComposition == "" || recordedContent == "" {
		return append(findings, "в шапке отчёта нет строк отпечатка — сверять нечего, и молчание "+
			"гейта означало бы, что предмет замера неподвижен, чего никто не проверял")
	}

	// (г) состав множества.
	if recordedComposition != fp.Composition {
		added, removed := diffSets(keysOf(recordedFiles), fp.Files)
		findings = append(findings, fmt.Sprintf(
			"СОСТАВ множества под отпечатком изменился: в отчёте %s, по дереву %s\n"+
				"  добавлено: %s\n  снято:     %s\n"+
				"  Содержимое прежних файлов от появления нового не меняется, поэтому плечо (а) "+
				"этого не ловит by construction",
			recordedComposition, fp.Composition, joinOrDash(added), joinOrDash(removed)))
	}

	// (а) содержимое — с ИМЕНЕМ виновника.
	if recordedContent != fp.Content {
		var moved []string
		for _, rel := range fp.Files {
			was, known := recordedFiles[rel]
			if now := contentOf(rel); known && was != now {
				moved = append(moved, fmt.Sprintf("%s (было %s, стало %s)", rel, was, now))
			}
		}
		sort.Strings(moved)
		findings = append(findings, fmt.Sprintf(
			"ПРЕДМЕТ ЗАМЕРА СДВИНУЛСЯ: отпечаток содержимого в отчёте %s, по дереву %s\n"+
				"  сдвинули его: %s\n"+
				"  Отчёт продолжает утверждать о поведении, которого в дереве больше нет",
			recordedContent, fp.Content, joinOrDash(moved)))
	}

	// (б) возраст.
	when, err := reportDate(text)
	if err != nil {
		findings = append(findings, fmt.Sprintf(
			"дата замера из шапки не прочитана (%v): возраст неизвестен, а «неизвестен» "+
				"здесь неотличимо от «свеж»", err))
		return findings
	}
	if elapsed := now.Sub(when); elapsed > scaleGridReportMaxAge {
		findings = append(findings, fmt.Sprintf(
			"отчёт СТАРШЕ предела: снят %s, прошло %.0f дней при пределе %.0f — дерево за это "+
				"время двигалось, и утверждение о порядках описывает прошлое",
			when.Format("2006-01-02"), elapsed.Hours()/24, scaleGridReportMaxAge.Hours()/24))
	}
	return findings
}

// ── ГЕЙТ НАД НАСТОЯЩИМ ОТЧЁТОМ ──────────────────────────────────────────────

// guardedReport — отчёт под гейтом ВМЕСТЕ СО СВОИМ предметом.
//
// Отчётов стало ТРИ, и предмет у них не один: два читающих прибора сторожатся
// отпечатком кода вердикта, отчёт о записи — отпечатком материализатора. Свести
// их к одному отпечатку значило бы завести гейт, который краснеет на чужой
// правке и молчит на своей, — форму проверки без содержания.
type guardedReport struct {
	path string
	// subject — чем считается отпечаток ЭТОГО отчёта.
	subject func(root string) (scalegrid.Fingerprint, error)
	// hint — как переснять именно его.
	hint string
}

func guardedReports() []guardedReport {
	return []guardedReport{
		{path: scalegrid.ReportPath, subject: scalegrid.ComputeFingerprint, hint: scaleGridRunHint},
		{path: scalegrid.StrengthReportPath, subject: scalegrid.ComputeFingerprint,
			hint: "KACHO_STRENGTH_FULL=1 go test ./services/iam/internal/repo/kacho/pg/relverdict/ " +
				"-run TestStrengthGrid_Report -count=1 -v -timeout 120m"},
		{path: scalegrid.WriteDeleteReportPath, subject: scalegrid.ComputeWriteDeleteFingerprint,
			hint: "KACHO_STRENGTH_WRITE=1 go test ./services/iam/internal/repo/kacho/pg/ " +
				"-run TestStrengthWriteDelete_Report -count=1 -v -timeout 120m"},
	}
}

// TestScaleGridFullReportIsFreshAndItsSubjectHasNotMoved — гейт свежести.
func TestScaleGridFullReportIsFreshAndItsSubjectHasNotMoved(t *testing.T) {
	root := repoRoot(t)

	reports := guardedReports()
	if len(reports) == 0 {
		t.Fatalf("под гейтом НОЛЬ отчётов: перечень пуст, и молчание гейта означало бы " +
			"свежесть, которой никто не проверял")
	}
	for _, gr := range reports {
		t.Run(gr.path, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, gr.path))
			if err != nil {
				t.Fatalf("отчёта нет по пути %s (%v).\n"+
					"Малая сетка в конвейере утверждает отсутствие ДЕГРАДАЦИИ на двух точках; "+
					"утверждение о порядках держит ТОЛЬКО полный отчёт, и без него его не "+
					"делает никто.\nСнять: %s", gr.path, err, gr.hint)
			}
			text := string(body)

			fp, err := gr.subject(root)
			if err != nil {
				t.Fatalf("отпечаток по текущему дереву не вычислен: %v", err)
			}

			// ОБЪЁМ ОСМОТРЕННОГО — отдельное утверждение, печатается ВСЕГДА.
			age := "не установлен"
			if when, derr := reportDate(text); derr == nil {
				age = fmt.Sprintf("%.0f дней", time.Since(when).Hours()/24)
			}
			t.Logf("прогон отчёта не исполнял; последний отчёт — %s, ревизия %s, возраст %s, "+
				"файлов под отпечатком %d (в шапке записано %d), таблиц выведено %d",
				gr.path, valueAfter(text, "  ревизия дерева      "), age,
				len(fp.Files), len(recordedFileHashes(text)), len(fp.Tables))
			// ПРИЗНАК ОТБОРА печатается рядом с числом: «файлов 74» без него не
			// отличить от «файлов 115», а разница между ними — та самая ширина
			// предмета, из-за которой отчёты обесценивались без причины (#961).
			// Предикат берётся У САМОГО отпечатка, а не у читающего прибора:
			// приборов два, предметы у них РАЗНЫЕ, и константа читающего под
			// отчётом о ЗАПИСИ печатала неправду о том, что этот отчёт сторожит
			// (называла каталоги вердикта вместо каталога материализатора).
			t.Logf("признак отбора под отпечаток: %s", predicateOf(fp))

			findings := judgeReport(text, fp, func(rel string) string {
				return scalegrid.ContentOf(root, rel)
			}, time.Now())
			for _, f := range findings {
				t.Errorf("%s\n  Пересними: %s", f, gr.hint)
			}
		})
	}
}

// predicateOf — предикат отпечатка, названный им самим.
//
// Пустой означает прибор чтения: так его печатает и писатель шапки. Второго
// умолчания здесь не заводится — оно разошлось бы с первым молча.
func predicateOf(fp scalegrid.Fingerprint) string {
	if fp.Predicate == "" {
		return scalegrid.FingerprintPredicate
	}
	return fp.Predicate
}

// ── ИНЪЕКЦИЯ: ГЕЙТ СПОСОБЕН УПАСТЬ И СПОСОБЕН СМОЛЧАТЬ ──────────────────────

// TestScaleGridFreshnessGateCanFailAndCanStaySilent — контроль в обе стороны.
func TestScaleGridFreshnessGateCanFailAndCanStaySilent(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-3 * 24 * time.Hour)

	// Синтетическое дерево: два файла с известными отпечатками.
	fp := scalegrid.Fingerprint{
		Composition: "COMPOSITION00001",
		Content:     "CONTENT000000001",
		Files:       []string{"a/one.go", "b/two.sql"},
		Tables:      []string{"kacho_iam.access_bindings"},
	}
	content := map[string]string{"a/one.go": "HASHA00000000001", "b/two.sql": "HASHB00000000002"}
	contentOf := func(rel string) string { return content[rel] }

	report := func(when time.Time, comp, cont string, files map[string]string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "%s%s\n", scaleGridReportDateMark, when.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "%s%s\n", scalegrid.MarkerComposition, comp)
		fmt.Fprintf(&b, "%s%s\n", scalegrid.MarkerContent, cont)
		fmt.Fprintf(&b, "%s\n", scalegrid.MarkerFileList)
		keys := keysOf(files)
		for _, rel := range keys {
			fmt.Fprintf(&b, "%s%s  %s\n", scalegrid.MarkerFile, files[rel], rel)
		}
		return b.String()
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: свежий отчёт, предмет неподвижен — гейт обязан МОЛЧАТЬ.
	// Без него всякое «покраснел» ниже зеленело бы и на исправном дереве.
	if got := judgeReport(report(fresh, fp.Composition, fp.Content, content), fp, contentOf, now); len(got) != 0 {
		t.Fatalf("законный близнец покраснел: свежий отчёт с неподвижным предметом обязан "+
			"проходить молча, иначе гейт краснеет на достижении собственной цели.\n%s",
			strings.Join(got, "\n"))
	}

	cases := []struct {
		name   string
		text   string
		fp     scalegrid.Fingerprint
		expect string
	}{
		{
			name:   "(а) содержимое файла правлено — гейт называет виновника",
			text:   report(fresh, fp.Composition, "OTHERCONTENT0001", map[string]string{"a/one.go": "WASA000000000001", "b/two.sql": "HASHB00000000002"}),
			fp:     fp,
			expect: "a/one.go (было WASA000000000001, стало HASHA00000000001)",
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
			fp:     scalegrid.Fingerprint{Composition: fp.Composition, Content: fp.Content, Tables: fp.Tables},
			expect: "ПУСТО",
		},
		{
			name: "(г) состав изменился, содержимое прежних файлов НЕ двигалось",
			text: report(fresh, "OLDCOMPOSITION01", fp.Content, content),
			fp: scalegrid.Fingerprint{
				Composition: fp.Composition, Content: fp.Content,
				Files:  []string{"a/one.go", "a/three.go", "b/two.sql"},
				Tables: fp.Tables,
			},
			expect: "добавлено: a/three.go",
		},
		{
			name:   "шапка без строк отпечатка",
			text:   fmt.Sprintf("%s%s\n", scaleGridReportDateMark, fresh.Format("2006-01-02 15:04:05 MST")),
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
			got := judgeReport(c.text, c.fp, contentOf, now)
			if len(got) == 0 {
				t.Fatalf("гейт СМОЛЧАЛ на инъекции %q: значит это плечо не способно упасть "+
					"и его зелёное ничего не означает", c.name)
			}
			joined := strings.Join(got, "\n")
			if !strings.Contains(joined, c.expect) {
				t.Errorf("гейт покраснел, но НЕ НАЗВАЛ предмет: ожидалось вхождение %q.\n%s",
					c.expect, joined)
			}
		})
	}
}

// ── вспомогательное ─────────────────────────────────────────────────────────

// repoRoot — корень дерева.
//
// Спрашивается у git через `internal/gitenv`, а не собирается из `..`: число
// шагов вверх зависит от того, где лежит вызывающий, и переезд файла молча увёл
// бы гейт смотреть в другой каталог. Прямой `exec.Command("git", …)` в этом
// дереве — находка отдельного гейта: унаследованные `GIT_DIR`/`GIT_INDEX_FILE`
// увели бы команду в чужой репозиторий.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("корень дерева не установлен (%v): гейту негде искать отчёт, и его молчание "+
			"не означало бы свежести", err)
	}
	return strings.TrimSpace(string(out))
}

func valueAfter(text, marker string) string {
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

// recordedFileHashes — пофайловые отпечатки из шапки отчёта.
func recordedFileHashes(text string) map[string]string {
	out := map[string]string{}
	i := strings.Index(text, scalegrid.MarkerFileList)
	if i < 0 {
		return out
	}
	for _, line := range strings.Split(text[i+len(scalegrid.MarkerFileList):], "\n") {
		if !strings.HasPrefix(line, scalegrid.MarkerFile) {
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

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func diffSets(was, now []string) (added, removed []string) {
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

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "—"
	}
	return strings.Join(v, ", ")
}

func reportDate(text string) (time.Time, error) {
	raw := valueAfter(text, scaleGridReportDateMark)
	if raw == "" {
		return time.Time{}, fmt.Errorf("строки %q в шапке нет", strings.TrimSpace(scaleGridReportDateMark))
	}
	// Формат — тот же, каким его пишет `Provenance.Header`.
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700"} {
		if when, err := time.Parse(layout, raw); err == nil {
			return when, nil
		}
	}
	return time.Time{}, fmt.Errorf("дата %q не разобрана ни одним известным форматом", raw)
}
