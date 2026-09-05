// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// matrix_volume_freshness_test.go — ГЕЙТ СВЕЖЕСТИ ЗАМЕРА ОБЪЁМА.
//
// # Что он сторожит
//
// Полный замер объёма (до 10⁶ объектов И 10⁶ выдач одновременно) в конвейере НЕ
// гоняется: он сажает миллионы строк. В конвейере идёт малая сетка
// (`TestMatrixVolume_SmallGridMeasuresSomethingAndStaysFlat`), полный замер —
// ручным прогоном, чей отчёт лежит артефактом дерева.
//
// Послабление обязано ИСТЕКАТЬ САМО. Отчёт, снятый на дереве, которого больше
// нет, — утверждение о прошлом, поданное как утверждение о настоящем; по самому
// отчёту это неразличимо, он выглядит одинаково в обоих случаях.
//
// # Почему гейт живёт ЗДЕСЬ, рядом со своим прибором
//
// Путь отчёта — константа ЭТОГО пакета (`matrixReportPath`), и она стоит в
// тестовом файле намеренно: не-тестовый файл в `relverdict` или `scalegrid`
// попадает под ОТПЕЧАТОК ПРЕДМЕТА, а значит его появление сделало бы несвежими
// отчёты СОСЕДНИХ приборов — те самые, которых этот прибор не касается. Цена
// решения названа: второе написание пути положило бы отчёт мимо гейта, поэтому
// написание здесь ровно одно, и гейт читает отчёт по нему же.
//
// # Три плеча, и каждое ловит своё
//
//	(а) содержимое — файл под отпечатком правлен; гейт НАЗЫВАЕТ виновника;
//	(б) возраст    — отчёт старше предела;
//	(в) состав     — файл добавлен или снят, даже если прежние неподвижны.
//
// Плечо (в) не покрывается плечом (а) BY CONSTRUCTION: содержимое прежних файлов
// от появления нового не меняется.
//
// # ЧЕГО ЭТОТ ГЕЙТ НЕ СТОРОЖИТ — сказано вслух, а не оставлено на догадку
//
// Отпечаток считает `scalegrid.ComputeFingerprint`, и его предмет — путь ЧТЕНИЯ
// (не-тестовые файлы relverdict и scalegrid плюс миграции). Продуктовый писатель
// выдач под него НЕ попадает. Значит правка пути записи НЕ сделает этот отчёт
// несвежим, и молчание гейта неподвижности пути записи НЕ доказывает. Заводить
// здесь второй отпечаток значило бы иметь два места об одном предмете, из
// которых верно одно; поэтому предмет назван, а не удвоен.
//
// # Способность упасть ДОКАЗАНА, а не заявлена
//
// Вердикт вынесен ЧИСТОЙ функцией (часы — параметром, а не `time.Now()` внутри),
// поэтому её можно накормить настоящим отчётом и синтетическим. Инъекция ниже
// проверяет ОБЕ стороны: по плечу на каждое расхождение — красное с
// координатой, и ЗАКОННЫЙ БЛИЗНЕЦ (свежий отчёт, неподвижный предмет) —
// молчание.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// matrixReportMaxAge — предел возраста отчёта.
//
// Шестьдесят дней — та же величина, что у гейта соседнего прибора: предмет один
// (дерево движется), и два разных предела означали бы два разных представления о
// том, когда замер перестаёт описывать код.
const matrixReportMaxAge = 60 * 24 * time.Hour

// matrixReportDateMark — строка шапки, из которой читается дата замера.
// Собирается `scalegrid.Provenance.Header`, поэтому написана дословно как там.
const matrixReportDateMark = "  снято               "

// ── ВЕРДИКТ ЧИСТОЙ ФУНКЦИЕЙ ─────────────────────────────────────────────────

// judgeMatrixReport — находки по отчёту. Пустой срез означает «свеж».
//
// `contentOf` и `now` — параметры, а не обращения к миру изнутри: иначе функцию
// нельзя накормить синтетикой, и способность гейта упасть осталась бы
// заявленной.
func judgeMatrixReport(text string, fp scalegrid.Fingerprint,
	contentOf func(rel string) string, now time.Time) []string {
	var findings []string

	// (в) предпосылка: у предиката есть предмет.
	if len(fp.Files) == 0 {
		return append(findings, "множество файлов под отпечатком ПУСТО — у предиката исчез "+
			"предмет; «совпало» здесь означает «не с чем сравнивать», и гейт сторожил бы пустоту.\n"+
			"  предикат: "+scalegrid.FingerprintPredicate)
	}

	recordedComposition := matrixValueAfter(text, scalegrid.MarkerComposition)
	recordedContent := matrixValueAfter(text, scalegrid.MarkerContent)
	if recordedComposition == "" || recordedContent == "" {
		return append(findings, "в шапке отчёта нет строк отпечатка — сверять нечего, и молчание "+
			"гейта означало бы, что предмет замера неподвижен, чего никто не проверял")
	}
	recorded := matrixRecordedHashes(text)

	// (в) состав множества.
	if recordedComposition != fp.Composition {
		var added, removed []string
		have := map[string]bool{}
		for _, f := range fp.Files {
			have[f] = true
			if _, ok := recorded[f]; !ok {
				added = append(added, f)
			}
		}
		for f := range recorded {
			if !have[f] {
				removed = append(removed, f)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		findings = append(findings, fmt.Sprintf(
			"СОСТАВ множества под отпечатком изменился: в отчёте %s, по дереву %s\n"+
				"  добавлено: %s\n  снято:     %s\n"+
				"  Содержимое прежних файлов от появления нового не меняется, поэтому плечо "+
				"содержимого этого не ловит by construction",
			recordedComposition, fp.Composition,
			matrixJoinOrDash(added), matrixJoinOrDash(removed)))
	}

	// (а) содержимое — с ИМЕНЕМ виновника: «что-то сдвинулось» посылает читателя
	// перебирать восемьдесят восемь файлов руками.
	if recordedContent != fp.Content {
		var moved []string
		for _, rel := range fp.Files {
			was, known := recorded[rel]
			if cur := contentOf(rel); known && was != cur {
				moved = append(moved, fmt.Sprintf("%s (было %s, стало %s)", rel, was, cur))
			}
		}
		sort.Strings(moved)
		findings = append(findings, fmt.Sprintf(
			"ПРЕДМЕТ ЗАМЕРА СДВИНУЛСЯ: отпечаток содержимого в отчёте %s, по дереву %s\n"+
				"  сдвинули его: %s\n"+
				"  Отчёт продолжает утверждать о стоимости операций на дереве, которого больше нет",
			recordedContent, fp.Content, matrixJoinOrDash(moved)))
	}

	// (б) возраст.
	when, err := matrixReportDate(text)
	if err != nil {
		return append(findings, fmt.Sprintf(
			"дата замера из шапки не прочитана (%v): возраст неизвестен, а «неизвестен» здесь "+
				"неотличимо от «свеж»", err))
	}
	if elapsed := now.Sub(when); elapsed > matrixReportMaxAge {
		findings = append(findings, fmt.Sprintf(
			"отчёт СТАРШЕ предела: снят %s, прошло %.0f дней при пределе %.0f — дерево за это "+
				"время двигалось, и утверждение о стоимости операций описывает прошлое",
			when.Format("2006-01-02"), elapsed.Hours()/24, matrixReportMaxAge.Hours()/24))
	}
	return findings
}

func matrixValueAfter(text, marker string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, marker) {
			return strings.TrimSpace(strings.TrimPrefix(line, marker))
		}
	}
	return ""
}

// matrixRecordedHashes — пофайловые отпечатки из шапки.
//
// Читаются строки вида `    <хэш>  <путь>`; чужие строки того же отступа
// отбрасываются по форме поля, а не по счёту, — счёт разошёлся бы с шапкой при
// первой же правке её текста.
func matrixRecordedHashes(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, scalegrid.MarkerFile) {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 2 || len(f[0]) != 16 || !strings.Contains(f[1], "/") {
			continue
		}
		out[f[1]] = f[0]
	}
	return out
}

func matrixReportDate(text string) (time.Time, error) {
	v := matrixValueAfter(text, matrixReportDateMark)
	if v == "" {
		return time.Time{}, fmt.Errorf("строка %q в шапке не найдена", strings.TrimSpace(matrixReportDateMark))
	}
	return time.Parse("2006-01-02 15:04:05 MST", v)
}

func matrixJoinOrDash(xs []string) string {
	if len(xs) == 0 {
		return "—"
	}
	return strings.Join(xs, ", ")
}

func matrixRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("корень дерева не установлен: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ── ГЕЙТ НАД НАСТОЯЩИМ ОТЧЁТОМ ──────────────────────────────────────────────

// TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved — гейт свежести.
func TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved(t *testing.T) {
	root := matrixRepoRoot(t)
	path := filepath.Join(root, matrixReportPath)

	body, err := os.ReadFile(path)
	if err != nil {
		// Отсутствие отчёта — ОТКАЗ, а не пропуск: пропуск здесь означал бы, что
		// замер не делается и об этом не докладывает никто.
		t.Fatalf("отчёта %s нет (%v) — полный замер объёма не снят, и в конвейере его не "+
			"делает никто.\nСнять: %s", matrixReportPath, err, matrixRunCommand)
	}
	fp, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток предмета замера не вычислен: %v", err)
	}
	text := string(body)

	findings := judgeMatrixReport(text, fp,
		func(rel string) string { return scalegrid.ContentOf(root, rel) }, time.Now())
	for _, f := range findings {
		t.Errorf("%s\n  Переснять: %s", f, matrixRunCommand)
	}

	// Объём осмотренного печатается ВСЕГДА: без него «ноль находок» неотличимо
	// от «ноль прочитанного».
	age := "не прочитан"
	if when, derr := matrixReportDate(text); derr == nil {
		age = fmt.Sprintf("%.0f дней", time.Since(when).Hours()/24)
	}
	t.Logf("полный замер объёма в ЭТОМ прогоне не исполнялся; последний отчёт — %s, "+
		"ревизия %s, возраст %s, файлов под отпечатком %d (в шапке записано %d), "+
		"таблиц выведено %d, точек в сетке %d",
		matrixReportPath, matrixValueAfter(text, "  ревизия дерева      "), age,
		len(fp.Files), len(matrixRecordedHashes(text)), len(fp.Tables), len(matrixPoints))
}

// ── ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ ──────────────────────────────────────────────────

// TestMatrixVolumeFreshnessGateCanFailAndCanStaySilent — способность гейта
// упасть и способность смолчать, обе доказаны на синтетике.
//
// Без первой половины гейт неотличим от отсутствующего; без второй — от
// сломанного, который краснеет на всём и будет снят первым же срабатыванием.
func TestMatrixVolumeFreshnessGateCanFailAndCanStaySilent(t *testing.T) {
	fp := scalegrid.Fingerprint{
		Composition: "aaaaaaaaaaaaaaaa",
		Content:     "bbbbbbbbbbbbbbbb",
		Files:       []string{"a/one.go", "a/two.go"},
		Tables:      []string{"kacho_iam.access_bindings"},
	}
	content := map[string]string{"a/one.go": "1111111111111111", "a/two.go": "2222222222222222"}
	contentOf := func(rel string) string { return content[rel] }
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	report := func(when, comp, cont string, files map[string]string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "%s%s\n", matrixReportDateMark, when)
		fmt.Fprintf(&b, "%s%s\n", scalegrid.MarkerComposition, comp)
		fmt.Fprintf(&b, "%s%s\n", scalegrid.MarkerContent, cont)
		keys := make([]string, 0, len(files))
		for k := range files {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s%s  %s\n", scalegrid.MarkerFile, files[k], k)
		}
		return b.String()
	}
	fresh := "2026-08-18 10:00:00 UTC"

	t.Run("ЗАКОННЫЙ БЛИЗНЕЦ: свежий отчёт неподвижного предмета — МОЛЧАНИЕ", func(t *testing.T) {
		got := judgeMatrixReport(report(fresh, fp.Composition, fp.Content, content), fp, contentOf, now)
		if len(got) != 0 {
			t.Fatalf("гейт покраснел на законном близнеце — он краснеет на всём и будет снят "+
				"первым же срабатыванием:\n%s", strings.Join(got, "\n"))
		}
	})

	t.Run("СОДЕРЖИМОЕ сдвинулось — красное С ИМЕНЕМ виновника", func(t *testing.T) {
		moved := map[string]string{"a/one.go": "1111111111111111", "a/two.go": "9999999999999999"}
		got := judgeMatrixReport(report(fresh, fp.Composition, "cccccccccccccccc", moved), fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на сдвинутом содержимом")
		}
		if !strings.Contains(strings.Join(got, "\n"), "a/two.go") {
			t.Fatalf("гейт не назвал виновника — читателю останется перебирать файлы руками:\n%s",
				strings.Join(got, "\n"))
		}
	})

	t.Run("СОСТАВ изменился — красное, хотя прежние файлы неподвижны", func(t *testing.T) {
		only := map[string]string{"a/one.go": "1111111111111111"}
		got := judgeMatrixReport(report(fresh, "dddddddddddddddd", fp.Content, only), fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на изменившемся составе — плечо содержимого этого не ловит " +
				"by construction, и без плеча состава новый файл уехал бы незамеченным")
		}
		if !strings.Contains(strings.Join(got, "\n"), "a/two.go") {
			t.Fatalf("гейт не назвал добавленный файл:\n%s", strings.Join(got, "\n"))
		}
	})

	t.Run("ВОЗРАСТ сверх предела — красное", func(t *testing.T) {
		old := now.Add(-matrixReportMaxAge - 48*time.Hour).Format("2006-01-02 15:04:05 MST")
		got := judgeMatrixReport(report(old, fp.Composition, fp.Content, content), fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на просроченном отчёте")
		}
	})

	t.Run("ПРЕДМЕТ ИСЧЕЗ — красное, а не «совпало»", func(t *testing.T) {
		empty := scalegrid.Fingerprint{Composition: "x", Content: "y"}
		got := judgeMatrixReport(report(fresh, "x", "y", nil), empty, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на пустом множестве файлов — «совпало» тут означает " +
				"«не с чем сравнивать»")
		}
	})

	t.Run("ШАПКА БЕЗ ОТПЕЧАТКА — красное", func(t *testing.T) {
		got := judgeMatrixReport(matrixReportDateMark+fresh+"\n", fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на шапке без строк отпечатка")
		}
	})

	t.Logf("проверено плеч: 5 (содержимое · состав · возраст · пустой предмет · шапка без "+
		"отпечатка) плюс законный близнец; файлов в синтетике %d", len(fp.Files))
}
