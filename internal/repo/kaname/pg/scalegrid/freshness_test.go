// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// scaleGridReportMaxAge — В8, величина ратифицирована владельцем.
const scaleGridReportMaxAge = 60 * 24 * time.Hour

// scaleGridReportDateMark — строка даты в шапке отчёта.
const scaleGridReportDateMark = "  снято               "

// scaleGridRunHint — КАК ПЕРЕСНЯТЬ. Отдельной строкой: сообщение отказа обязано
// говорить, что делать, а не только что не так.
const scaleGridRunHint = "KACHO_SCALEGRID_FULL=1 go test -C services/iam " +
	"./internal/repo/kaname/pg/relverdict/ -run TestScaleGrid_FullGridReport " +
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

	// Пофайловый перечень — ПРЕДПОСЫЛКА обоих плеч ниже: по нему они называют
	// виновника. Пустой означает «сверять не с чем», и молчание на нём было бы
	// неотличимо от «всё сошлось».
	if len(recordedFiles) == 0 {
		return append(findings, "в шапке отчёта НЕТ пофайлового перечня (хэш · тождество · "+
			"путь): плечи состава и содержимого назвать виновника не могут, а «совпало» "+
			"здесь означало бы «не с чем сравнивать».\n  предикат: "+predicateOf(fp))
	}

	// (г) СОСТАВ — по ТОЖДЕСТВАМ, а не по путям: переезд каталога состава не
	// меняет, приход и уход файла меняют.
	sameComposition := recordedComposition == fp.Composition
	if !sameComposition {
		added, removed := diffSets(keysOf(recordedFiles), fp.Identities)
		findings = append(findings, fmt.Sprintf(
			"СОСТАВ множества под отпечатком изменился: в отчёте %s, по дереву %s\n"+
				"  добавлено: %s\n  снято:     %s\n"+
				"  Содержимое прежних файлов от появления нового не меняется, поэтому плечо (а) "+
				"этого не ловит by construction",
			recordedComposition, fp.Composition, joinOrDash(added), joinOrDash(removed)))
	}

	// (а) СОДЕРЖИМОЕ — с ИМЕНЕМ виновника, найденным по тождеству.
	if recordedContent != fp.Content {
		var moved []string
		for i, id := range fp.Identities {
			was, known := recordedFiles[id]
			if !known {
				continue
			}
			if now := contentOf(fp.Files[i]); was.hash != now {
				moved = append(moved, fmt.Sprintf("%s (%s: было %s, стало %s)",
					id, fp.Files[i], was.hash, now))
			}
		}
		sort.Strings(moved)

		switch {
		case len(moved) > 0:
			findings = append(findings, fmt.Sprintf(
				"ПРЕДМЕТ ЗАМЕРА СДВИНУЛСЯ: отпечаток содержимого в отчёте %s, по дереву %s\n"+
					"  сдвинули его: %s\n"+
					"  Отчёт продолжает утверждать о поведении, которого в дереве больше нет",
				recordedContent, fp.Content, joinOrDash(moved)))
		case !sameComposition:
			// Расхождение объяснено плечом состава выше: ни один ОБЩИЙ файл не
			// двигался, содержимое разошлось из-за пришедшего или ушедшего.
			// Отчёт всё равно несвеж — предмет замера стал другим множеством.
			findings = append(findings, fmt.Sprintf(
				"ПРЕДМЕТ ЗАМЕРА СДВИНУЛСЯ СОСТАВОМ: отпечаток содержимого в отчёте %s, "+
					"по дереву %s, при этом НИ ОДИН общий файл не двигался\n"+
					"  Расхождение объясняется плечом состава выше (пришёл или ушёл файл), "+
					"а не правкой существующего",
				recordedContent, fp.Content))
		default:
			// Состав ТОТ ЖЕ, содержимое разошлось, а пофайловая сверка не нашла
			// ни одного расхождения. Три величины противоречат друг другу, и
			// пока противоречие не разобрано, вердикт вынесен НЕ О ТОМ.
			findings = append(findings, fmt.Sprintf(
				"ВЕРДИКТ ВЫНЕСЕН НЕ О ТОМ: отпечаток содержимого в отчёте %s, по дереву %s, "+
					"состав ТОТ ЖЕ (%s), а пофайловая сверка не нашла НИ ОДНОГО расхождения\n"+
					"  Итоговый хэш и пофайловые хэши считает один и тот же код, поэтому "+
					"расходиться они не могут: сдвинулся не предмет замера, а сам прибор — "+
					"починке подлежит он, а не отчёт",
				recordedContent, fp.Content, fp.Composition))
		}
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
			hint: "KACHO_STRENGTH_FULL=1 go test -C services/iam ./internal/repo/kaname/pg/relverdict/ " +
				"-run TestStrengthGrid_Report -count=1 -v -timeout 120m"},
		{path: scalegrid.WriteDeleteReportPath, subject: scalegrid.ComputeWriteDeleteFingerprint,
			hint: "KACHO_STRENGTH_WRITE=1 go test -C services/iam ./internal/repo/kaname/pg/ " +
				"-run TestStrengthWriteDelete_Report -count=1 -v -timeout 120m"},
	}
}

// TestScaleGridFullReportIsFreshAndItsSubjectHasNotMoved — гейт свежести.
func TestScaleGridFullReportIsFreshAndItsSubjectHasNotMoved(t *testing.T) {
	// КОРЕНЬ ОБХОДА, А НЕ ДЕРЕВО ПЛАТФОРМЫ (задача продукта #2273).
	//
	// Здесь стоял `Require`, то есть ПРОПУСК в самостоятельном клоне, и причина
	// была названа честно: словарь координат прибора выводился из состава КОРНЯ,
	// а корень в монорепо и в клоне разный — один и тот же код давал разные
	// отпечатки, и сверять записанное в шапке было не с чем.
	//
	// Причины больше нет: словарь выводится из ПОСТАВКИ модуля, и отпечаток в
	// обеих посадках один (`fingerprint_posture_test.go`). Оба операнда гейта —
	// отчёт и код — с модулем едут, поэтому пропуск здесь означал бы «условие не
	// создано» там, где оно создано, а послабление, у которого исчез предмет,
	// само есть находка.
	//
	// `RequireCorpus` пропуска не имеет by construction: обе посадки дают корень,
	// и отказ означал бы, что его нет ни у одной.
	root, _ := platformtree.RequireCorpus(t)

	reports := guardedReports()
	if len(reports) == 0 {
		t.Fatalf("под гейтом НОЛЬ отчётов: перечень пуст, и молчание гейта означало бы " +
			"свежесть, которой никто не проверял")
	}
	for _, gr := range reports {
		t.Run(gr.path, func(t *testing.T) {
			// Координата приводится к ПОСАДКЕ: отчёты едут вместе с модулем,
			// поэтому в самостоятельном клоне они лежат от его корня, без
			// приставки `services/iam`. Сложенный путь был бы верен ровно для
			// монорепо, и «отчёта нет» звучало бы там, где отчёт есть.
			body, err := os.ReadFile(platformtree.RequirePath(t, gr.path))
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

	// Синтетическое дерево: два файла с известными тождествами и отпечатками.
	fp := scalegrid.Fingerprint{
		Composition: "COMPOSITION00001",
		Content:     "CONTENT000000001",
		Identities:  []string{"вердикт/one.go", "миграции/two.sql"},
		Files:       []string{"a/one.go", "b/two.sql"},
		Tables:      []string{"kaname.access_bindings"},
	}
	// contentOf ключуется ПУТЁМ (так его зовёт гейт), перечень шапки — ТОЖДЕСТВОМ.
	content := map[string]string{
		"a/one.go": "HASHA00000000001", "b/two.sql": "HASHB00000000002",
		// те же файлы после переезда каталога: содержимое ТО ЖЕ, путь другой
		"z/one.go": "HASHA00000000001", "z/two.sql": "HASHB00000000002",
	}
	contentOf := func(rel string) string { return content[rel] }

	recorded := map[string]recordedFile{
		"вердикт/one.go":   {hash: "HASHA00000000001", path: "a/one.go"},
		"миграции/two.sql": {hash: "HASHB00000000002", path: "b/two.sql"},
	}

	report := func(when time.Time, comp, cont string, files map[string]recordedFile) string {
		var b strings.Builder
		fmt.Fprintf(&b, "%s%s\n", scaleGridReportDateMark, when.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "%s%s\n", scalegrid.MarkerComposition, comp)
		fmt.Fprintf(&b, "%s%s\n", scalegrid.MarkerContent, cont)
		fmt.Fprintf(&b, "%s\n", scalegrid.MarkerFileList)
		for _, id := range keysOf(files) {
			fmt.Fprintf(&b, "%s%s  %s  %s\n", scalegrid.MarkerFile, files[id].hash, id, files[id].path)
		}
		return b.String()
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: свежий отчёт, предмет неподвижен — гейт обязан МОЛЧАТЬ.
	// Без него всякое «покраснел» ниже зеленело бы и на исправном дереве.
	if got := judgeReport(report(fresh, fp.Composition, fp.Content, recorded), fp, contentOf, now); len(got) != 0 {
		t.Fatalf("законный близнец покраснел: свежий отчёт с неподвижным предметом обязан "+
			"проходить молча, иначе гейт краснеет на достижении собственной цели.\n%s",
			strings.Join(got, "\n"))
	}

	// ВТОРОЙ ЗАКОННЫЙ БЛИЗНЕЦ: каталог ПЕРЕЕХАЛ — пути все до одного другие,
	// тождества и содержимое те же. Гейт обязан МОЛЧАТЬ: адрес кода не есть его
	// поведение, а пересъёмка одного отчёта стоит до двух часов на живой базе.
	//
	// Именно этот случай прибор и не различал: сопоставление шло по путям, ни
	// одна пара не находилась, и «содержимое сдвинулось» печаталось без единого
	// виновника — вердикт о том, чего проверка не смотрела (#2039).
	movedTree := scalegrid.Fingerprint{
		Composition: fp.Composition, // состав по ТОЖДЕСТВАМ переезд не двигает
		Content:     fp.Content,     // содержимое то же — путь в него не входит
		Identities:  []string{"вердикт/one.go", "миграции/two.sql"},
		Files:       []string{"z/one.go", "z/two.sql"}, // каталог переименован
		Tables:      fp.Tables,
	}
	if got := judgeReport(report(fresh, fp.Composition, fp.Content, recorded),
		movedTree, contentOf, now); len(got) != 0 {
		t.Fatalf("гейт покраснел на ЧИСТОМ ПЕРЕИМЕНОВАНИИ: ни один оператор не изменился, "+
			"а отчёт объявлен несвежим — это ложная тревога ценой двухчасовой пересъёмки.\n%s",
			strings.Join(got, "\n"))
	}

	cases := []struct {
		name   string
		text   string
		fp     scalegrid.Fingerprint
		expect string
	}{
		{
			// Плечо содержимого краснеет, а пофайловая сверка при неизменном
			// составе не нашла ни одного виновника. Это противоречие ВНУТРИ
			// прибора: итоговый и пофайловые хэши считает один и тот же код.
			// Раньше такое печаталось как «сдвинули его: —» и читалось как
			// вердикт о дереве.
			name:   "содержимое разошлось, состав тот же, виновника нет — ВЕРДИКТ НЕ О ТОМ",
			text:   report(fresh, fp.Composition, "OTHERCONTENT0001", recorded),
			fp:     fp,
			expect: "ВЕРДИКТ ВЫНЕСЕН НЕ О ТОМ",
		},
		{
			// Перечень — предпосылка обоих плеч: без него виновника назвать
			// нечем, и «совпало» означало бы «не с чем сравнивать».
			name: "шапка без пофайлового перечня — предпосылка плеч отсутствует",
			text: fmt.Sprintf("%s%s\n%s%s\n%s%s\n",
				scaleGridReportDateMark, fresh.Format("2006-01-02 15:04:05 MST"),
				scalegrid.MarkerComposition, fp.Composition,
				scalegrid.MarkerContent, fp.Content),
			fp:     fp,
			expect: "НЕТ пофайлового перечня",
		},
		{
			name: "(а) содержимое файла правлено — гейт называет виновника",
			text: report(fresh, fp.Composition, "OTHERCONTENT0001", map[string]recordedFile{
				"вердикт/one.go":   {hash: "WASA000000000001", path: "a/one.go"},
				"миграции/two.sql": {hash: "HASHB00000000002", path: "b/two.sql"},
			}),
			fp:     fp,
			expect: "вердикт/one.go (a/one.go: было WASA000000000001, стало HASHA00000000001)",
		},
		{
			name:   "(б) отчёт старше 60 дней",
			text:   report(now.Add(-61*24*time.Hour), fp.Composition, fp.Content, recorded),
			fp:     fp,
			expect: "СТАРШЕ предела",
		},
		{
			name:   "(в) множество под отпечатком пусто",
			text:   report(fresh, fp.Composition, fp.Content, recorded),
			fp:     scalegrid.Fingerprint{Composition: fp.Composition, Content: fp.Content, Tables: fp.Tables},
			expect: "ПУСТО",
		},
		{
			name: "(г) состав изменился, содержимое прежних файлов НЕ двигалось",
			text: report(fresh, "OLDCOMPOSITION01", fp.Content, recorded),
			fp: scalegrid.Fingerprint{
				Composition: fp.Composition, Content: fp.Content,
				Identities: []string{"вердикт/one.go", "вердикт/three.go", "миграции/two.sql"},
				Files:      []string{"a/one.go", "a/three.go", "b/two.sql"},
				Tables:     fp.Tables,
			},
			expect: "добавлено: вердикт/three.go",
		},
		{
			name:   "шапка без строк отпечатка",
			text:   fmt.Sprintf("%s%s\n", scaleGridReportDateMark, fresh.Format("2006-01-02 15:04:05 MST")),
			fp:     fp,
			expect: "нет строк отпечатка",
		},
		{
			name:   "дата не читается",
			text:   report(fresh, fp.Composition, fp.Content, recorded)[strings.Index(report(fresh, fp.Composition, fp.Content, recorded), "\n")+1:],
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

// recordedFile — строка пофайлового перечня из шапки: хэш и путь на момент замера.
type recordedFile struct {
	hash string
	path string
}

// recordedFileHashes — пофайловый перечень из шапки, КЛЮЧОМ ПО ТОЖДЕСТВУ.
//
// Ключ — тождество, а не путь: переезд каталога меняет все пути разом, и
// сопоставление по ним не находит НИ ОДНОЙ пары. Гейт тогда объявлял бы
// расхождение содержимого и не мог назвать ни одного виновника — вердикт о том,
// чего проверка не смотрела.
func recordedFileHashes(text string) map[string]recordedFile {
	out := map[string]recordedFile{}
	i := strings.Index(text, scalegrid.MarkerFileList)
	if i < 0 {
		return out
	}
	for _, line := range strings.Split(text[i+len(scalegrid.MarkerFileList):], "\n") {
		if !strings.HasPrefix(line, scalegrid.MarkerFile) {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		// Три поля по форме, а не по счёту строк: счёт разошёлся бы с шапкой при
		// первой же правке её текста.
		if len(f) != 3 || len(f[0]) != 16 || !strings.Contains(f[1], "/") || !strings.Contains(f[2], "/") {
			continue
		}
		out[f[1]] = recordedFile{hash: f[0], path: f[2]}
	}
	return out
}

func keysOf(m map[string]recordedFile) []string {
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
