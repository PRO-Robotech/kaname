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
// Базовый отпечаток считает `scalegrid.ComputeFingerprint`: путь ЧТЕНИЯ
// (не-тестовые файлы relverdict и scalegrid плюс миграции). Продуктовый писатель
// выдач под него НЕ попадает. Значит правка пути записи НЕ сделает этот отчёт
// несвежим, и молчание гейта неподвижности пути записи НЕ доказывает.
// Отпечаток писателя сюда не добавляем. Matrix-local расширение ниже включает
// оснастку Given/замера: её изменение тоже требует настоящей пересъёмки.
//
// # Способность упасть ДОКАЗАНА, а не заявлена
//
// Вердикт вынесен ЧИСТОЙ функцией (часы — параметром, а не `time.Now()` внутри),
// поэтому её можно накормить настоящим отчётом и синтетическим. Инъекция ниже
// проверяет ОБЕ стороны: по плечу на каждое расхождение — красное с
// координатой, и ЗАКОННЫЙ БЛИЗНЕЦ (свежий отчёт, неподвижный предмет) —
// молчание.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"github.com/PRO-Robotech/kaname/internal/treeposture"
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

	// Пофайловый перечень — ПРЕДПОСЫЛКА обоих плеч ниже: по нему они называют
	// виновника. Пустой означает «сверять не с чем».
	if len(recorded) == 0 {
		return append(findings, "в шапке отчёта НЕТ пофайлового перечня (хэш · тождество · "+
			"путь): плечи состава и содержимого назвать виновника не могут, а «совпало» "+
			"здесь означало бы «не с чем сравнивать»")
	}

	// (в) СОСТАВ — по ТОЖДЕСТВАМ, а не по путям: переезд каталога состава не
	// меняет, приход и уход файла меняют.
	sameComposition := recordedComposition == fp.Composition
	if !sameComposition {
		var added, removed []string
		have := map[string]bool{}
		for _, id := range fp.Identities {
			have[id] = true
			if _, ok := recorded[id]; !ok {
				added = append(added, id)
			}
		}
		for id := range recorded {
			if !have[id] {
				removed = append(removed, id)
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

	// (а) СОДЕРЖИМОЕ — с ИМЕНЕМ виновника, найденным по тождеству: «что-то
	// сдвинулось» посылает читателя перебирать девятнадцать файлов руками.
	if recordedContent != fp.Content {
		var moved []string
		for i, id := range fp.Identities {
			was, known := recorded[id]
			if !known {
				continue
			}
			if cur := contentOf(fp.Files[i]); was.hash != cur {
				moved = append(moved, fmt.Sprintf("%s (%s: было %s, стало %s)",
					id, fp.Files[i], was.hash, cur))
			}
		}
		sort.Strings(moved)

		switch {
		case len(moved) > 0:
			findings = append(findings, fmt.Sprintf(
				"ПРЕДМЕТ ЗАМЕРА СДВИНУЛСЯ: отпечаток содержимого в отчёте %s, по дереву %s\n"+
					"  сдвинули его: %s\n"+
					"  Отчёт продолжает утверждать о стоимости операций на дереве, которого больше нет",
				recordedContent, fp.Content, matrixJoinOrDash(moved)))
		case !sameComposition:
			findings = append(findings, fmt.Sprintf(
				"ПРЕДМЕТ ЗАМЕРА СДВИНУЛСЯ СОСТАВОМ: отпечаток содержимого в отчёте %s, "+
					"по дереву %s, при этом НИ ОДИН общий файл не двигался\n"+
					"  Расхождение объясняется плечом состава выше (пришёл или ушёл файл), "+
					"а не правкой существующего",
				recordedContent, fp.Content))
		default:
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

// matrixRecordedFile — строка пофайлового перечня: хэш и путь на момент замера.
type matrixRecordedFile struct {
	hash string
	path string
}

// matrixRecordedHashes — пофайловый перечень из шапки, КЛЮЧОМ ПО ТОЖДЕСТВУ.
//
// Читаются строки вида `    <хэш>  <тождество>  <путь>`; чужие строки того же
// отступа отбрасываются по форме поля, а не по счёту, — счёт разошёлся бы с
// шапкой при первой же правке её текста.
//
// Ключ — тождество, а не путь: переезд каталога меняет все пути разом, и
// сопоставление по ним не находит НИ ОДНОЙ пары. Гейт тогда объявляет
// расхождение содержимого и не может назвать ни одного виновника — вердикт о
// том, чего проверка не смотрела (kacho#2039).
func matrixRecordedHashes(text string) map[string]matrixRecordedFile {
	out := map[string]matrixRecordedFile{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, scalegrid.MarkerFile) {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 3 || len(f[0]) != 16 || !strings.Contains(f[1], "/") || !strings.Contains(f[2], "/") {
			continue
		}
		out[f[1]] = matrixRecordedFile{hash: f[0], path: f[2]}
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

// matrixRepoRoot — КОРЕНЬ ОБХОДА в той посадке, в которой идёт прогон.
//
// Здесь стоял `Require`, то есть ПРОПУСК в самостоятельном клоне, и причина была
// названа честно: словарь координат прибора выводился из состава КОРНЯ, а корень
// в монорепо и в клоне разный — один и тот же код давал разные отпечатки.
//
// Причины больше нет (задача продукта kacho#2273): словарь выводится из ПОСТАВКИ
// модуля, и отпечаток в обеих посадках один — это утверждает гейт-сосед
// `scalegrid/fingerprint_posture_test.go`. Оба операнда — отчёт и код — с
// модулем едут, поэтому пропуск означал бы «условие не создано» там, где оно
// создано.
func matrixRepoRoot(t *testing.T) string {
	t.Helper()
	root, _ := platformtree.RequireCorpus(t)
	return root
}

// matrixFixtureFiles — локальное замыкание Given/замера и конфигурация TestMain
// сверх базового read-path отпечатка: общий ComputeFingerprint исключает *_test.go.
// Включены вызываемые exec, capture, tuplesRead, мост к SQL/оси и определение
// самого списка. Целиком файлы: изменение соседней пробы может дать лишнюю
// пересъёмку, но изменение общего helper не останется невидимым.
//
// Граница TestMain явная: SearchPath/Name/Migrate здесь под отпечатком. Реализация
// импортированного corelib/pgtest, pgx, migrations.FS и среда Postgres — внешняя
// инфраструктура, не замыкание локальных тестовых функций. Версии зависимостей
// определяет go.mod/go.sum; DDL покрывает прежний read-path предикат, а не все
// миграции/триггеры записи. Это не отпечаток всего исполняемого бинаря/сервера.
// Пути — координаты поставки; ContentOf сохраняет её переносимость. Этот список
// влияет только на matrix report, не на соседние full-grid/strength reports.
var matrixFixtureFiles = []struct{ identity, path string }{
	{"матрица/matrix_volume_integration_test.go", "services/iam/internal/repo/kaname/pg/relverdict/matrix_volume_integration_test.go"},
	{"матрица/matrix_volume_freshness_test.go", "services/iam/internal/repo/kaname/pg/relverdict/matrix_volume_freshness_test.go"},
	{"матрица/matrix_volume_report_test.go", "services/iam/internal/repo/kaname/pg/relverdict/matrix_volume_report_test.go"},
	{"матрица/r7_cost_bounded_seed_integration_test.go", "services/iam/internal/repo/kaname/pg/relverdict/r7_cost_bounded_seed_integration_test.go"},
	{"матрица/scalegrid_probe_integration_test.go", "services/iam/internal/repo/kaname/pg/relverdict/scalegrid_probe_integration_test.go"},
	{"матрица/activewayin.go", "services/iam/internal/testsupport/activewayin/activewayin.go"},
	{"матрица/query_integration_test.go", "services/iam/internal/repo/kaname/pg/relverdict/query_integration_test.go"},
	{"матрица/planrows_live_integration_test.go", "services/iam/internal/repo/kaname/pg/relverdict/planrows_live_integration_test.go"},
	{"матрица/list_page_cost_integration_test.go", "services/iam/internal/repo/kaname/pg/relverdict/list_page_cost_integration_test.go"},
	{"матрица/export_test.go", "services/iam/internal/repo/kaname/pg/relverdict/export_test.go"},
	{"матрица/grantarm_assembly_test.go", "services/iam/internal/repo/kaname/pg/relverdict/grantarm_assembly_test.go"},
	{"матрица/testmain_pgtest_test.go", "services/iam/internal/repo/kaname/pg/relverdict/testmain_pgtest_test.go"},
}

func matrixFingerprint(root string) (scalegrid.Fingerprint, error) {
	fp, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		return fp, err
	}
	return matrixFingerprintWithFixtures(fp, func(path string) string {
		return scalegrid.ContentOf(root, path)
	})
}

// Базовый digest не пересчитываем своим разбором Go/SQL: сохраняем его целиком
// и доменно отделённо дописываем тождества и те же ContentOf, что печатает Header.
// Нечитаемая обязательная зависимость — ошибка, а не хэш строки «нечитаем».
func matrixFingerprintWithFixtures(fp scalegrid.Fingerprint, contentOf func(string) string) (scalegrid.Fingerprint, error) {
	if len(fp.Files) == 0 || len(fp.Files) != len(fp.Identities) || fp.Composition == "" || fp.Content == "" {
		return fp, fmt.Errorf("матрица: неполный базовый отпечаток")
	}
	files := make(map[string]string, len(fp.Files)+len(matrixFixtureFiles))
	for i, id := range fp.Identities {
		if _, exists := files[id]; exists {
			return fp, fmt.Errorf("матрица: повторное тождество %s", id)
		}
		files[id] = fp.Files[i]
	}
	composition := sha256.New()
	content := sha256.New()
	fmt.Fprintf(composition, "matrix-fixtures-v1\n%s\n", fp.Composition)
	fmt.Fprintf(content, "matrix-fixtures-v1\n%s\n", fp.Content)
	for _, file := range matrixFixtureFiles {
		if _, exists := files[file.identity]; exists {
			return fp, fmt.Errorf("матрица: повторное тождество %s", file.identity)
		}
		sum := contentOf(file.path)
		if decoded, err := hex.DecodeString(sum); err != nil || len(decoded) != 8 {
			return fp, fmt.Errorf("матрица: зависимость %s не прочитана: %s", file.identity, sum)
		}
		files[file.identity] = file.path
		fmt.Fprintf(composition, "%s\n", file.identity)
		fmt.Fprintf(content, "%s\n%s\n", file.identity, sum)
	}
	fp.Identities = make([]string, 0, len(files))
	for id := range files {
		fp.Identities = append(fp.Identities, id)
	}
	sort.Strings(fp.Identities)
	fp.Files = make([]string, 0, len(files))
	for _, id := range fp.Identities {
		fp.Files = append(fp.Files, files[id])
	}
	fp.Composition = hex.EncodeToString(composition.Sum(nil))[:16]
	fp.Content = hex.EncodeToString(content.Sum(nil))[:16]
	fp.Predicate += "; дополнительно matrix-local замыкание оснастки: " + strings.Join(fp.Identities, ", ") +
		"; matrix-fixtures-v1 сохраняет базовые digest и добавляет тождества/ContentOf обязательных fixture-файлов"
	return fp, nil
}

// matrixFixturePath приводит обе записи координаты к явно названному корню.
func matrixFixturePath(t *testing.T, root, rel string) string {
	t.Helper()
	path, err := treeposture.PathUnder(root, rel)
	if err != nil {
		t.Fatalf("координата %s: %v", rel, err)
	}
	return path
}

// Проверяется реальный путь matrixFingerprint -> ComputeFingerprint/ContentOf,
// включая нормализацию координат и verdict. Только копии в t.TempDir: исходная
// поставка читается, но ни одна инъекция не пишет в неё. SQL здесь лишь текст
// для парсера отпечатка; подключений к базе и запуска полного замера нет.
func TestMatrixVolumeFingerprintIncludesItsFixtureClosure(t *testing.T) {
	sourceRoot := matrixRepoRoot(t)
	moduleCoord := treeposture.ModuleDirInPlatform()
	verdictDir := moduleCoord + "/internal/repo/kaname/pg/relverdict"
	gridDir := moduleCoord + "/internal/repo/kaname/pg/scalegrid"
	read := func(t *testing.T, root, rel string) []byte {
		t.Helper()
		body, err := os.ReadFile(matrixFixturePath(t, root, rel))
		if err != nil {
			t.Fatalf("чтение копируемой зависимости %s: %v", rel, err)
		}
		return body
	}
	write := func(t *testing.T, root, rel string, body []byte) {
		t.Helper()
		path := matrixFixturePath(t, root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Конечное дерево: один минимальный read-path/DDL, реальные не-тестовые
	// файлы scalegrid (включая обязательную оснастку) и все реальные fixture-
	// файлы. Ни обход всего репозитория, ни копия всей истории миграций не нужны.
	bodies := map[string][]byte{
		moduleCoord + "/go.mod":                               read(t, sourceRoot, moduleCoord+"/go.mod"),
		verdictDir + "/query.go":                              []byte("package relverdict\nconst query = `SELECT id FROM kaname.access_bindings`\n"),
		moduleCoord + "/internal/migrations/0001_initial.sql": []byte("CREATE TABLE kaname.access_bindings (id text PRIMARY KEY);\n"),
	}
	entries, err := os.ReadDir(matrixFixturePath(t, sourceRoot, gridDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			rel := gridDir + "/" + entry.Name()
			bodies[rel] = read(t, sourceRoot, rel)
		}
	}
	for _, file := range matrixFixtureFiles {
		bodies[file.path] = read(t, sourceRoot, file.path)
	}
	build := func(t *testing.T, platform bool) string {
		t.Helper()
		root := t.TempDir()
		if platform {
			if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(moduleCoord)), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		for rel, body := range bodies {
			write(t, root, rel, body)
		}
		return root
	}
	root := build(t, false)
	good, err := matrixFingerprint(root)
	if err != nil {
		t.Fatalf("реальное полное замыкание не принято: %v", err)
	}
	base, err := scalegrid.ComputeFingerprint(root)
	if err != nil || len(good.Files) != len(base.Files)+len(matrixFixtureFiles) {
		t.Fatalf("замыкание не добавлено к реальному базовому отпечатку: %v", err)
	}
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	report := matrixReportDateMark + now.Format("2006-01-02 15:04:05 MST") + "\n" + good.FingerprintLines(root)
	judge := func(root string, fp scalegrid.Fingerprint) []string {
		return judgeMatrixReport(report, fp, func(rel string) string {
			return scalegrid.ContentOf(root, rel)
		}, now)
	}
	if got := judge(root, good); len(got) != 0 {
		t.Fatalf("неподвижные файлы отвергнуты: %v", got)
	}
	platformRoot := build(t, true)
	moved, err := matrixFingerprint(platformRoot)
	if err != nil || moved.Composition != good.Composition || moved.Content != good.Content {
		t.Fatalf("перенос того же модуля меняет отпечаток: %v", err)
	}
	if got := judge(platformRoot, moved); len(got) != 0 {
		t.Fatalf("законный перенос модуля отвергнут: %v", got)
	}

	// По одному изменению поведения в каждом обязательном файле. Это
	// независимый перечень controls: удаление зависимости из closure тоже
	// роняет пробу, а не удаляет вместе с ней единственный отрицательный случай.
	mutations := map[string]struct{ before, after string }{
		"матрица/matrix_volume_integration_test.go":        {"const matrixRepeats = 11", "const matrixRepeats = 12"},
		"матрица/matrix_volume_freshness_test.go":          {"const matrixReportMaxAge = 60 * 24 * time.Hour", "const matrixReportMaxAge = 61 * 24 * time.Hour"},
		"матрица/matrix_volume_report_test.go":             {"const matrixFlatCeiling = 2.0", "const matrixFlatCeiling = 3.0"},
		"матрица/r7_cost_bounded_seed_integration_test.go": {"const r7CostSeedBatch = 128", "const r7CostSeedBatch = 127"},
		"матрица/scalegrid_probe_integration_test.go":      {"const probeRepeats = 21", "const probeRepeats = 22"},
		"матрица/activewayin.go":                           {"fixture-password-row-without-a-known-password", "changed-fixture-password-row-without-a-known-password"},
		"матрица/query_integration_test.go":                {"tx.Exec(ctx, sql, args...)", "tx.Exec(ctx, sql)"},
		"матрица/planrows_live_integration_test.go":        {"args: d.Args", "args: nil"},
		"матрица/list_page_cost_integration_test.go":       {"sum(seq_tup_read + coalesce(idx_tup_fetch, 0))", "sum(seq_tup_read + 1 + coalesce(idx_tup_fetch, 0))"},
		"матрица/export_test.go":                           {"withNesting(verdictQuerySQL, false)", "withNesting(verdictQuerySQL, true)"},
		"матрица/grantarm_assembly_test.go":                {"build(labelTable, nesting)", "build(labelTable, !nesting)"},
		"матрица/testmain_pgtest_test.go":                  {`SearchPath: "kaname,public"`, `SearchPath: "public"`},
	}
	if len(mutations) != len(matrixFixtureFiles) {
		t.Fatalf("controls/обязательные зависимости разошлись: %d/%d", len(mutations), len(matrixFixtureFiles))
	}
	for _, file := range matrixFixtureFiles {
		t.Run(file.identity, func(t *testing.T) {
			original := bodies[file.path]
			t.Cleanup(func() { write(t, root, file.path, original) })
			mutation, ok := mutations[file.identity]
			if !ok || !strings.Contains(string(original), mutation.before) {
				t.Fatalf("значащий control для %s отсутствует или устарел", file.identity)
			}
			// Оба написания читают ОДИН файл через настоящий ContentOf.
			local := strings.TrimPrefix(file.path, moduleCoord+"/")
			if a, b := scalegrid.ContentOf(root, file.path), scalegrid.ContentOf(root, local); a == "нечитаем" || a != b {
				t.Fatalf("каноническая и модульная координаты разошлись: %s / %s", a, b)
			}
			write(t, root, file.path, append(append([]byte{}, original...), []byte("\n// matrix fingerprint comment-only control\n")...))
			comment, err := matrixFingerprint(root)
			if err != nil || comment.Content != good.Content || comment.Composition != good.Composition {
				t.Fatalf("комментарий меняет отпечаток %s: %v", file.identity, err)
			}
			if got := judge(root, comment); len(got) != 0 {
				t.Fatalf("комментарий отвергнут: %v", got)
			}

			// Значащий оператор меняется в настоящем Go-файле, а не в callback.
			write(t, root, file.path, []byte(strings.Replace(string(original), mutation.before, mutation.after, 1)))
			changed, err := matrixFingerprint(root)
			if err != nil || changed.Content == good.Content || changed.Composition != good.Composition {
				t.Fatalf("значащая правка %s не меняет только содержимое: %v", file.identity, err)
			}
			if got := judge(root, changed); len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), file.identity) {
				t.Fatalf("правка %s не отвергнута с именем виновника: %v", file.identity, got)
			}
			if err := os.Remove(matrixFixturePath(t, root, file.path)); err != nil {
				t.Fatal(err)
			}
			if _, err := matrixFingerprint(root); err == nil || !strings.Contains(err.Error(), file.identity) {
				t.Fatalf("пропавшая обязательная зависимость %s не отвергнута с именем: %v", file.identity, err)
			}
			write(t, root, file.path, original)
		})
	}
	unchanged, err := matrixFingerprint(root)
	if err != nil || unchanged.Content != good.Content || unchanged.Composition != good.Composition {
		t.Fatalf("восстановленные файлы разошлись: %v", err)
	}
	if got := judge(root, unchanged); len(got) != 0 {
		t.Fatalf("восстановленный законный близнец отвергнут: %v", got)
	}
}

// ── ГЕЙТ НАД НАСТОЯЩИМ ОТЧЁТОМ ──────────────────────────────────────────────

// TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved — гейт свежести.
func TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved(t *testing.T) {
	root := matrixRepoRoot(t)
	path := platformtree.RequirePath(t, matrixReportPath)

	body, err := os.ReadFile(path)
	if err != nil {
		// Отсутствие отчёта — ОТКАЗ, а не пропуск: пропуск здесь означал бы, что
		// замер не делается и об этом не докладывает никто.
		t.Fatalf("отчёта %s нет (%v) — полный замер объёма не снят, и в конвейере его не "+
			"делает никто.\nСнять: %s", matrixReportPath, err, matrixRunCommand)
	}
	fp, err := matrixFingerprint(root)
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
		Identities:  []string{"вердикт/one.go", "вердикт/two.go"},
		Files:       []string{"a/one.go", "a/two.go"},
		Tables:      []string{"kaname.access_bindings"},
	}
	// contentOf ключуется ПУТЁМ (так его зовёт гейт), перечень шапки — ТОЖДЕСТВОМ.
	content := map[string]string{
		"a/one.go": "1111111111111111", "a/two.go": "2222222222222222",
		// те же файлы после переезда каталога: содержимое ТО ЖЕ, путь другой
		"z/one.go": "1111111111111111", "z/two.go": "2222222222222222",
	}
	contentOf := func(rel string) string { return content[rel] }
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	recorded := map[string]matrixRecordedFile{
		"вердикт/one.go": {hash: "1111111111111111", path: "a/one.go"},
		"вердикт/two.go": {hash: "2222222222222222", path: "a/two.go"},
	}

	report := func(when, comp, cont string, files map[string]matrixRecordedFile) string {
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
			fmt.Fprintf(&b, "%s%s  %s  %s\n", scalegrid.MarkerFile, files[k].hash, k, files[k].path)
		}
		return b.String()
	}
	fresh := "2026-08-18 10:00:00 UTC"

	t.Run("ЗАКОННЫЙ БЛИЗНЕЦ: свежий отчёт неподвижного предмета — МОЛЧАНИЕ", func(t *testing.T) {
		got := judgeMatrixReport(report(fresh, fp.Composition, fp.Content, recorded), fp, contentOf, now)
		if len(got) != 0 {
			t.Fatalf("гейт покраснел на законном близнеце — он краснеет на всём и будет снят "+
				"первым же срабатыванием:\n%s", strings.Join(got, "\n"))
		}
	})

	t.Run("СОДЕРЖИМОЕ сдвинулось — красное С ИМЕНЕМ виновника", func(t *testing.T) {
		moved := map[string]matrixRecordedFile{
			"вердикт/one.go": {hash: "1111111111111111", path: "a/one.go"},
			"вердикт/two.go": {hash: "9999999999999999", path: "a/two.go"},
		}
		got := judgeMatrixReport(report(fresh, fp.Composition, "cccccccccccccccc", moved), fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на сдвинутом содержимом")
		}
		if !strings.Contains(strings.Join(got, "\n"), "вердикт/two.go") {
			t.Fatalf("гейт не назвал виновника — читателю останется перебирать файлы руками:\n%s",
				strings.Join(got, "\n"))
		}
	})

	t.Run("СОСТАВ изменился — красное, хотя прежние файлы неподвижны", func(t *testing.T) {
		only := map[string]matrixRecordedFile{
			"вердикт/one.go": {hash: "1111111111111111", path: "a/one.go"},
		}
		got := judgeMatrixReport(report(fresh, "dddddddddddddddd", fp.Content, only), fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на изменившемся составе — плечо содержимого этого не ловит " +
				"by construction, и без плеча состава новый файл уехал бы незамеченным")
		}
		if !strings.Contains(strings.Join(got, "\n"), "вердикт/two.go") {
			t.Fatalf("гейт не назвал добавленный файл:\n%s", strings.Join(got, "\n"))
		}
	})

	t.Run("ВТОРОЙ ЗАКОННЫЙ БЛИЗНЕЦ: каталог ПЕРЕЕХАЛ — МОЛЧАНИЕ", func(t *testing.T) {
		// Пути все до одного другие, тождества и содержимое те же. Ни один
		// оператор не изменился, поэтому пересъёмка (до двух часов на живой
		// базе) не нужна. Именно этого прибор и не различал: сопоставление шло
		// по путям, ни одна пара не находилась, и «содержимое сдвинулось»
		// печаталось без единого виновника (kacho#2039).
		movedTree := scalegrid.Fingerprint{
			Composition: fp.Composition, // состав по ТОЖДЕСТВАМ переезд не двигает
			Content:     fp.Content,     // содержимое то же — путь в него не входит
			Identities:  []string{"вердикт/one.go", "вердикт/two.go"},
			Files:       []string{"z/one.go", "z/two.go"}, // каталог переименован
			Tables:      fp.Tables,
		}
		got := judgeMatrixReport(report(fresh, fp.Composition, fp.Content, recorded),
			movedTree, contentOf, now)
		if len(got) != 0 {
			t.Fatalf("гейт покраснел на ЧИСТОМ ПЕРЕИМЕНОВАНИИ — это ложная тревога ценой "+
				"двухчасовой пересъёмки:\n%s", strings.Join(got, "\n"))
		}
	})

	t.Run("СОДЕРЖИМОЕ разошлось при том же составе и без виновника — ВЕРДИКТ НЕ О ТОМ", func(t *testing.T) {
		got := judgeMatrixReport(report(fresh, fp.Composition, "eeeeeeeeeeeeeeee", recorded),
			fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на расхождении итогового хэша")
		}
		if !strings.Contains(strings.Join(got, "\n"), "ВЕРДИКТ ВЫНЕСЕН НЕ О ТОМ") {
			t.Fatalf("гейт объявил сдвиг предмета, не назвав ни одного виновника, — прежде "+
				"это печаталось как «сдвинули его: —» и читалось как вердикт о дереве:\n%s",
				strings.Join(got, "\n"))
		}
	})

	t.Run("ШАПКА БЕЗ ПОФАЙЛОВОГО ПЕРЕЧНЯ — красное", func(t *testing.T) {
		got := judgeMatrixReport(report(fresh, fp.Composition, fp.Content, nil), fp, contentOf, now)
		if len(got) == 0 {
			t.Fatal("гейт смолчал на шапке без пофайлового перечня — виновника назвать нечем")
		}
	})

	t.Run("ВОЗРАСТ сверх предела — красное", func(t *testing.T) {
		old := now.Add(-matrixReportMaxAge - 48*time.Hour).Format("2006-01-02 15:04:05 MST")
		got := judgeMatrixReport(report(old, fp.Composition, fp.Content, recorded), fp, contentOf, now)
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

	t.Logf("проверено плеч: 8 (содержимое · состав · вердикт-не-о-том · пофайловый перечень · "+
		"возраст · пустой предмет · шапка без отпечатка) плюс ДВА законных близнеца "+
		"(неподвижный предмет и чистое переименование); файлов в синтетике %d", len(fp.Files))
}
