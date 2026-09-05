// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// chaintables_gate_test.go — ТАБЛИЦА, КОТОРУЮ ЧИТАЕТ ЦЕПЬ, А КАТАЛОГ ЧТЕНИЯ НЕ
// НАЗЫВАЕТ НИ ОДНИМ ФАЙЛОМ, — НАХОДКА (приёмка R7-4, сценарий R7-4-16).
//
// ─────────────────────────────────────────────────────────────────────────────
// СЕГОДНЯШНЕЕ ДЕРЕВО ЭТОТ ГЕЙТ ПРОХОДИТ, и сказать это надо первым
//
// Гейт заведён ВПЕРЁД: он не сообщает о находке, он не даёт ей завестись. На
// момент посадки каталог чтения называет КАЖДУЮ таблицу, которую читает
// представление цепи, — измерено, а не предположено (перепись печатается ниже
// каждым прогоном). Гейт, выдающий себя за отчёт о находке там, где находки нет,
// был бы тем же классом, который эта под-фаза чинит в документах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ ЕСТЬ, И ОН ИЗМЕРЕН
//
// Прибор свежести (`scalegrid.ComputeFingerprint`) выводит перечень читаемых
// таблиц ИЗ ТЕКСТА не-тестовых файлов каталога чтения — по приставке имени схемы,
// а не из выписанного списка. Отсюда его сила и его слабое место разом: таблица,
// чьё имя перестало встречаться в каталоге, выпадает из-под отпечатка МОЛЧА — и
// прибор перестаёт замечать правку её миграции, продолжая выглядеть исправным.
//
// Держится это НЕ распределённо: часть имён приносит ЕДИНСТВЕННЫЙ файл каталога.
// Уедет он (переезд, переименование, вынос реестра осей меток в общий пакет,
// сокращение перечня в комментарии обхода) — основания уйдут вместе с ним, и ни
// одна другая проверка этого не заметит: представление продолжит читать те же
// таблицы, отчёты продолжат считаться свежими.
//
// СКОЛЬКО имён держится одним файлом — гейт ПЕЧАТАЕТ каждым прогоном, а не
// объявляет числом в этом комментарии. Число здесь устарело бы на первой же
// правке любого файла каталога — и устарело бы молча, ровно тем классом, который
// эта под-фаза чинит в двух текстах о цепи.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЙ БЛИЗНЕЦ — ОБЯЗАТЕЛЕН, ИНАЧЕ ГЕЙТ ТРЕБОВАЛ БЫ ПИСАТЬ ИМЯ ДВАЖДЫ
//
// Сверяется ОБЪЕДИНЕНИЕ имён по всем файлам каталога, а не соответствие «файл,
// который таблицу читает, её же и называет». Второе было бы требованием назвать
// имя дважды: запрос вердикта поднимается по ПРЕДСТАВЛЕНИЮ и таблиц под ним не
// называет исполняемым текстом вовсе — они названы его комментарием и реестром
// осей меток. Близнец предъявляется ДВАЖДЫ: синтетикой — всегда, и настоящим
// деревом — когда у него там есть предмет. Есть ли он сегодня, гейт ПЕЧАТАЕТ, а
// не обещает: предмет исчезает, как только каждое имя цепи начинает называть
// какой-нибудь из файлов, несущих сам обход.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОТКУДА БЕРУТСЯ ОБЕ СТОРОНЫ — НИ ОДНА НЕ ВЫПИСАНА
//
//	каталог чтения — `scalegrid.ComputeFingerprint`, ЕГО собственный ответ; второй
//	                 реализации здесь не заводится, иначе разошлись бы молча и
//	                 именно там, где расхождение не видно;
//	цепь           — исполняемый текст представления из ПОСЛЕДНЕЙ по версии
//	                 миграции, которая его объявляет; комментарии и строковые
//	                 литералы вырезаются ПЕРЕД разбором, иначе гейт читал бы
//	                 объяснение защиты наравне с защитой.
//
// Предпосылка проверяется отдельно: извлекатель имён этого файла обязан давать на
// файлах каталога РОВНО тот перечень, что даёт прибор. Разойдясь, он произвёл бы
// ложные находки на исправном дереве — и первый же ложный срабат гейт выключил бы.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
)

// chainViewName — имя представления цепи. Названо здесь ЯВНО, потому что гейт
// обязан говорить, что он сторожит; переименование представления не проходит
// мимо — миграции, объявляющей представление с этим именем, гейт не найдёт и
// ОТКАЖЕТ, а не промолчит.
const chainViewName = "kacho_iam.resource_scope_edge"

// chainTableMark — приставка, по которой имена таблиц выводятся из текста. Та же,
// что у прибора; совпадение не берётся на веру, а проверяется предпосылкой
// (chainCatalogueCouplingFindings).
const chainTableMark = "kacho_iam."

// chainViewDecl — объявление представления в любой из двух форм: `740001` завела
// его через CREATE VIEW, последующие переопределяют через CREATE OR REPLACE VIEW.
var chainViewDecl = regexp.MustCompile(`CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+` +
	regexp.QuoteMeta(chainViewName) + `\b`)

// chainMigrationVersion — числовой префикс имени миграции. Именно числом:
// лексикографический порядок сравнивает `0098` и `740001` как строки, и порядок
// применения от такого сравнения не зависит.
var chainMigrationVersion = regexp.MustCompile(`^(\d+)_`)

// ── ИЗВЛЕЧЕНИЕ ──────────────────────────────────────────────────────────────

// chainExecutableSQL — текст без комментариев и без строковых литералов.
//
// Литералы вырезаются наравне с комментариями: комментарий представления —
// строковый литерал `COMMENT ON VIEW … IS '…'`, и он перечисляет источники
// звеньев прозой. Гейт, читающий его как исполняемый текст, зеленел бы на
// РАССКАЗЕ о таблице там, где сама таблица из запроса ушла.
func chainExecutableSQL(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); {
		switch {
		case src[i] == '\'':
			i++
			for i < len(src) {
				if src[i] == '\'' {
					i++
					if i < len(src) && src[i] == '\'' { // экранированная кавычка
						i++
						continue
					}
					break
				}
				i++
			}
			b.WriteString("''")
		case strings.HasPrefix(src[i:], "--"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

// chainTableNamesIn — имена вида `kacho_iam.<таблица>`, встреченные в тексте.
func chainTableNamesIn(src string) []string {
	seen := map[string]bool{}
	var out []string
	for i := 0; ; {
		j := strings.Index(src[i:], chainTableMark)
		if j < 0 {
			break
		}
		start := i + j
		k := start + len(chainTableMark)
		for k < len(src) {
			c := src[k]
			if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				k++
				continue
			}
			break
		}
		if name := src[start:k]; name != chainTableMark && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		i = k
	}
	sort.Strings(out)
	return out
}

// chainTablesOfTheView — таблицы, которые читает представление цепи, плюс путь
// миграции, из которой они взяты.
func chainTablesOfTheView(root string, migrations []string) ([]string, string, error) {
	bestVersion, bestPath, bestStmt := -1, "", ""
	for _, rel := range migrations {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, "", fmt.Errorf("чтение миграции %s: %w", rel, err)
		}
		// Только блок Up: блок Down переопределяет представление ОБРАТНО, и его
		// текст — описание снятого состояния, а не действующего.
		src := string(body)
		if i := strings.Index(src, "-- +goose Up"); i >= 0 {
			src = src[i:]
		}
		if i := strings.Index(src, "-- +goose Down"); i >= 0 {
			src = src[:i]
		}
		exec := chainExecutableSQL(src)
		loc := chainViewDecl.FindStringIndex(exec)
		if loc == nil {
			continue
		}
		m := chainMigrationVersion.FindStringSubmatch(filepath.Base(rel))
		if m == nil {
			return nil, "", fmt.Errorf("у миграции %s нет числовой версии в имени: порядок "+
				"применения по такому имени не установить", rel)
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, "", fmt.Errorf("версия миграции %s не число: %w", rel, err)
		}
		if v <= bestVersion {
			continue
		}
		stmt := exec[loc[0]:]
		if i := strings.Index(stmt, ";"); i >= 0 {
			stmt = stmt[:i]
		}
		bestVersion, bestPath, bestStmt = v, rel, stmt
	}
	if bestPath == "" {
		return nil, "", fmt.Errorf("ни одна миграция под отпечатком не объявляет %s: сверять "+
			"нечего, и молчание гейта означало бы, что цепь не читает ничего", chainViewName)
	}
	var tables []string
	for _, name := range chainTableNamesIn(bestStmt) {
		if name == chainViewName { // само представление читателем себя не является
			continue
		}
		tables = append(tables, name)
	}
	return tables, bestPath, nil
}

// ── ВЕРДИКТ ЧИСТОЙ ФУНКЦИЕЙ ─────────────────────────────────────────────────

// chainTablesNotNamedByCatalogue — находки. Пустой срез означает «каталог чтения
// называет всё, что читает цепь».
//
// Чистая: обе стороны — параметры, поэтому функцию можно накормить настоящим
// деревом и синтетикой, и способность гейта упасть не остаётся заявленной.
func chainTablesNotNamedByCatalogue(chain, catalogue []string) []string {
	if len(chain) == 0 {
		return []string{"ПРЕДПОСЫЛКА: под представлением " + chainViewName + " не найдено ни " +
			"одной таблицы. «Ноль находок» здесь означало бы «ноль прочитанного»"}
	}
	if len(catalogue) == 0 {
		return []string{"ПРЕДПОСЫЛКА: каталог чтения не назвал НИ ОДНОГО имени таблицы. " +
			"Сверять не с чем, а не «всё названо»"}
	}
	named := map[string]bool{}
	for _, n := range catalogue {
		named[n] = true
	}
	var findings []string
	for _, t := range chain {
		if named[t] {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s: цепь областей эту таблицу ЧИТАЕТ, а каталог чтения не называет её ни одним "+
				"своим не-тестовым файлом. Значит она выпала из-под отпечатка предмета замера: "+
				"правку её миграции прибор свежести перестанет замечать молча, а отчёты об "+
				"объёме и прочности останутся «свежими» на дереве, которого они не мерили.\n"+
				"  Закрывается одним из двух: имя названо любым файлом каталога (хоть тем, что "+
				"её читает, хоть соседним) ЛИБО ветвь, читающая её, снята из представления",
			t))
	}
	return findings
}

// chainCatalogueCouplingFindings — предпосылка: извлекатель этого файла и прибор
// дают на одном корпусе ОДИН перечень.
//
// Без этой сверки в дереве завелись бы два правила об одном предмете, и
// разошлись бы они молча — обе стороны продолжали бы отвечать «имя найдено» на
// именах, которые обе понимают одинаково, и разъехались бы ровно на новом.
func chainCatalogueCouplingFindings(mine, appliance []string) []string {
	if len(mine) != len(appliance) {
		return []string{fmt.Sprintf("извлекатель гейта дал %d имён, прибор — %d: правила "+
			"разошлись, и находки гейта больше не о том же предмете.\n  гейт:   %s\n  прибор: %s",
			len(mine), len(appliance), strings.Join(mine, ", "), strings.Join(appliance, ", "))}
	}
	for i := range mine {
		if mine[i] != appliance[i] {
			return []string{fmt.Sprintf("извлекатель гейта и прибор разошлись на имени %q "+
				"против %q", mine[i], appliance[i])}
		}
	}
	return nil
}

// ── ГЕЙТ НАД НАСТОЯЩИМ ДЕРЕВОМ ──────────────────────────────────────────────

// chainCatalogueDir — каталог чтения ВЫВОДИТСЯ, а не выписывается: `go test`
// запускает бинарь из каталога пакета, а пакет и есть каталог чтения. Выписанный
// путь пережил бы переезд пакета и сторожил бы пустоту.
func chainCatalogueDir(t *testing.T, root string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не установлен: %v", err)
	}
	resolve := func(p string) string {
		if r, rerr := filepath.EvalSymlinks(p); rerr == nil {
			return r
		}
		return p
	}
	rel, err := filepath.Rel(resolve(root), resolve(wd))
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("каталог пакета %s не лежит под корнем дерева %s (rel=%q, err=%v): гейт "+
			"сверял бы файлы чужого дерева", wd, root, rel, err)
	}
	return filepath.ToSlash(rel)
}

// TestR7_4_16_ChainTableUnnamedByTheReadCatalogueIsAFinding — гейт.
func TestR7_4_16_ChainTableUnnamedByTheReadCatalogueIsAFinding(t *testing.T) {
	root := matrixRepoRoot(t)
	dir := chainCatalogueDir(t, root)

	fp, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("перечень прибора не вычислен: %v", err)
	}

	var catalogueFiles, migrationFiles []string
	for _, rel := range fp.Files {
		switch {
		case strings.HasPrefix(rel, dir+"/") && strings.HasSuffix(rel, ".go"):
			catalogueFiles = append(catalogueFiles, rel)
		case strings.HasSuffix(rel, ".sql"):
			migrationFiles = append(migrationFiles, rel)
		}
	}
	if len(catalogueFiles) == 0 {
		t.Fatalf("ПРЕДПОСЫЛКА: под отпечатком нет ни одного не-тестового файла каталога %s — "+
			"осматривать нечего, и «ноль находок» было бы «ноль прочитанного»", dir)
	}

	// Предпосылка: правило извлечения имён у гейта и у прибора — одно.
	var mine []string
	{
		var joined strings.Builder
		for _, rel := range catalogueFiles {
			body, rerr := os.ReadFile(filepath.Join(root, rel))
			if rerr != nil {
				t.Fatalf("чтение файла каталога %s: %v", rel, rerr)
			}
			joined.Write(body)
			joined.WriteString("\n")
		}
		mine = chainTableNamesIn(joined.String())
	}
	for _, f := range chainCatalogueCouplingFindings(mine, fp.Tables) {
		t.Errorf("ПРЕДПОСЫЛКА НЕ ДЕРЖИТСЯ: %s", f)
	}

	chain, migration, err := chainTablesOfTheView(root, migrationFiles)
	if err != nil {
		t.Fatalf("таблицы цепи не выведены: %v", err)
	}

	// Объём осмотренного — печатается ВСЕГДА: «ноль находок» обязано быть отличимо
	// от «ноль прочитанного».
	t.Logf("осмотрено: файлов каталога %d (%s), имён прочитано %d; представление %s взято из "+
		"%s, таблиц под ним %d\n  каталог: %s\n  цепь:    %s",
		len(catalogueFiles), dir, len(fp.Tables), chainViewName, migration, len(chain),
		strings.Join(fp.Tables, ", "), strings.Join(chain, ", "))

	findings := chainTablesNotNamedByCatalogue(chain, fp.Tables)
	for _, f := range findings {
		t.Errorf("%s", f)
	}
	if len(findings) != 0 {
		return
	}

	// КТО ДЕРЖИТ КАЖДОЕ ИМЯ — перепись, а не число в комментарии. Отсюда и предмет
	// гейта (имя на одном файле), и законный близнец (имя, принесённое файлом,
	// который эту таблицу не читает).
	walkFiles, holders := map[string]bool{}, map[string][]string{}
	for _, rel := range catalogueFiles {
		body, rerr := os.ReadFile(filepath.Join(root, rel))
		if rerr != nil {
			t.Fatalf("чтение файла каталога %s: %v", rel, rerr)
		}
		src := string(body)
		if strings.Contains(src, chainViewName) {
			walkFiles[rel] = true
		}
		for _, name := range chainTableNamesIn(src) {
			holders[name] = append(holders[name], rel)
		}
	}

	var single, carriedByOutsiders []string
	for _, tbl := range chain {
		if len(holders[tbl]) == 1 {
			single = append(single, fmt.Sprintf("%s ← %s", tbl, holders[tbl][0]))
		}
		onlyOutside := len(holders[tbl]) > 0
		for _, rel := range holders[tbl] {
			if walkFiles[rel] {
				onlyOutside = false
				break
			}
		}
		if onlyOutside {
			carriedByOutsiders = append(carriedByOutsiders,
				fmt.Sprintf("%s ← %s", tbl, strings.Join(holders[tbl], ", ")))
		}
	}

	if len(single) == 0 {
		t.Logf("предмет гейта на сегодняшнем дереве в вырожденном состоянии: каждое имя цепи " +
			"держат минимум два файла каталога. Гейт от этого не лишний — он сторожит момент, " +
			"когда держателей станет ноль, а не когда их станет один")
	} else {
		t.Logf("ПРЕДМЕТ ГЕЙТА, измеренный ЭТИМ прогоном: %d имён цепи из %d держатся "+
			"ЕДИНСТВЕННЫМ файлом каталога — %s. Уйдёт файл, и основание прибора выпадет молча",
			len(single), len(chain), strings.Join(single, " · "))
	}
	if len(carriedByOutsiders) == 0 {
		t.Logf("законному близнецу на дереве предмета сейчас НЕТ: каждую таблицу цепи называет " +
			"хотя бы один файл, несущий сам обход. Близнеца держит синтетика инъекции")
	} else {
		t.Logf("законный близнец на дереве (гейт молчит, и это правильно): %d имён цепи "+
			"названы ТОЛЬКО файлами, которые их не читают — %s",
			len(carriedByOutsiders), strings.Join(carriedByOutsiders, " · "))
	}

	t.Logf("СЕГОДНЯШНЕЕ ДЕРЕВО ГЕЙТ ПРОХОДИТ, и это его штатное состояние: он заведён ВПЕРЁД — " +
		"не сообщить о находке, а не дать ей завестись")
}

// TestR7_4_16_TheGateFallsWhenANameLeavesTheCatalogueAndStaysSilentOnItsTwin —
// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ, настоящими именами дерева, а не выдуманными.
func TestR7_4_16_TheGateFallsWhenANameLeavesTheCatalogueAndStaysSilentOnItsTwin(t *testing.T) {
	root := matrixRepoRoot(t)
	fp, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("перечень прибора не вычислен: %v", err)
	}
	var migrations []string
	for _, rel := range fp.Files {
		if strings.HasSuffix(rel, ".sql") {
			migrations = append(migrations, rel)
		}
	}
	chain, _, err := chainTablesOfTheView(root, migrations)
	if err != nil {
		t.Fatalf("таблицы цепи не выведены: %v", err)
	}
	if len(chain) < 2 {
		t.Fatalf("таблиц цепи %d: на таком входе инъекция вырождена", len(chain))
	}

	// (б) ЗАКОННЫЙ БЛИЗНЕЦ, он же положительный контроль: настоящее дерево — молчание.
	// Без него красное «на всём» было бы неотличимо от красного «на дефекте».
	if got := chainTablesNotNamedByCatalogue(chain, fp.Tables); got != nil {
		t.Fatalf("законный близнец покраснел: гейт находит дефект на исправном дереве — %v", got)
	}

	// (б) ЗАКОННЫЙ БЛИЗНЕЦ, синтетика: имя принесено файлом, который таблицу НЕ
	// читает. Гейт обязан молчать — иначе он требовал бы называть имя дважды.
	if got := chainTablesNotNamedByCatalogue([]string{chain[0]}, []string{chain[0]}); got != nil {
		t.Errorf("гейт нашёл находку на имени, названном каталогом: %v.\n"+
			"  Сверяется ОБЪЕДИНЕНИЕ имён каталога, а не совпадение «читает и называет один "+
			"и тот же файл»", got)
	}

	// (а) КРАСНОЕ С КООРДИНАТОЙ: имя ушло из каталога — по каждой таблице цепи
	// отдельно, потому что уйти может любая.
	for _, gone := range chain {
		var narrowed []string
		for _, n := range fp.Tables {
			if n != gone {
				narrowed = append(narrowed, n)
			}
		}
		findings := chainTablesNotNamedByCatalogue(chain, narrowed)
		if len(findings) != 1 {
			t.Errorf("имя %s снято из каталога → находок %d, ожидалась одна: %v",
				gone, len(findings), findings)
			continue
		}
		if !strings.Contains(findings[0], gone) {
			t.Errorf("имя %s снято из каталога → находка есть, но координаты не называет: %q",
				gone, findings[0])
		}
	}

	// ПРЕДПОСЫЛКИ: пустая сторона — ОТКАЗ, а не «расхождений нет».
	if got := chainTablesNotNamedByCatalogue(nil, fp.Tables); len(got) != 1 ||
		!strings.Contains(got[0], "ПРЕДПОСЫЛКА") {
		t.Errorf("пустая цепь: ожидался отказ по предпосылке, получено %v", got)
	}
	if got := chainTablesNotNamedByCatalogue(chain, nil); len(got) != 1 ||
		!strings.Contains(got[0], "ПРЕДПОСЫЛКА") {
		t.Errorf("пустой каталог: ожидался отказ по предпосылке, получено %v", got)
	}

	// ПРЕДПОСЫЛКА СВЯЗКИ: расхождение правил извлечения — находка, а не тишина.
	if got := chainCatalogueCouplingFindings(chain, fp.Tables); len(got) != 1 {
		t.Errorf("извлекатель и прибор объявлены сошедшимися на РАЗНЫХ корпусах: %v", got)
	}
	if got := chainCatalogueCouplingFindings(fp.Tables, fp.Tables); got != nil {
		t.Errorf("сверка правил извлечения покраснела на одинаковых перечнях: %v", got)
	}
}

// ── ИНЪЕКЦИЯ ЧЕРЕЗ ВСЮ ЦЕПОЧКУ ВЫВОДА, А НЕ ТОЛЬКО ЧЕРЕЗ СРАВНЕНИЕ ──────────
//
// Сравнение выше — чистая функция, и накормить её списками можно любыми. Но
// дрейфует не сравнение, а ВЫВОД: перечень прибора и таблицы представления
// добываются двумя разными обходами дерева. Инъекция ниже снимает имя из
// НАСТОЯЩИХ файлов каталога, скопированных в синтетический корень, и прогоняет
// обе стороны целиком — прибор по копии, представление по копии миграций.
//
// Рабочая копия при этом не трогается ни на секунду: в неё пишут соседние
// сессии, и правка-с-откатом здесь означала бы гонку за чужой файл.

// chainSyntheticRoot — копия трёх каталогов, которых касается прибор, в
// собственном временном корне. Непустое `drop` снимает имя таблицы из файлов
// КАТАЛОГА (миграции остаются нетронутыми — цепь обязана продолжать её читать).
func chainSyntheticRoot(t *testing.T, root, drop string) string {
	t.Helper()
	tmp := t.TempDir()
	dirs := []struct {
		rel    string
		suffix string
		strip  bool
	}{
		{"services/iam/internal/repo/kacho/pg/relverdict", ".go", true},
		{"services/iam/internal/repo/kacho/pg/scalegrid", ".go", false},
		{"services/iam/internal/migrations", ".sql", false},
	}
	for _, d := range dirs {
		src := filepath.Join(root, d.rel)
		dst := filepath.Join(tmp, filepath.FromSlash(d.rel))
		if err := os.MkdirAll(dst, 0o750); err != nil {
			t.Fatalf("синтетический корень: %v", err)
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			t.Fatalf("синтетический корень, чтение %s: %v", d.rel, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), d.suffix) {
				continue
			}
			body, rerr := os.ReadFile(filepath.Join(src, e.Name()))
			if rerr != nil {
				t.Fatalf("синтетический корень, чтение %s/%s: %v", d.rel, e.Name(), rerr)
			}
			text := string(body)
			if d.strip && drop != "" {
				// Приставка ломается точкой: имя перестаёт распознаваться и
				// прибором, и гейтом — ровно как при уходе файла из каталога.
				text = strings.ReplaceAll(text, drop,
					strings.ReplaceAll(drop, chainTableMark, "kacho_iam_INJECTED_"))
			}
			if werr := os.WriteFile(filepath.Join(dst, e.Name()), []byte(text), 0o600); werr != nil {
				t.Fatalf("синтетический корень, запись %s: %v", e.Name(), werr)
			}
		}
	}
	return tmp
}

// chainJudgeRoot — вердикт по корню целиком: обе стороны выводятся заново.
func chainJudgeRoot(t *testing.T, root string) []string {
	t.Helper()
	fp, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("перечень прибора по корню %s: %v", root, err)
	}
	var migrations []string
	for _, rel := range fp.Files {
		if strings.HasSuffix(rel, ".sql") {
			migrations = append(migrations, rel)
		}
	}
	chain, _, err := chainTablesOfTheView(root, migrations)
	if err != nil {
		t.Fatalf("таблицы цепи по корню %s: %v", root, err)
	}
	return chainTablesNotNamedByCatalogue(chain, fp.Tables)
}

// TestR7_4_16_TheWholeDerivationFallsWhenANameLeavesTheCatalogue — та же инъекция,
// но через ВЕСЬ вывод: настоящие файлы, настоящий прибор, настоящее представление.
func TestR7_4_16_TheWholeDerivationFallsWhenANameLeavesTheCatalogue(t *testing.T) {
	root := matrixRepoRoot(t)

	// (б) ЗАКОННЫЙ БЛИЗНЕЦ: копия БЕЗ правки — молчание. Без него красное ниже
	// было бы неотличимо от «гейт красен на копии как таковой».
	control := chainSyntheticRoot(t, root, "")
	if got := chainJudgeRoot(t, control); got != nil {
		t.Fatalf("нетронутая копия дерева покраснела: %v", got)
	}

	// (а) КРАСНОЕ С КООРДИНАТОЙ: имя ушло из каталога, цепь продолжает читать.
	//
	// ЦЕЛЬ ИНЪЕКЦИИ — ТАБЛИЦА ЧЛЕНСТВ, а не строка пользователя. Здесь стояло
	// `users`, и мишень пережила свой предмет: с #944 звено личности берёт аккаунт
	// из членства, цепь таблицу пользователей больше НЕ ЧИТАЕТ — снятие её имени
	// из каталога перестало быть дефектом, и инъекция доказывала бы способность
	// гейта упасть там, где падать не на чем. Мишенью обязана быть таблица,
	// которую цепь читает СЕГОДНЯ.
	const gone = chainTableMark + "memberships"
	injected := chainSyntheticRoot(t, root, gone)
	findings := chainJudgeRoot(t, injected)
	if len(findings) != 1 {
		t.Fatalf("имя %s снято из каталога копии → находок %d, ожидалась одна: %v",
			gone, len(findings), findings)
	}
	if !strings.Contains(findings[0], gone) {
		t.Errorf("находка есть, но координаты не называет: %q", findings[0])
	}
	t.Logf("инъекция через весь вывод: имя %s снято из файлов каталога копии — гейт краснеет "+
		"и называет таблицу; та же копия без правки молчит", gone)
}
