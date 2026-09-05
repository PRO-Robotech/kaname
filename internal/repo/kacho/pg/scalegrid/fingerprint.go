// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ОТПЕЧАТОК ПРЕДМЕТА ЗАМЕРА — «ИЗМЕНИЛОСЬ ЛИ ТО, ЧТО ОТЧЁТ МЕРИЛ»
//
// # Почему отпечаток, а не «ревизия отчёта — предок вершины»
//
// В этом продукте вливают СХЛОПЫВАНИЕМ: squash рождает новый хеш, и записанная
// в шапке ревизия предком вершины не становится НИКОГДА. Гейт с таким плечом
// краснел бы на каждом вливании, включая то, которым отчёт и приезжает, — то
// есть был бы снят первым же срабатыванием.
//
// Отпечаток от истории не зависит вовсе: он переживает схлопывание, перенос,
// черри-пик и переписанную историю, и отвечает на настоящий вопрос — не «отчёт
// старше вершины?», а «изменилось ли то, что он измерял?».
//
// # ПОЧЕМУ МНОЖЕСТВО ВЫВОДИТСЯ, А ЕГО СОСТАВ ВХОДИТ В ХЭШ
//
// Выписанный перечень не двигается от НОВОГО файла: положи в `relverdict/`
// пятый не-тестовый файл, меняющий запрос, — содержимое прежних четырёх не
// изменится, отпечаток совпадёт, и гейт промолчит ровно там, где обязан
// заговорить. Поэтому хэшей ДВА: по составу (ловит появление и исчезновение
// файла) и по содержимому (ловит правку существующего). Разделены они затем,
// чтобы гейт мог НАЗВАТЬ, что именно сдвинулось.
//
// # ОДНА РЕАЛИЗАЦИЯ НА ДВУХ ЧИТАТЕЛЕЙ
//
// Отпечаток считают писатель отчёта и гейт свежести. Вторая реализация
// разошлась бы с первой молча — и разошлась бы именно там, где расхождение не
// видно: обе давали бы «совпало» на неподвижном дереве.

// fingerprintTableMark — приставка, по которой из кода вердикта ВЫВОДЯТСЯ имена
// читаемых таблиц. Схема названа целиком, потому что в запросах она пишется
// целиком.
const fingerprintTableMark = "kacho_iam."

// verdictDir / gridDir — каталоги, чьё не-тестовое содержимое и есть предмет.
const (
	verdictDir = "services/iam/internal/repo/kacho/pg/relverdict"
	gridDir    = "services/iam/internal/repo/kacho/pg/scalegrid"
	migrateDir = "services/iam/internal/migrations"
)

// FingerprintPredicate — предикат печатается В ШАПКУ рядом с отпечатком.
//
// Печатается затем, чтобы читатель мог его ПОВТОРИТЬ и оспорить, а не поверить
// шестнадцати знакам хэша.
const FingerprintPredicate = `все не-тестовые .go каталогов ` + verdictDir + ` и ` + gridDir +
	`; те .sql каталога ` + migrateDir + `, что МЕНЯЮТ СТРУКТУРУ (CREATE/ALTER/DROP ` +
	`вне комментариев) хотя бы одной таблицы, ` +
	`которую читает запрос вердикта (имена таблиц ВЫВЕДЕНЫ из кода вердикта по приставке "` +
	fingerprintTableMark + `", а не выписаны); БЕЗ файлов, объявленных оснасткой ` +
	`отпечатка (они не касаются базы — проверяется разбором, а не перечнем)` +
	`; у .go под отпечаток идёт ЗНАЧАЩЕЕ содержимое — поток лексем БЕЗ комментариев ` +
	`(директивы //go: сохранены), поэтому смена заголовка лицензии или прозы замер НЕ ` +
	`обесценивает; .sql берётся ПОБАЙТОВО — в его комментариях живут директивы мигратора ` +
	`(-- +goose), а отделить их текстом нельзя: две дефиса встречаются и внутри литерала`

// Fingerprint — отпечаток предмета замера.
type Fingerprint struct {
	// Composition — хэш отсортированного СПИСКА путей.
	Composition string
	// Content — хэш содержимого файлов в том же порядке.
	Content string
	// Files — сами пути, для сообщения гейта.
	Files []string
	// Tables — выведенные имена таблиц; печатаются, чтобы «ноль находок» было
	// отличимо от «ноль прочитанного».
	Tables []string
	// Predicate — ЧТО именно взято под отпечаток, словами.
	//
	// Поле, а не константа пакета: приборов стало два, и предметы у них РАЗНЫЕ —
	// у читающего это код вердикта, у пишущего материализатор. Печатать обоим
	// один предикат значило бы написать в шапке второго отчёта неправду о том,
	// что он сторожит. Пусто — предикат прибора чтения.
	Predicate string
}

// ComputeFingerprint — отпечаток по ТЕКУЩЕМУ дереву.
func ComputeFingerprint(root string) (Fingerprint, error) {
	var fp Fingerprint
	fp.Predicate = FingerprintPredicate

	code, err := nonTestGoFiles(root, verdictDir)
	if err != nil {
		return fp, err
	}
	gridFiles, err := nonTestGoFiles(root, gridDir)
	if err != nil {
		return fp, err
	}
	gridFiles, err = withoutScaffolding(root, gridFiles)
	if err != nil {
		return fp, err
	}

	// Имена таблиц ВЫВОДЯТСЯ из кода вердикта. Выписанный перечень не двигался
	// бы от новой таблицы в запросе и продолжал бы сторожить прежние.
	tables := map[string]bool{}
	for _, rel := range code {
		body, rerr := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- rel получен обходом СОБСТВЕННОГО дерева репозитория (git ls-files под корнем root), не из запроса и не от пользователя; прибор читает свои же файлы, чтобы взять их отпечаток
		if rerr != nil {
			return fp, fmt.Errorf("scalegrid: чтение %s: %w", rel, rerr)
		}
		for _, name := range tableNamesIn(string(body)) {
			tables[name] = true
		}
	}
	for name := range tables {
		fp.Tables = append(fp.Tables, name)
	}
	sort.Strings(fp.Tables)

	migrations, err := migrationsNaming(root, fp.Tables)
	if err != nil {
		return fp, err
	}

	files := append(append(append([]string{}, code...), gridFiles...), migrations...)
	sort.Strings(files)
	fp.Files = files

	// `hash.Hash.Write` не возвращает ошибки by construction (это записано в его
	// контракте), но линтер дерева читает возвращаемое значение, а не контракт.
	ch := sha256.New()
	for _, rel := range files {
		ch.Write([]byte(rel + "\n"))
	}
	fp.Composition = hex.EncodeToString(ch.Sum(nil))[:16]

	fp.Content, err = contentHash(root, files)
	if err != nil {
		return fp, err
	}
	return fp, nil
}

// ЗНАЧАЩЕЕ СОДЕРЖИМОЕ — ОТПЕЧАТОК ЛОВИТ ПОВЕДЕНИЕ, А НЕ БАЙТЫ (#2039)
//
// # Что было неверно
//
// Отпечаток брался от ВСЕХ байтов файла, поэтому правка, не касавшаяся ни
// одного оператора, объявляла замер устаревшим. Смена заголовка лицензии в 90
// файлах обесценила четыре отчёта разом; пересъёмка одного — до двух часов
// прогона на поднятой базе. То есть прибор ловил «файл тронут», а обязан ловить
// «предмет замера сдвинулся», и цена ошибки была не разовой: следующий, кто
// сменит комментарий, встал бы перед тем же выбором — платить восемь часов либо
// править гейт под результат.
//
// # Почему РАЗБОРОМ, а не текстовой заменой
//
// Текстовая замена «убрать всё после //» попадает ВНУТРЬ строкового литерала, а
// эти файлы — сплошь запросы в обратных кавычках. Срезав хвост литерала, она
// объявила бы правку запроса незначащей: дыра открылась бы ровно там, где она
// дороже всего. Здесь границы комментариев даёт РАЗБОРЩИК, поэтому литерал не
// может быть принят за комментарий by construction. Обе стороны закреплены
// пробой (`fingerprint_significant_test.go`), включая строку с `//` внутри
// запроса.
//
// # Что НЕ снимается — и это названо, а не подразумевается
//
//	директива `//go:...`  РЕШАЕТ, компилируется ли файл; снять её вместе с
//	                      прозой значило бы перестать замечать смену состава
//	                      собираемого кода
//	.sql целиком          комментарии SQL здесь НЕ проза: `-- +goose Up` и
//	                      `-- +goose Down` читает мигратор, `-- +kacho
//	                      point-of-no-return` — гейт отката. Сняв их, мы
//	                      перестали бы отличать миграцию, поменявшую Up и Down
//	                      местами
//
// # Граница, названная честно
//
// Отпечаток берётся с потока ЛЕКСЕМ, поэтому неразличимыми становятся и правки
// форматирования — отступ, перенос строки, пустая строка. Это осознанно: gofmt
// в этом дереве обязателен, значит форматирование канонично, а замер от него не
// зависит. Содержимое строковых литералов при этом сохраняется ДОСЛОВНО: лексема
// несёт литерал целиком, и пробел внутри запроса лексером не трогается.

// significantContent — содержимое файла БЕЗ незначащего.
//
// Для `.go` — поток лексем без комментариев (директивы сохранены). Для всего
// остального — байты как есть.
//
// Неразбираемый `.go` — ОТКАЗ, а не молчаливый возврат байтов: возврат
// восстановил бы байтовую чувствительность там, где её никто не ждёт, и отличить
// это от исправной работы было бы нечем.
func significantContent(rel string, src []byte) ([]byte, error) {
	if !strings.HasSuffix(rel, ".go") {
		return src, nil
	}

	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution); err != nil {
		return nil, fmt.Errorf(
			"scalegrid: %s не разбирается как Go, значащее содержимое неопределимо: %w", rel, err)
	}

	lexFset := token.NewFileSet()
	file := lexFset.AddFile(rel, lexFset.Base(), len(src))
	var errs scanner.ErrorList
	var sc scanner.Scanner
	sc.Init(file, src, func(pos token.Position, msg string) { errs.Add(pos, msg) }, scanner.ScanComments)

	var b strings.Builder
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT && !isKeptDirective(lit) {
			continue
		}
		if lit != "" {
			b.WriteString(lit)
		} else {
			b.WriteString(tok.String())
		}
		b.WriteByte('\n')
	}
	if errs.Len() > 0 {
		return nil, fmt.Errorf("scalegrid: %s не разбирается на лексемы: %w", rel, errs.Err())
	}
	return []byte(b.String()), nil
}

// isKeptDirective — комментарий, который остаётся под отпечатком.
//
// Директива — не проза: `//go:build` решает, попадёт ли файл в сборку вовсе.
// Признак берётся у стандартной библиотеки (`ast.ParseDirective`), а не
// выписывается перечнем: выписанный не двигался бы от директивы, которой мы
// сегодня не знаем, и та уехала бы из-под отпечатка молча.
func isKeptDirective(lit string) bool {
	_, ok := ast.ParseDirective(token.NoPos, lit)
	return ok
}

// contentHash — хэш ЗНАЧАЩЕГО содержимого перечня файлов.
//
// Одна реализация на обоих читателей отпечатка (вердикт и материализатор):
// вторая разошлась бы с первой молча — и разошлась бы именно там, где
// расхождение не видно, потому что обе давали бы «совпало» на неподвижном
// дереве.
func contentHash(root string, files []string) (string, error) {
	h := sha256.New()
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- rel получен обходом СОБСТВЕННОГО дерева репозитория под корнем root, не из запроса и не от пользователя; прибор читает свои же файлы, чтобы взять их отпечаток
		if err != nil {
			return "", fmt.Errorf("scalegrid: чтение %s: %w", rel, err)
		}
		significant, err := significantContent(rel, body)
		if err != nil {
			return "", err
		}
		h.Write(significant)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// fingerprintScaffolding — файлы каталога сетки, которые ОСНАСТКА, а не предмет
// замера: они вычисляют отпечаток и печатают отчёт, но не задают ни одного
// запроса, ни одной величины сетки и не касаются базы.
//
// # Зачем исключение
//
// Без него отпечаток сторожил САМ СЕБЯ: всякая правка предиката свежести
// обесценивала все отчёты и требовала двухчасовой пересъёмки — при том что
// поведение, о стоимости которого отчёт говорит, не менялось ни на строку.
// То есть механизм, заведённый против ложной свежести, производил ложную
// несвежесть, и цена была не разовой, а на каждую правку впредь.
//
// # Почему это НЕ послабление
//
// Исключение самоистекает: `withoutScaffolding` проверяет, что исключаемый файл
// и в самом деле оснастка — не обращается к базе и не строит запроса. Начнёт —
// вернётся под отпечаток сам, без чьей-либо памяти. Запись, которой больше
// нечего исключать, тоже находка: отсутствующий файл — отказ, а не тишина.
var fingerprintScaffolding = map[string]bool{
	gridDir + "/fingerprint.go": true, // вычисляет отпечаток
	gridDir + "/report.go":      true, // печатает отчёт
}

// scaffoldingStillHolds — остаётся ли файл ОСНАСТКОЙ, то есть неспособным
// повлиять на измеряемую стоимость.
//
// Признак берётся с РАЗОБРАННОГО дерева, а не с текста, и это не педантизм:
// первая же редакция читала текст и объявила находкой САМА СЕБЯ — регулярка со
// словами `SELECT|INSERT|…` живёт в этом файле строковым литералом. Гейт,
// сработавший на собственном объяснении, — тот самый класс, который мы ловим.
//
// Исполнить запрос без пакета базы нельзя, поэтому признак — ИМПОРТ пакета
// базы либо вызов `Query`/`Exec`/`QueryRow`. Строка с SQL сама по себе
// признаком не является: оснастка вправе цитировать запрос в объяснении.
func scaffoldingStillHolds(rel string, src []byte) (bool, string) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.ImportsOnly|parser.SkipObjectResolution)
	if err == nil {
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "jackc/pgx") || path == "database/sql" {
				return false, "импортирует пакет базы " + path
			}
		}
	}

	full, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		// Неразобранный файл — ОТКАЗ, а не молчание: пропустить его значило бы
		// вынести из-под отпечатка то, что мы не прочитали.
		return false, "не разбирается как Go: " + err.Error()
	}
	var reason string
	ast.Inspect(full, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || reason != "" {
			return reason == ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Query", "QueryRow", "Exec", "SendBatch":
			reason = "зовёт " + sel.Sel.Name + " — обращается к базе"
			return false
		}
		return true
	})
	if reason != "" {
		return false, reason
	}
	return true, ""
}

// withoutScaffolding — множество без оснастки, с проверкой каждого исключения.
//
// Проверяется КАЖДОЕ исключение и в обе стороны: файл, переставший быть
// оснасткой, возвращается под отпечаток сам; запись, которой в дереве больше
// не соответствует файл, — отказ, а не тишина. Иначе перечень имён пережил бы
// свой предмет и молча покрывал пустоту.
func withoutScaffolding(root string, files []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(files))
	for _, rel := range files {
		if !fingerprintScaffolding[rel] {
			out = append(out, rel)
			continue
		}
		seen[rel] = true
		body, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- rel получен обходом СОБСТВЕННОГО каталога
		if err != nil {
			return nil, fmt.Errorf("scalegrid: чтение оснастки %s: %w", rel, err)
		}
		if ok, why := scaffoldingStillHolds(rel, body); !ok {
			return nil, fmt.Errorf(
				"scalegrid: %s объявлен оснасткой отпечатка, но %s — значит он влияет на измеряемую "+
					"стоимость и обязан вернуться под отпечаток; сними его из fingerprintScaffolding",
				rel, why)
		}
	}
	for rel := range fingerprintScaffolding {
		if !seen[rel] {
			return nil, fmt.Errorf(
				"scalegrid: %s объявлен оснасткой отпечатка, но в дереве его нет — "+
					"исключение пережило свой предмет и молча покрывает пустоту", rel)
		}
	}
	return out, nil
}

// ContentOf — отпечаток содержимого ОДНОГО файла; гейт называет им виновника.
func ContentOf(root, rel string) string {
	sum, err := contentHash(root, []string{rel})
	if err != nil {
		return "нечитаем"
	}
	return sum
}

func nonTestGoFiles(root, dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil {
		return nil, fmt.Errorf("scalegrid: состав %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, dir+"/"+name)
	}
	sort.Strings(out)
	return out, nil
}

func migrationsNaming(root string, tables []string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, migrateDir))
	if err != nil {
		return nil, fmt.Errorf("scalegrid: состав %s: %w", migrateDir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(root, migrateDir, name)) // #nosec G304 -- name получено обходом СОБСТВЕННОГО каталога миграций репозитория, не из запроса и не от пользователя; прибор читает свои же файлы, чтобы взять их отпечаток
		if rerr != nil {
			return nil, fmt.Errorf("scalegrid: чтение миграции %s: %w", name, rerr)
		}
		if migrationTouchesStructure(string(body), tables) {
			out = append(out, migrateDir+"/"+name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// migrationTouchesStructure — меняет ли миграция СТРУКТУРУ одной из измеряемых
// таблиц, то есть способна ли она изменить стоимость, о которой отчёт говорит.
//
// # Почему не «встречается имя таблицы»
//
// Прежний предикат брал подстроку ГДЕ УГОДНО в файле — включая комментарий и
// посев данных. Отпечаток от этого становился шире своего предмета: отчёт
// обесценивался миграцией, которая измеряемого пути не касалась вовсе, а каждая
// пересъёмка стоит около двух часов прогона. Замер 2026-08-22 на этом дереве:
// широкий предикат брал 115 миграций, узкий — 74; то есть **41 файл**, больше
// трети множества, сторожились без предмета.
//
// # Что считается влиянием, а что нет
//
//	влияет     CREATE/ALTER/DROP над таблицей или её индексом — план чтения меняется
//	не влияет  упоминание в комментарии — текст не исполняется вовсе
//	не влияет  INSERT/UPDATE/DELETE — данные меняют СТОИМОСТЬ прогона, но её
//	           меряет сам прогон; отпечаток же отвечает на «изменилось ли ТО,
//	           ЧЕМ мерили», а не «изменилось ли то, ЧТО намеряли»
//
// Граница названа честно: DDL над измеряемой таблицей включается ВСЕГДА, даже
// если конкретная правка плана не меняет (комментарий к колонке, снятие
// умолчания). Судить об этом пришлось бы по смыслу, а не по форме, — и первая
// же ошибка суждения дала бы отчёт, который выглядит свежим и не является им.
// Ошибка в эту сторону стоит лишнего прогона; в обратную — ложного числа.
//
// # Временный объект структуры не меняет (#1833)
//
// Форма «создать временную таблицу из выборки» несёт в ОДНОМ операторе три
// признака сразу — `CREATE`, `DROP` (из хвоста `ON COMMIT DROP`) и имя
// измеряемой таблицы, — но DDL идёт над временной таблицей, а измеряемая только
// ЧИТАЕТСЯ. Плана чтения это не меняет, и отчёт от такой миграции ложным не
// становится. Прежний предикат брал оператор целиком, потому что требовал лишь
// совпадения глагола и имени где угодно в одном куске.
//
// Поэтому конструкции DDL над ВРЕМЕННЫМ объектом снимаются с оператора до
// проверки на глагол: остался глагол — оператор судится как прежде, не
// остался — оператор структуры не менял. Обратная сторона сохранена и
// проверяется законным близнецом: та же форма БЕЗ слова `TEMP` создаёт таблицу
// в схеме и под отпечаток попадает.
func migrationTouchesStructure(src string, tables []string) bool {
	code := stripSQLComments(src)
	for _, stmt := range strings.Split(code, ";") {
		if !ddlVerbRe.MatchString(stripTempObjectDDL(stmt)) {
			continue
		}
		for _, tbl := range tables {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(tbl) + `\b`).MatchString(stmt) {
				return true
			}
		}
	}
	return false
}

var (
	ddlVerbRe       = regexp.MustCompile(`(?i)\b(CREATE|ALTER|DROP)\b`)
	sqlLineComment  = regexp.MustCompile(`--[^\n]*`)
	sqlBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

	// tempObjectCreate — создание ВРЕМЕННОГО объекта. Временный объект живёт в
	// `pg_temp` и измеряемой таблицей быть не может by construction, поэтому
	// глагол над ним о структуре схемы не говорит ничего.
	tempObjectCreate = regexp.MustCompile(`(?i)\bCREATE\s+(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY)\s+(?:UNLOGGED\s+)?(?:TABLE|VIEW|SEQUENCE)\b`)

	// tempOnCommit — хвост `ON COMMIT …` формы создания временной таблицы.
	// Слово `DROP` здесь — часть объявления времени жизни, а не снятие объекта;
	// в Postgres эта оговорка законна ТОЛЬКО у временной таблицы.
	tempOnCommit = regexp.MustCompile(`(?i)\bON\s+COMMIT\s+(?:DROP|DELETE\s+ROWS|PRESERVE\s+ROWS)\b`)
)

// stripTempObjectDDL — оператор без конструкций DDL над временными объектами.
//
// Снимается ровно объявление (`CREATE TEMP TABLE`, хвост `ON COMMIT …`), а не
// весь оператор: всё остальное — включая соседний глагол над измеряемой
// таблицей, если он в этом же операторе есть, — судится как прежде.
func stripTempObjectDDL(stmt string) string {
	return tempOnCommit.ReplaceAllString(tempObjectCreate.ReplaceAllString(stmt, " "), " ")
}

// stripSQLComments — текст без комментариев: они не исполняются, значит на
// стоимость влиять не могут. Имя таблицы в объяснении, ПОЧЕМУ её здесь не
// трогают, — самый частый вид ложного попадания под отпечаток.
func stripSQLComments(src string) string {
	return sqlLineComment.ReplaceAllString(sqlBlockComment.ReplaceAllString(src, " "), " ")
}

// tableNamesIn — имена `kacho_iam.<таблица>`, встреченные в тексте.
func tableNamesIn(src string) []string {
	var out []string
	seen := map[string]bool{}
	for i := 0; ; {
		j := strings.Index(src[i:], fingerprintTableMark)
		if j < 0 {
			break
		}
		start := i + j
		k := start + len(fingerprintTableMark)
		for k < len(src) && (src[k] == '_' || (src[k] >= 'a' && src[k] <= 'z') ||
			(src[k] >= 'A' && src[k] <= 'Z') || (src[k] >= '0' && src[k] <= '9')) {
			k++
		}
		name := src[start:k]
		if name != fingerprintTableMark && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		i = k
	}
	return out
}

// Marker* — приставки строк отпечатка в шапке. Читает их гейт, поэтому они
// объявлены здесь, рядом с писателем: разъехавшись, писатель и читатель дали бы
// «отпечаток не найден» на исправном отчёте.
const (
	MarkerComposition = "  отпечаток состава     "
	MarkerContent     = "  отпечаток содержимого "
	MarkerFile        = "    "
	MarkerFileList    = "  ФАЙЛЫ ПОД ОТПЕЧАТКОМ (пофайлово, чтобы гейт назвал ВИНОВНИКА, а не только факт)"
)

// FingerprintLines — строки отпечатка для шапки отчёта.
//
// Пофайлово, а не одним числом: гейт, знающий только итоговый хэш, умеет
// сказать «что-то сдвинулось» и не умеет сказать ЧТО — а находка без координаты
// требует от читателя той же работы заново.
func (fp Fingerprint) FingerprintLines(root string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n", MarkerComposition, fp.Composition)
	fmt.Fprintf(&b, "%s%s\n", MarkerContent, fp.Content)
	fmt.Fprintf(&b, "  файлов под отпечатком %d, таблиц выведено %d (%s)\n",
		len(fp.Files), len(fp.Tables), strings.Join(fp.Tables, ", "))
	predicate := fp.Predicate
	if predicate == "" {
		predicate = FingerprintPredicate
	}
	fmt.Fprintf(&b, "  предикат отпечатка    %s\n", predicate)
	fmt.Fprintf(&b, "%s\n", MarkerFileList)
	for _, rel := range fp.Files {
		fmt.Fprintf(&b, "%s%s  %s\n", MarkerFile, ContentOf(root, rel), rel)
	}
	return b.String()
}
