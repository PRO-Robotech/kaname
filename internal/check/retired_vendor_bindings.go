// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_vendor_bindings.go — ГЕЙТ КЛАССА: привязок к снимаемому провайдеру
// личности в дереве службы не становится больше, а их убыль записывается тем же
// изменением, которым она сделана (задача #323, эпик kacho#2564).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Прежний провайдер личности (выдача токена и сессия) снимается из службы.
// Снятие идёт многими изменениями, и каждое из них обязано уменьшать число
// привязок, а не менять одни на другие. Замер задачи: поле адреса прежнего
// издателя в конфигурации обогащения токена стояло в 74 строках 30 файлов на
// cbbac984 и в 79 строках 31 файла на 8f95be6c6 — две новые пробы полос хуков
// привязались к нему, и ни одна проверка этого дерева не покраснела.
//
// Судья этого класса у платформы (задачи kacho#2730 и kacho#2864, файл
// `internal/repohygiene/retiredidentityvendorceiling.go` её дерева) читает
// дерево службы ПО ПИНУ `go.mod` платформы, то есть видит рост только тогда,
// когда платформа сдвигает пин, — после того как выросшее изменение уже влито
// здесь. Этот гейт судит то же дерево в момент изменения.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА — ВЕДОМОСТЬ ПО ФАЙЛАМ, А НЕ ОДНО ЧИСЛО
//
// Ведомость (`RetiredVendorLedger`, файл `RetiredVendorLedgerRel`) хранит
// ТОЧНОЕ число привязок каждого файла. Исходов у файла три, и два из них —
// находки:
//
//	привязок больше записи (или записи нет)   рост — снимите привязку
//	привязок меньше записи                    убыль не записана — снизьте запись
//	                                          до факта тем же изменением
//	привязок ноль, запись есть                запись без предмета — снимите её
//
// Почему по файлам: сумма по дереву ПРОЩАЕТ перенос. Изменение, снявшее десять
// строк в одном файле и добавившее одну в новом, по сумме убывает — а новая
// привязка при этом появилась. Ровно так выглядел рост этой задачи: по всему
// классу в единице этого гейта дерево между cbbac984 и 8f95be6c6 убыло с 1068
// до 873, а две пробы привязались заново. Ведомость по файлам называет такую
// координату, сумма — нет.
//
// Почему точное число, а не потолок: потолок, не сниженный вслед за убылью,
// прощает возврат снятого до прежней высоты. Точная запись делает возврат
// ростом.
//
// ЗАПИСЬ ЗАНИМАЕТ ДВЕ СТРОКИ — путь и число, — и это решение о слиянии, а не
// вкус. git сливает правки СОСЕДНИХ строк конфликтом (проверено на git 2.53:
// правки строк 2 и 3 в двух ветках дают конфликт, правки строк 2 и 4 при
// нетронутой строке 3 — чистое слияние). Две ветки волны, снявшие привязки в
// разных файлах, правят числа разных записей; строка пути между числами
// остаётся нетронутой, и сведение волны не конфликтует в ведомости.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА И ОСИ
//
// Класс один: текст несёт имя снимаемого провайдера (`RetiredVendorMarks`),
// подстрокой без учёта регистра. Мест прочтения три, по оси на каждое:
//
//	RetiredVendorAxisPath    путь файла несёт имя        1 единица за файл
//	RetiredVendorAxisLine    строка текста несёт имя     1 единица за строку
//	RetiredVendorAxisBinary  байты двоичного несут имя   1 единица за файл
//
// Граница слова НЕ ставится: слитное написание строчными — настоящая
// привязка, и правило границы отбросило бы её молча. Измерено на 8f95be6c6:
// слов, где имя продолжено строчной буквой, в дереве службы два
// (`hydraadminurl`, `hydraadmintokenenv`), и оба — привязки. Чужое слово,
// втекающее в имя, придёт находкой роста со своим текстом — видно, а не молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЕ ФОРМЫ — КАК СНЯТИЕ ЗАПИСЫВАЕТСЯ, НЕ ПОДНИМАЯ ВЕДОМОСТИ
//
// Подъём записи ответом не бывает (граница 4 ниже). Формы, которыми снятие
// обходится без него:
//
//   - ИСТОРИЯ СХЕМЫ СНЯТОГО. Строка каталога истории схемы (миграции и их
//     пробы), каждое имя провайдера в которой — часть идентификатора, снятого
//     самой историей, не привязка: миграция, снимающая столбец, обязана его
//     назвать. Правило, условия и границы — `retired_vendor_schema_history.go`;
//     перепись печатает число таких строк отдельно.
//   - ИМЯ ИЗ СЛОВАРЯ. Проба стража этого класса берёт имя провайдера из его
//     словаря (`RetiredVendorMarks`, `RetiredIssuerName`), а не выписывает
//     заново: привязка — строка словаря, и считается она один раз. То же
//     для имени настройки: проба собирает его из того же словаря, а не
//     выписывает литералом.
//   - ПЕРЕНОС. Запись нового файла заводится, запись прежнего снижается, обе
//     правки — в одном диффе (шапка ведомости).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ВИДИТ — НАЗВАНО, А НЕ ПОДРАЗУМЕВАЕТСЯ
//
//  1. ПРОЗА. Файлы `.md`/`.mdx` и строки, НАЧИНАЮЩИЕСЯ маркером комментария, не
//     судятся: упоминание провайдера в тексте дерево к нему не привязывает, а
//     утверждение о нём как о действующем судит `retired_issuer_claim.go`.
//     Перепись печатает число таких строк отдельно.
//  2. ВЕДОМОСТЬ. Файл `RetiredVendorLedgerRel` — запись этого гейта, а не
//     привязка; он исключён по точному пути, и его отсутствие в дереве — отказ
//     (исключение, которому нечего исключать, истекает само).
//  3. ПУТЬ API ПРОВАЙДЕРА БЕЗ ЕГО ИМЕНИ, ИМЯ, СКЛЕЕННОЕ ИЗ ЛИТЕРАЛОВ, И
//     СОДЕРЖИМОЕ АРХИВОВ. Эти оси держит судья платформы по пину: словарь
//     поверхностей живёт у него в единственном экземпляре, копия его сюда
//     запрещена правилом о копиях между репозиториями. Архивов в дереве службы
//     нет; двоичные судятся байтами, и их число печатается переписью.
//  4. ПОДЪЁМ ЗАПИСИ. Ведомость — файл дерева, и изменение может поднять число
//     записи вместе с ростом. Гейт этого не различает: без дерева базы перенос
//     привязки из файла в файл и чистый рост дают одну и ту же правку. Подъём
//     виден диффом одного файла, а чистый рост против базы ловит судья
//     платформы на сдвиге пина. Так зелёное уже добывалось: сборка #483
//     подняла пять записей на 42 (коммит 49c38e18c) — строки снятия столбца,
//     проба стража с именем литералом, проба с именем настройки литералом и
//     перенос методов, записанный не в том диффе, где снижен прежний файл.
//     Каждому из этих случаев отвечает законная форма выше.
//  5. ИМЯ ИЗ СЛОВАРЯ В НЕ-ПРОБЕ. Форма «имя из словаря» законна для проб
//     стража; не-тестовый код, собирающий имя провайдера из словаря, привязку
//     прячет, и гейт её не видит — как и всякую склейку (граница 3).
package check

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// RetiredVendorLedgerRel — путь ведомости от корня дерева. Единственный путь,
// исключённый из обхода поимённо.
const RetiredVendorLedgerRel = "internal/check/retired_vendor_bindings_ledger.go"

// RetiredVendorMarks — имя снимаемого провайдера личности, по которому
// узнаётся класс: служба выдачи, служба сессии и пространство их образов.
// Голое имя издателя библиотек сюда НЕ входит: под ним же живёт библиотека
// собственной чеканки токенов, ради которой снятие и делается.
var RetiredVendorMarks = []string{"hydra", "kratos", "oryd/"}

// RetiredVendorCountingUnit — единица счёта одним текстом; печатается переписью.
const RetiredVendorCountingUnit = "строка текста, несущая имя провайдера, — одна единица, " +
	"сколько бы вхождений в ней ни было; путь, несущий имя, — одна единица за файл сверх " +
	"его строк; двоичный файл с именем в байтах — одна единица"

// Оси — константами, чтобы проба утверждала ось, а не подстроку текста.
const (
	RetiredVendorAxisPath   = "имя провайдера в пути"
	RetiredVendorAxisLine   = "имя провайдера в строке"
	RetiredVendorAxisBinary = "имя провайдера в байтах двоичного"
)

// Виды находки — закрытый словарь.
const (
	RetiredVendorGrown  = "рост"
	RetiredVendorShrunk = "убыль не записана"
	RetiredVendorOrphan = "запись без предмета"
)

// Отказы: там, где судить не по чему. Третья категория, а не «находок ноль».
var (
	// ErrRetiredVendorLedgerAbsent — файла ведомости нет в обходе.
	ErrRetiredVendorLedgerAbsent = errors.New("файла ведомости нет в обойдённом дереве")
	// ErrRetiredVendorLedgerForm — ведомость записана не по форме.
	ErrRetiredVendorLedgerForm = errors.New("ведомость записана не по форме")
)

// retiredVendorTextCap — предел длины текста строки в находке, байт. Число
// судится по строкам целиком; усекается только показ.
const retiredVendorTextCap = 200

// RetiredVendorLedgerEntry — одна запись ведомости: файл и точное число его
// привязок в единице `RetiredVendorCountingUnit`.
type RetiredVendorLedgerEntry struct {
	File     string
	Bindings int
}

// RetiredVendorBinding — одна привязка.
type RetiredVendorBinding struct {
	File string
	// Line — номер строки; 0 там, где судится файл целиком (путь, байты).
	Line int
	Axis string
	Text string
}

// Coord — координата привязки: `файл:строка · ось · текст`.
func (b RetiredVendorBinding) Coord() string {
	at := b.File
	if b.Line > 0 {
		at = fmt.Sprintf("%s:%d", b.File, b.Line)
	}
	return fmt.Sprintf("%s · %s · %s", at, b.Axis, b.Text)
}

// RetiredVendorFinding — расхождение файла с его записью.
type RetiredVendorFinding struct {
	Kind     string
	File     string
	Recorded int
	Actual   int
	// Bindings — все привязки файла; у роста это и есть координата.
	Bindings []RetiredVendorBinding
}

func (f RetiredVendorFinding) String() string {
	switch f.Kind {
	case RetiredVendorGrown:
		recorded := fmt.Sprintf("при записи %d", f.Recorded)
		if f.Recorded == 0 {
			recorded = "при отсутствии записи"
		}
		lines := make([]string, 0, len(f.Bindings))
		for _, b := range f.Bindings {
			lines = append(lines, b.Coord())
		}
		return fmt.Sprintf("%s: %s — привязок к снимаемому провайдеру личности %d %s (+%d). "+
			"Снятие идёт в одну сторону: снимите привязку. Перенос из другого файла — "+
			"запись этого файла и снижение записи того тем же изменением. Привязки "+
			"файла, все %d:\n  %s",
			f.Kind, f.File, f.Actual, recorded, f.Actual-f.Recorded, len(lines),
			strings.Join(lines, "\n  "))
	case RetiredVendorShrunk:
		return fmt.Sprintf("%s: %s — привязок %d при записи %d (−%d). Снизьте запись "+
			"`%s` до %d тем же изменением: не сниженная запись простит возврат снятого",
			f.Kind, f.File, f.Actual, f.Recorded, f.Recorded-f.Actual, f.File, f.Actual)
	default:
		return fmt.Sprintf("%s: %s — привязок 0 при записи %d. Снимите запись `%s` тем "+
			"же изменением: запись, которой нечего описывать, истекает вместе с предметом",
			f.Kind, f.File, f.Recorded, f.File)
	}
}

// RetiredVendorCensus — объём осмотренного. Печатается всегда: «находок ноль»
// обязано быть отличимо от «прочитано ноль».
type RetiredVendorCensus struct {
	// Разбиение обхода: Text + Binary + Prose + Ledger == Walked.
	Walked int
	Text   int
	Binary int
	Prose  int
	Ledger int
	// Lines — строк прочитано в судимых построчно.
	Lines int
	// CommentSkipped — строк, несущих имя, но начинающихся маркером
	// комментария: цена границы, названная числом.
	CommentSkipped int

	// История схемы (`retired_vendor_schema_history.go`): миграций прочитано,
	// идентификаторов, снятых историей, и строк истории снятого — законная
	// форма снятия, названная числом, а не умолчанием.
	HistoryMigrations int
	HistoryRemoved    int
	HistoryLines      int

	Bindings int
	ByPath   int
	ByLine   int
	ByBinary int
	// Files — файлов, несущих хоть одну привязку.
	Files int

	// Entries, Recorded — записей ведомости и их сумма.
	Entries  int
	Recorded int

	Findings int
}

func (c RetiredVendorCensus) String() string {
	return fmt.Sprintf("перепись: путей обойдено %d = судимо построчно %d · двоичных %d · "+
		"прозы %d (граница) · ведомость %d (граница) · строк прочитано %d · строк-комментариев "+
		"с именем провайдера %d (граница) · история схемы: миграций %d, снятых ею идентификаторов %d, "+
		"строк истории снятого %d (законная форма) · привязок %d (в пути %d · в строке %d · в байтах %d) "+
		"в %d файлах · ведомость: записей %d, сумма %d · находок %d; единица счёта — %s",
		c.Walked, c.Text, c.Binary, c.Prose, c.Ledger, c.Lines, c.CommentSkipped,
		c.HistoryMigrations, c.HistoryRemoved, c.HistoryLines,
		c.Bindings, c.ByPath, c.ByLine, c.ByBinary, c.Files, c.Entries, c.Recorded,
		c.Findings, RetiredVendorCountingUnit)
}

// RetiredVendorVerdict — исход суда над деревом.
type RetiredVendorVerdict struct {
	Findings []RetiredVendorFinding
	Census   RetiredVendorCensus
	// PerFile — привязки дерева по файлу.
	PerFile map[string][]RetiredVendorBinding
	// RemovedBySchemaHistory — идентификаторы, снятые историей схемы, по
	// возрастанию.
	RemovedBySchemaHistory []string
}

// Roster — перечень файлов с привязками: `число · путь`, по пути. Форма
// совпадает с тем, что ведомость обязана записать.
func (v RetiredVendorVerdict) Roster() string {
	files := make([]string, 0, len(v.PerFile))
	for f := range v.PerFile {
		files = append(files, f)
	}
	sort.Strings(files)
	rows := make([]string, 0, len(files))
	for _, f := range files {
		rows = append(rows, fmt.Sprintf("%d · %s", len(v.PerFile[f]), f))
	}
	return strings.Join(rows, "\n")
}

// JudgeRetiredVendorBindings — тело гейта над телами файлов дерева и ведомостью.
// Вынесено, чтобы инъекция звала ТО ЖЕ, что исполняется на дереве. Корпус — ВСЕ
// отслеживаемые файлы: проза и ведомость отсеиваются здесь, а не у читателя,
// иначе правило отбора жило бы вне пробы.
func JudgeRetiredVendorBindings(corpus TreeCorpus, ledger []RetiredVendorLedgerEntry) (RetiredVendorVerdict, error) {
	v := RetiredVendorVerdict{PerFile: map[string][]RetiredVendorBinding{}}
	c := &v.Census
	c.Walked = len(corpus)
	if len(corpus) == 0 {
		return v, fmt.Errorf("%w — судить нечего", ErrEmptyTraversal)
	}
	if _, ok := corpus[RetiredVendorLedgerRel]; !ok {
		return v, fmt.Errorf("%w: %s — исключение, которому нечего исключать, истекает само: "+
			"ведомость переехала либо снята, а константа пути осталась",
			ErrRetiredVendorLedgerAbsent, RetiredVendorLedgerRel)
	}
	recorded, err := retiredVendorLedgerIndex(ledger)
	if err != nil {
		return v, err
	}
	c.Entries = len(ledger)
	for _, e := range ledger {
		c.Recorded += e.Bindings
	}
	hist := buildRetiredVendorSchemaHistory(corpus)
	c.HistoryMigrations = hist.migrations
	c.HistoryRemoved = len(hist.removed)
	v.RemovedBySchemaHistory = hist.removedSorted()

	for _, rel := range corpus.Rels() {
		switch {
		case rel == RetiredVendorLedgerRel:
			c.Ledger++
			continue
		case retiredVendorProse(rel):
			c.Prose++
			continue
		}
		body := corpus[rel]
		var found []RetiredVendorBinding
		if retiredVendorCarries(rel) {
			c.ByPath++
			found = append(found, RetiredVendorBinding{File: rel, Axis: RetiredVendorAxisPath, Text: rel})
		}
		if strings.ContainsRune(body, 0) || !utf8.ValidString(body) {
			c.Binary++
			if retiredVendorCarries(body) {
				c.ByBinary++
				found = append(found, RetiredVendorBinding{File: rel, Axis: RetiredVendorAxisBinary, Text: rel})
			}
		} else {
			c.Text++
			c.Lines += strings.Count(body, "\n") + 1
			if retiredVendorCarries(body) {
				for i, line := range strings.Split(body, "\n") {
					if !retiredVendorCarries(line) {
						continue
					}
					if retiredVendorCommentLine(line) {
						c.CommentSkipped++
						continue
					}
					if hist.isHistoryLine(rel, line) {
						c.HistoryLines++
						continue
					}
					c.ByLine++
					found = append(found, RetiredVendorBinding{
						File: rel, Line: i + 1, Axis: RetiredVendorAxisLine,
						Text: retiredVendorShown(strings.TrimSpace(line)),
					})
				}
			}
		}
		if len(found) > 0 {
			v.PerFile[rel] = found
		}
	}
	c.Files = len(v.PerFile)
	c.Bindings = c.ByPath + c.ByLine + c.ByBinary

	files := make([]string, 0, len(v.PerFile)+len(recorded))
	for f := range v.PerFile {
		files = append(files, f)
	}
	for f := range recorded {
		if _, ok := v.PerFile[f]; !ok {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		actual, want := len(v.PerFile[f]), recorded[f]
		switch {
		case actual > want:
			v.Findings = append(v.Findings, RetiredVendorFinding{
				Kind: RetiredVendorGrown, File: f, Recorded: want, Actual: actual, Bindings: v.PerFile[f]})
		case actual == 0:
			v.Findings = append(v.Findings, RetiredVendorFinding{
				Kind: RetiredVendorOrphan, File: f, Recorded: want})
		case actual < want:
			v.Findings = append(v.Findings, RetiredVendorFinding{
				Kind: RetiredVendorShrunk, File: f, Recorded: want, Actual: actual})
		}
	}
	c.Findings = len(v.Findings)
	return v, nil
}

// retiredVendorLedgerIndex — ведомость картой, с проверкой формы: путь непуст,
// число положительно, пути строго по возрастанию (порядок — часть формы: два
// сводимых изменения обязаны вставлять запись в одно и то же место).
func retiredVendorLedgerIndex(ledger []RetiredVendorLedgerEntry) (map[string]int, error) {
	out := make(map[string]int, len(ledger))
	for i, e := range ledger {
		switch {
		case e.File == "":
			return nil, fmt.Errorf("%w: запись %d без пути", ErrRetiredVendorLedgerForm, i+1)
		case e.Bindings <= 0:
			return nil, fmt.Errorf("%w: запись %s несёт %d — запись с нулём не описывает "+
				"ничего и снимается вместе с последней привязкой файла",
				ErrRetiredVendorLedgerForm, e.File, e.Bindings)
		case i > 0 && ledger[i-1].File >= e.File:
			return nil, fmt.Errorf("%w: запись %s стоит после %s — пути идут строго по "+
				"возрастанию, без повторов", ErrRetiredVendorLedgerForm, e.File, ledger[i-1].File)
		}
		out[e.File] = e.Bindings
	}
	return out, nil
}

// retiredVendorProse — проза: объявленный вид содержимого, а не догадка.
func retiredVendorProse(rel string) bool {
	lower := retiredVendorASCIILower(rel)
	return strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".mdx")
}

// retiredVendorCarries — текст несёт имя провайдера, без учёта регистра.
func retiredVendorCarries(text string) bool {
	lower := retiredVendorASCIILower(text)
	for _, m := range RetiredVendorMarks {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// retiredVendorASCIILower — нижний регистр только для латиницы, по байтам.
// Имена провайдера — ASCII; библиотечное приведение меняет длину на
// невалидной последовательности, а двоичные судятся тем же предикатом.
func retiredVendorASCIILower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// retiredVendorCommentLine — строка НАЧИНАЕТСЯ маркером комментария. Маркеры
// те же, что у судьи платформы: `--` и `*` — только с пробелом следом, иначе
// это флаг командной строки, то есть настоящая привязка.
func retiredVendorCommentLine(line string) bool {
	s := strings.TrimLeft(line, " \t")
	switch {
	case strings.HasPrefix(s, "#"), strings.HasPrefix(s, "//"),
		strings.HasPrefix(s, "<!--"), strings.HasPrefix(s, ";"):
		return true
	case s == "--" || s == "*":
		return true
	case strings.HasPrefix(s, "-- "), strings.HasPrefix(s, "--\t"),
		strings.HasPrefix(s, "* "), strings.HasPrefix(s, "*\t"):
		return true
	}
	return false
}

// retiredVendorShown — текст строки для показа, усечённый по границе руны.
func retiredVendorShown(s string) string {
	if len(s) <= retiredVendorTextCap {
		return s
	}
	cut := retiredVendorTextCap
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
