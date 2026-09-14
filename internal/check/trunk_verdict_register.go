// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// trunk_verdict_register.go — РАЗБОР ПЕРЕЧНЯ «что не переносится со слияния на
// ствол» (задача PRO-Robotech/kaname#62, предикат 3).
//
// # ПРЕДМЕТ
//
// Держатель делает красное ствола заметным. Он не отвечает на второй вопрос:
// ПОЧЕМУ зелёная кнопка слияния этого не обещала. Ответ — свойство продукта, а
// не прогона, и живёт он перечнем: свойство · почему не переносится · ЧЕМ
// СУДИТСЯ ПОСЛЕ ПОСАДКИ.
//
// # ПОЧЕМУ У КАЖДОЙ СТРОКИ ОБЯЗАН БЫТЬ ПРОИЗВОДИТЕЛЬ
//
// Строка без третьей колонки — обещание: она называет расхождение и не называет
// никого, кто его заметит. Ровно этот класс задача #62 и закрывает, поэтому
// перечень, заведённый ради неё, не вправе его воспроизводить.
//
// # КООРДИНАТА ЗАДАНИЯ БЕРЁТСЯ ПО ПОЗИЦИИ, А НЕ ПО ФОРМЕ ИМЕНИ
//
// Первая редакция считала заданием всякое имя в обратных кавычках, похожее на
// идентификатор. Она провалила собственный контроль: из 23 распознанных имён 7
// заданиями НЕ были — флаги (`--push`, `--self-test`), ключи объявления
// (`push`, `cancel-in-progress`), имя процесса (`ci`), имя пробы и имя
// переменной Go. Форма у них общая с формой идентификатора задания, и отличить
// их по ней нельзя ни при какой аккуратности.
//
// Поэтому координатой задания считается ровно ВТОРАЯ КОЛОНКА таблицы
// обязательных контекстов — место, где задание стоит структурно. Прозу гейт не
// разбирает вовсе: имя, названное в ней, он не объявляет ни верным, ни ложным,
// и это сказано здесь, чтобы его молчание не принимали за проверку.
//
// # ЧТО ГЕЙТ ДЕРЖИТ, А ЧТО НЕТ — СКАЗАНО ПРЯМО
//
// Держит: каждая строка полна · каждое задание, названное СТРУКТУРНО, существует
// в дереве · каждый процесс ствола в перечне назван. НЕ держит: имена, названные
// прозой (см. выше), и ИСТИННОСТЬ третьей колонки
// — машинно «судит ли это на самом деле» не решается, и обещать обратное значило
// бы завести ту же форму без содержания этажом выше.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// TrunkRegisterRel — дом перечня. ОДНО объявление координаты.
const TrunkRegisterRel = ".github/TRUNK-VERDICT.md"

// registerRow — строка таблицы перечня.
type registerRow struct {
	Cells []string
	Line  int
}

// inlineCode — имена в обратных кавычках: по ним перечень называет координаты.
var inlineCode = regexp.MustCompile("`([^`]+)`")

// TrunkRegisterCensus — объём осмотренного.
type TrunkRegisterCensus struct {
	// Rows — строк перечня «что не переносится»; Complete — из них с непустым
	// производителем. Contexts — строк таблицы обязательных контекстов.
	Rows, Complete, Contexts int
	// JobsNamed — упомянутых заданий; JobsResolved — из них найденных в дереве.
	JobsNamed, JobsResolved int
	// ProcessesNamed — процессов ствола, названных перечнем, из ProcessesOnTrunk.
	ProcessesNamed, ProcessesOnTrunk int
}

// String — перепись одной строкой: «ноль находок» обязано быть отличимо от
// «ноль прочитанного».
func (c TrunkRegisterCensus) String() string {
	return fmt.Sprintf("строк перечня %d (с производителем %d) · строк контекстов %d · "+
		"названо заданий %d (резолвится %d) · процессов ствола названо %d из %d",
		c.Rows, c.Complete, c.Contexts, c.JobsNamed, c.JobsResolved,
		c.ProcessesNamed, c.ProcessesOnTrunk)
}

// isSeparator — строка-разделитель шапки таблицы (`|---|---|`).
func isSeparator(t string) bool {
	if !strings.HasPrefix(t, "|") || !strings.HasSuffix(t, "|") {
		return false
	}
	body := strings.Trim(t, "|")
	return strings.TrimSpace(strings.NewReplacer("-", "", "|", "", ":", "").Replace(body)) == ""
}

// markdownRows — строки таблиц документа, кроме заголовочных и разделительных.
//
// ШАПКА ОТСЕКАЕТСЯ ПО СЛЕДУЮЩЕЙ СТРОКЕ, а не по номеру и не по содержимому.
// Первая редакция её не отсекала, и перепись насчитывала девять строк перечня
// при семи: шапка обеих таблиц шла в счёт. Число, которое перепись печатает,
// обязано быть тем, которое она измеряет, — иначе она сама есть форма без
// содержания. Хуже счёта было второе: шапка перечня несёт три непустые клетки и
// потому «полна» ПО ПОСТРОЕНИЮ, то есть подпирала бы утверждение о полноте
// строк, ни одной строкой не являясь.
func markdownRows(raw string) []registerRow {
	lines := strings.Split(raw, "\n")
	var out []registerRow
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "|") || !strings.HasSuffix(t, "|") {
			continue
		}
		if isSeparator(t) {
			continue
		}
		if i+1 < len(lines) && isSeparator(strings.TrimSpace(lines[i+1])) {
			continue // шапка: за нею идёт разделитель
		}
		body := strings.Trim(t, "|")
		cells := strings.Split(body, "|")
		for j := range cells {
			cells[j] = strings.TrimSpace(cells[j])
		}
		out = append(out, registerRow{Cells: cells, Line: i + 1})
	}
	return out
}

// DeclaredContexts — обязательные контексты, ОБЪЯВЛЕННЫЕ перечнем (первая
// колонка таблицы контекстов).
//
// Живут они не в дереве, а в настройках ветки, поэтому перечень их копирует — и
// копия обязана быть сверяема. Сверку делает вызывающий (это сеть), а не эта
// функция; здесь — только то, что объявлено.
func DeclaredContexts(raw string, trunkProcesses []string) []string {
	var out []string
	for _, r := range markdownRows(raw) {
		if len(r.Cells) != 3 {
			continue
		}
		if _, isProc := registerHasProcess(trunkProcesses, r.Cells[2]); !isProc {
			continue
		}
		name := strings.Trim(r.Cells[0], "`")
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AuditTrunkRegister — вердикт о перечне.
//
// jobs — задания, существующие в дереве (имя задания → процесс); trunkProcesses
// — отображаемые имена процессов ствола. Чистая функция от входа затем, чтобы
// инъекция подавалась входом, а не правкой дерева.
func AuditTrunkRegister(raw string, jobs map[string]string, trunkProcesses []string) ([]string, TrunkRegisterCensus, error) {
	var census TrunkRegisterCensus
	if strings.TrimSpace(raw) == "" {
		return nil, census, fmt.Errorf("перечень %s пуст — вердикт беспредметен", TrunkRegisterRel)
	}
	if len(jobs) == 0 {
		return nil, census, fmt.Errorf("заданий дерева подано ноль: резолвить координаты не с чем, " +
			"и «все резолвятся» означало бы «ни одной не проверили»")
	}

	rows := markdownRows(raw)
	if len(rows) == 0 {
		return nil, census, fmt.Errorf("в %s ноль строк таблиц — разбор не дошёл до перечня", TrunkRegisterRel)
	}

	var findings []string
	named := map[string]bool{}

	for _, r := range rows {
		switch len(r.Cells) {
		case 3:
			// Таблица контекстов — три колонки, средняя есть задание.
			// Перечень «что не переносится» — тоже три; различает их третья:
			// у контекстов там имя процесса, у перечня — производитель.
			if _, isProc := registerHasProcess(trunkProcesses, r.Cells[2]); isProc {
				census.Contexts++
				for _, m := range inlineCode.FindAllStringSubmatch(r.Cells[1], -1) {
					named[m[1]] = true
				}
				continue
			}
			census.Rows++
			if r.Cells[2] == "" {
				findings = append(findings, fmt.Sprintf(
					"строка %d перечня не называет, ЧЕМ свойство судится после посадки: "+
						"%q — это обещание, а не проверка", r.Line, trimCell(r.Cells[0])))
			} else {
				census.Complete++
			}
		default:
			findings = append(findings, fmt.Sprintf(
				"строка %d несёт %d колонок вместо трёх: перечень читается разбором, и "+
					"неполная строка молча выпала бы из него", r.Line, len(r.Cells)))
		}
	}

	if census.Rows == 0 {
		return nil, census, fmt.Errorf("перечень «что не переносится» пуст: ноль строк есть " +
			"«ноль прочитанного», а не «расхождений нет»")
	}

	// КООРДИНАТЫ РЕЗОЛВЯТСЯ. Имя задания, пережившее своё задание, посылает
	// читателя искать не там — и выглядит при этом действующим утверждением.
	keys := make([]string, 0, len(named))
	for k := range named {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		census.JobsNamed++
		if _, ok := jobs[k]; ok {
			census.JobsResolved++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"перечень называет задание %q, которого в дереве нет: координата пережила свой "+
				"предмет", k))
	}

	// КАЖДЫЙ ПРОЦЕСС СТВОЛА НАЗВАН. Заведут четвёртый — перечень обязан сказать,
	// что он обещает и чем судится, а не промолчать о нём.
	census.ProcessesOnTrunk = len(trunkProcesses)
	for _, p := range trunkProcesses {
		if strings.Contains(raw, p) {
			census.ProcessesNamed++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"процесс ствола %q в перечне не назван: его вердикт не объяснён ничем", p))
	}
	return findings, census, nil
}

func registerHasProcess(hay []string, needle string) (int, bool) {
	for i, h := range hay {
		if h == needle {
			return i, true
		}
	}
	return 0, false
}

func trimCell(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:60] + "…"
}
