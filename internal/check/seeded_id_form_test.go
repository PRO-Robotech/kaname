// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	migrationsapp "github.com/PRO-Robotech/kaname/internal/migrations"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Идентификатор, ПОСЕЯННЫЙ миграцией, обязан проходить проверку формы, которую
// сервис ставит первым стейтментом каждого глагола. Гейт задачи kacho#1808.
//
// # ЧТО СЛУЧИЛОСЬ БЕЗ НЕГО
//
// Свод посеял системную роль `system.viewer` идентификатором длиной 21 при
// требуемых 20 — и роль была недостижима по id НИ ОДНИМ путём: `Get`,
// `GetRoleCompiled`, `Update`, `Delete`, `ListAccessBindingsByRole` отвергали её
// `INVALID_ARGUMENT` ещё до чтения. Арендатор получал роль в ответе `List` и не
// мог её прочитать. Соседняя роль `system.admin` (длина 20, буква тела вне
// алфавита фундамента) вела себя иначе, и различие НИКЕМ НЕ РЕШАЛОСЬ.
//
// # СУДИТСЯ ИДЕНТИФИКАТОР, ОСТАВЛЕННЫЙ КОРПУСОМ В СИЛЕ (kaname#543)
//
// Применённая миграция не правится (ban #5), поэтому негодная вставка остаётся в
// корпусе навсегда, а годным id её делает ПОЗДНЯЯ миграция, переводящая строку
// оператором `UPDATE <таблица> SET id = '<новый>' WHERE id = '<прежний>'` в
// верхней половине. Гейт сворачивает такие переводы по ключу «таблица,
// литерал» в порядке корпуса и судит то, что осталось в силе; число свёрнутых
// переводов печатается. Без свёртки гейт краснел бы на исправленном посеве, и
// выход из красного у него был бы один — снова перечень прощённого.
//
// # СУДЬЯ ДВУХОСНЫЙ: ПУТЬ ЗАПРОСА И ФУНДАМЕНТ
//
// Проверка пути запроса судит префикс и ДЛИНУ, но не алфавит тела: id длины 20 с
// буквой вне алфавита ею принимается — ровно класс системной роли `system.admin`.
// Поэтому слитную форму судят ОБЕ: `shared.ValidateResourceID` (путь запроса
// служба отвергать не должна) и `ids.HasKnownPrefix` фундамента — тот судья,
// которым край kacho проверяет строгую форму id (`kacho#2976`).
//
// # ПОЧЕМУ ГЕЙТ СУДИТ ФОРМОЙ ИЗ ТАБЛИЦЫ, А НЕ СВОИМ ПРАВИЛОМ
//
// Форм у идентификаторов iam ТРИ (слитная, через подчёркивание, через дефис), и
// какая кому положена, объявляет ЕДИНСТВЕННАЯ таблица `mintedPrefixes`
// (`contract_id_form_test.go`), чьи строки доказаны ИСПОЛНЕНИЕМ генератора.
// Своё правило здесь было бы вторым местом об одном предмете: `cag_…` длиной 21
// — законная форма, и гейт с правилом «ровно 20» краснел бы на исправном
// посеве.
//
// Слитную форму судит НАСТОЯЩАЯ `shared.ValidateResourceID` — та же функция, что
// стоит на пути запроса. Копия её условия разошлась бы с ней молча.
//
// # ЧТО ГЕЙТ НЕ СУДИТ
//
// Литерал, чей первый сегмент не назван ни одной строкой таблицы
// (`cluster_root`, внешние субъекты входа, идентификаторы чужих доменов),
// — не идентификатор ресурса iam, и форма его этой таблицей не задана. Такие
// значения считаются отдельной величиной переписи, а не находкой.
//
// Многострочные вставки (`INSERT … SELECT`) разбором не берутся и тоже
// СЧИТАЮТСЯ: «ноль находок» обязано быть отличимо от «ноль разобранного».
//
// # ПОЧЕМУ ВЕДОМОСТЬ ПУСТА
//
// Она несла ОДНУ запись — живой дефект kacho#1808: роль `kacho-system.viewer`
// посеяна идентификатором длиной 21 и была недостижима по id ни одним глаголом.
// Сначала запись сменил закрытый перечень посеянного в проверке пути запроса
// (kacho#1808), затем kaname#543 перевела обе системные роли на каноническую
// форму поздней миграцией и сняла перечень: в силе остаются только годные id,
// и прощать нечего ни ведомостью, ни перечнем.
//
// Пустая ведомость — ЦЕЛЬ гейта, поэтому пробой она не считается: проверка не
// имеет права падать на достижении собственной цели.
//
// Ведомость САМОИСТЕКАЕТ: запись, чьего литерала в названном файле больше нет
// либо чей посев больше не негоден, — находка. Без самоистечения она пережила бы
// предмет и стала бы слепой зоной для следующего негодного посева.

const iamMigrationsDir = "services/iam/internal/migrations"

// reSingleLineInsert — вставка, записанная одной строкой: имя таблицы, список
// колонок, список значений. Все посевы этого дерева записаны так.
var reSingleLineInsert = regexp.MustCompile(
	`(?m)^INSERT INTO\s+([\w.]+)\s*\(([^)]*)\)\s*VALUES\s*\((.*)\);\s*$`)

// reMultiLineInsert — вставка, которую разбор НЕ берёт. Считается, а не молчит.
var reMultiLineInsert = regexp.MustCompile(`(?m)^INSERT INTO\s+[\w.]+`)

// seededSeedException — прощённая пара «файл посева ↔ литерал».
type seededSeedException struct {
	file    string
	literal string
	reason  string
}

// seededIDLedger — прощённые посевы. ПУСТА, и это ЦЕЛЬ, а не недосмотр.
//
// Единственная запись жила здесь, пока исход kacho#1808 не был выбран; посев,
// который она прощала, переведён в форму поздней миграцией (kaname#543), и гейт
// судит id в силе. Ведомость самоистекает (проба `TestSeededIDLedgerSelfExpires`
// это и утверждает): запись, которой нечего прощать, — находка.
func seededIDLedger() []seededSeedException { return nil }

// seededIDCensus — объём осмотренного.
type seededIDCensus struct {
	filesRead     int // файлов миграций прочитано
	insertsSeen   int // вставок встречено
	insertsParsed int // из них разобрано
	idValues      int // значений колонки `id` извлечено
	judged        int // из них судимы таблицей форм
	unknownFamily int // первый сегмент не назван таблицей — не наш идентификатор
	renamesSeen   int // переводов id в верхних половинах корпуса
	renamesFolded int // из них свёрнуто в посев: id в силе отличен от вставленного
	ledgerEntries int // записей ведомости
	ledgerApplied int // записей, которым было что прощать
}

// reSeedRename — перевод строки на другой id: `UPDATE <таблица> SET id = '<новый>'
// WHERE id = '<прежний>'`. Судится только ВЕРХНЯЯ половина миграции: нижняя
// возвращает прежнее состояние и о том, что в силе, не говорит.
var reSeedRename = regexp.MustCompile(
	`(?i)\bUPDATE\s+([\w.]+)\s+SET\s+id\s*=\s*'([^']*)'\s+WHERE\s+id\s*=\s*'([^']*)'`)

// seedRename — один перевод корпуса: файл, таблица, прежний и новый id.
type seedRename struct {
	file, table, from, to string
}

// seedRenames — переводы id в верхних половинах корпуса, в порядке корпуса.
func seedRenames(names []string, migrations map[string]string) []seedRename {
	var out []seedRename
	for _, name := range names {
		for _, m := range reSeedRename.FindAllStringSubmatch(migrationsapp.MigrationUpSection(migrations[name]), -1) {
			out = append(out, seedRename{file: name, table: strings.ToLower(m[1]), from: m[3], to: m[2]})
		}
	}
	return out
}

// idInForce — id, который корпус оставляет в силе за вставкой `lit` в таблицу
// `table` из файла `file`: переводы ПОЗЖЕ файла вставки применяются по порядку.
func idInForce(renames []seedRename, file, table, lit string) string {
	cur := lit
	for _, r := range renames {
		if r.file > file && r.table == strings.ToLower(table) && r.from == cur {
			cur = r.to
		}
	}
	return cur
}

// splitSQLValues делит список значений по запятым ВЕРХНЕГО уровня, уважая
// одинарные кавычки (удвоение внутри — экранирование) и вложенные скобки.
func splitSQLValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, depth := false, 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case inQuote && ch == '\'' && i+1 < len(s) && s[i+1] == '\'':
			cur.WriteByte(ch)
			cur.WriteByte(s[i+1])
			i++
			continue
		case ch == '\'':
			inQuote = !inQuote
		case !inQuote && ch == '(':
			depth++
		case !inQuote && ch == ')':
			depth--
		case !inQuote && depth == 0 && ch == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	out = append(out, strings.TrimSpace(cur.String()))
	return out
}

// formOfPrefix ищет строку таблицы форм, чьей формой записан литерал.
// Возвращает false, когда семейство литерала таблицей не названо.
func formOfPrefix(lit string) (mintedPrefix, bool) {
	best, found := mintedPrefix{}, false
	for _, m := range mintedPrefixes {
		want := m.prefix + m.form.separator()
		if !strings.HasPrefix(lit, want) {
			continue
		}
		if !found || len(m.prefix) > len(best.prefix) {
			best, found = m, true
		}
	}
	return best, found
}

// auditSeededIDs — чистое ядро обеих проб: решает по текстам миграций.
func auditSeededIDs(migrations map[string]string, ledger []seededSeedException) ([]string, seededIDCensus) {
	var findings []string
	c := seededIDCensus{filesRead: len(migrations), ledgerEntries: len(ledger)}
	forgiven := map[string]bool{}

	names := make([]string, 0, len(migrations))
	for n := range migrations {
		names = append(names, n)
	}
	sort.Strings(names)
	renames := seedRenames(names, migrations)
	c.renamesSeen = len(renames)

	for _, name := range names {
		body := migrations[name]
		c.insertsSeen += len(reMultiLineInsert.FindAllString(body, -1))

		for _, m := range reSingleLineInsert.FindAllStringSubmatch(body, -1) {
			c.insertsParsed++
			cols := strings.Split(m[2], ",")
			vals := splitSQLValues(m[3])
			if len(cols) != len(vals) {
				continue
			}
			for i, col := range cols {
				if strings.TrimSpace(col) != "id" {
					continue
				}
				raw := vals[i]
				if len(raw) < 2 || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
					continue // выражение, а не литерал: форму задаёт SQL, не посев
				}
				lit := strings.ReplaceAll(raw[1:len(raw)-1], "''", "'")
				c.idValues++

				live := idInForce(renames, name, m[1], lit)
				form, known := formOfPrefix(live)
				if !known {
					c.unknownFamily++
					continue
				}
				c.judged++
				if live != lit {
					c.renamesFolded++
				}
				bad := judgeMintedForm(live, form)
				if bad != "" {
					if idx := ledgerIndex(ledger, name, lit); idx >= 0 {
						forgiven[ledgerKey(name, lit)] = true
						continue
					}
					inForce := ""
					if live != lit {
						inForce = fmt.Sprintf(" (в силе после переводов корпуса — %q)", live)
					}
					findings = append(findings, fmt.Sprintf(
						"%s: %s посеян идентификатор %q%s — %s. Проверка формы стоит ПЕРВЫМ "+
							"стейтментом каждого глагола, а край судит id формой фундамента, "+
							"поэтому такой ресурс недостижим по id",
						name, m[1], lit, inForce, bad))
				}
			}
		}
	}

	for _, e := range ledger {
		if forgiven[ledgerKey(e.file, e.literal)] {
			c.ledgerApplied++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"ВЕДОМОСТИ НЕЧЕГО ПРОЩАТЬ: запись про %s / %q (%s) пережила свой предмет — "+
				"негодного посева там больше нет, запись снимается",
			e.file, e.literal, e.reason))
	}
	return findings, c
}

func ledgerKey(file, literal string) string { return file + "\x00" + literal }

func ledgerIndex(ledger []seededSeedException, file, literal string) int {
	for i, e := range ledger {
		if e.file == file && e.literal == literal {
			return i
		}
	}
	return -1
}

// judgeMintedForm судит литерал формой его префикса. Слитную — НАСТОЯЩЕЙ
// функцией пути запроса и судьёй фундамента `ids.HasKnownPrefix` (первая не
// знает алфавита тела); разделительные — длиной и разделителем той же формы,
// что доказана исполнением генератора в соседней пробе.
func judgeMintedForm(lit string, m mintedPrefix) string {
	if m.form == mintConcatenated {
		if err := shared.ValidateResourceID(lit, m.prefix, "resource"); err != nil {
			return "он не проходит shared.ValidateResourceID: " + err.Error()
		}
		if !ids.HasKnownPrefix(lit) {
			return "он не проходит ids.HasKnownPrefix фундамента: префикс вне каталога " +
				"либо знак тела вне алфавита"
		}
		return ""
	}
	want := len(m.prefix) + len(m.form.separator()) + kac127BodyLen
	if len(lit) != want {
		return fmt.Sprintf("длина %d, а форма префикса %q требует %d",
			len(lit), m.prefix, want)
	}
	return ""
}

// kac127BodyLen — длина тела идентификатора у всех трёх форм.
const kac127BodyLen = 17

// TestSeededResourceIDsPassTheServiceOwnFormCheck — несущее утверждение.
func TestSeededResourceIDsPassTheServiceOwnFormCheck(t *testing.T) {
	paths, err := treecorpus.UnderWithSuffix(platformtree.RequirePath(t, iamMigrationsDir), ".sql")
	require.NoError(t, err)

	migrations := map[string]string{}
	for _, p := range paths {
		raw, readErr := os.ReadFile(p) // #nosec G304 -- путь пришёл из индекса git каталога миграций
		require.NoError(t, readErr)
		migrations[p[strings.LastIndex(p, "/")+1:]] = string(raw)
	}

	findings, c := auditSeededIDs(migrations, seededIDLedger())

	t.Logf("перепись: файлов миграций %d · вставок встречено %d (разобрано %d) · "+
		"значений колонки id %d · судимо таблицей форм %d · семейство не названо %d · "+
		"переводов id в корпусе %d (свёрнуто в посев %d) · "+
		"записей ведомости %d (применено %d) · находок %d",
		c.filesRead, c.insertsSeen, c.insertsParsed, c.idValues, c.judged, c.unknownFamily,
		c.renamesSeen, c.renamesFolded, c.ledgerEntries, c.ledgerApplied, len(findings))

	require.NotZerof(t, c.filesRead, "обход миграций пуст — вердикт беспредметен (%s)", iamMigrationsDir)
	require.NotZerof(t, c.judged,
		"ни один посеянный идентификатор не был судим таблицей форм — отрицание стало "+
			"вакуумным: либо посевы сменили запись, либо разбор её больше не узнаёт")

	require.Emptyf(t, findings,
		"посеянный идентификатор не проходит собственную проверку формы сервиса:\n%s",
		strings.Join(findings, "\n"))
}
