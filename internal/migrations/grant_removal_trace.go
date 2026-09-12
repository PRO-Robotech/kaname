// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// grant_removal_trace.go — миграция, СНИМАЮЩАЯ выдачи, обязана оставить след
// той формы, которую платформа для этого завела; и ни одна миграция не
// переносит выдачу с одной роли на другую.
//
// Порт с монорепо (`internal/repohygiene/grantremovaltrace.go`, снят вынесением
// службы — `kacho#2597`; приёмка `seed-identity-names-its-own-service.md` §6
// уже называла держателем `TestNoMigrationMovesGrantsBetweenRoles`, а он не
// существовал ни в одном файле — только в комментариях).
//
// # Предмет
//
// Строка `kaname.access_bindings` — это доступ, выданный арендатору. Миграция,
// удаляющая её, доступ ОТБИРАЕТ; и если рядом нет записи в журнал жизненного
// цикла выдачи, у которого есть читатель, то «отобрано» становится неотличимо
// от «никогда не выдавалось». Арендатор видит отсутствие права и не может
// узнать ни что оно было, ни когда исчезло, ни почему.
//
// # Замер на дне переезда (эта ревизия, `internal/migrations`)
//
// Корпус — 10 файлов. Ровно один называет таблицу выдач ОПЕРАТОРОМ удаления
// (`20260909202745_module_identities_leave_the_baseline.sql`), и он несёт
// след — вставку в `kaname.audit_outbox` — ДО удаления, в той же накатной
// половине. Храповик заведён нулём и это подтверждено переписью гейта, а не
// предположено: см. `TestMigrationRemovingGrantsLeavesATrace`.
//
// # Почему ХРАПОВИК, а не ведомость имён
//
// Применённую миграцию не правят (запрет #5) — значит найденную без следа
// придётся либо простить, либо держать ствол красным за прошлое. Ведомость
// имён растёт молча, и её никто не сверяет; число сверяется одним обходом и
// меняется только сознательно. Перечень имён при этом ПЕЧАТАЕТСЯ каждым
// прогоном — прощение остаётся видимым.
//
// Храповик ДВУСТОРОННИЙ: находка приходит и на следующей миграции без следа, и
// на уменьшении числа прощённых. Односторонний потолок не истекает никогда и
// потому механизмом не является.
//
// # Почему снятие выдач У СУБЪЕКТА входит в класс
//
// Норма — про ОТОБРАННЫЙ ДОСТУП, а не про снятую роль: строки выдач исчезают
// одинаково, а служебная учётка — такой же первоклассный принципал, как
// человек.
//
// # Граница, названная честно
//
// Гейт судит НАКАТНУЮ половину: `DELETE` в откатной половине снимает СВОЮ ЖЕ
// вставку, откатываясь, и доступа не отбирает. Он не судит, ВЕРЕН ли текст
// оставленного следа и доедет ли он до читателя, — только что запись есть. И
// он ничего не говорит о выдачах, снятых прод-кодом: у того путь свой и свой
// журнал.
package migrations

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// GrantRemovalRatchet — сколько миграций корпуса СЕГОДНЯ снимают выдачи без
// следа. Число, а не перечень: см. шапку файла. Отклонение в любую сторону —
// находка.
const GrantRemovalRatchet = 0

// Распознаватели намеренно ТЕРПИМЫ к написанию: SQL нечувствителен к регистру
// ключевых слов и допускает произвольные пробелы между лексемами, а предикат,
// узнающий одну запись из многих законных, МОЛЧИТ на остальных — и молчание
// читается как факт о дереве.
var (
	reGrantDelete = regexp.MustCompile(`(?i)delete\s+from\s+kaname\s*\.\s*access_bindings`)
	reGrantTrace  = regexp.MustCompile(`(?i)insert\s+into\s+kaname\s*\.\s*audit_outbox`)
	// reGrantTableNamed — таблица выдач, названная ЛЮБЫМ глаголом.
	reGrantTableNamed = regexp.MustCompile(`(?i)\bkaname\s*\.\s*access_bindings\b`)
)

// GrantRemovalCensus — объём осмотренного. Три величины, а не одна: «ноль
// находок» обязано быть отличимо от «ноль прочитанного», а «ноль в накатной
// половине» — от «распознаватель перестал узнавать удаление вовсе».
type GrantRemovalCensus struct {
	FilesRead  int
	WithDelete int // удаление выдач где угодно в файле
	InUpHalf   int // из них — в накатной половине
}

// GrantMigrationSource — один файл корпуса: имя для находки и текст для
// разбора.
type GrantMigrationSource struct {
	Name string
	Body string
}

// AuditGrantRemovalTrace — ядро гейта. Возвращает имена миграций, снимающих
// выдачи без следа, и перепись.
func AuditGrantRemovalTrace(corpus []GrantMigrationSource) (silent []string, c GrantRemovalCensus) {
	for _, m := range corpus {
		c.FilesRead++
		// Литералы забеливаются ВМЕСТЕ с комментариями: прозаическое сообщение
		// об отказе, называющее оператор, для поиска по образцу неотличимо от
		// самого оператора.
		whole := SQLBlankStrings(SQLBlankComments(m.Body))
		if !reGrantDelete.MatchString(whole) {
			continue
		}
		c.WithDelete++
		up := SQLBlankStrings(MigrationUpSection(m.Body))
		if !reGrantDelete.MatchString(up) {
			continue
		}
		c.InUpHalf++
		if reGrantTrace.MatchString(up) {
			continue
		}
		silent = append(silent, m.Name)
	}
	sort.Strings(silent)
	return silent, c
}

// GrantTableMentions — сколько операторов корпуса называют таблицу выдач
// ЛЮБЫМ глаголом. Общая предпосылка обоих гейтов файла: ноль означает, что
// корпус не прочитан либо таблица выдач из него исчезла.
func GrantTableMentions(corpus []GrantMigrationSource) int {
	n := 0
	for _, m := range corpus {
		body := SQLBlankStrings(SQLBlankComments(m.Body))
		n += len(reGrantTableNamed.FindAllStringIndex(body, -1))
	}
	return n
}

// ReadMigrationCorpus — корпус миграций, состав берётся у вызывающего (индекс
// git либо `embed.FS`), а не с диска напрямую.
func ReadMigrationCorpus(paths []string, read func(string) ([]byte, error)) ([]GrantMigrationSource, error) {
	out := make([]GrantMigrationSource, 0, len(paths))
	for _, p := range paths {
		body, err := read(p)
		if err != nil {
			return nil, err
		}
		out = append(out, GrantMigrationSource{Name: filepath.Base(p), Body: string(body)})
	}
	return out, nil
}

// GrantRemovalFinding — текст находки. Отдельной функцией, чтобы обе стороны
// храповика (перебор и недобор) говорили ОДНИМ голосом и назывались вместе с
// перечнем.
func GrantRemovalFinding(got int, names []string) string {
	var b strings.Builder
	switch {
	case got > GrantRemovalRatchet:
		b.WriteString("миграций, снимающих выдачи БЕЗ следа, стало больше: ")
	default:
		b.WriteString("миграций, снимающих выдачи без следа, стало меньше: ")
	}
	b.WriteString("было ")
	b.WriteString(strconv.Itoa(GrantRemovalRatchet))
	b.WriteString(", стало ")
	b.WriteString(strconv.Itoa(got))
	b.WriteString(". Перечень: ")
	b.WriteString(strings.Join(names, ", "))
	if got > GrantRemovalRatchet {
		b.WriteString(". Миграция, удаляющая строки kaname.access_bindings в накатной " +
			"половине, ОТБИРАЕТ у арендатора доступ; без записи в kaname.audit_outbox " +
			"«отобрано» неотличимо от «никогда не выдавалось». Оставь след в той же " +
			"половине — либо, если удаление снимает собственную вставку той же миграции, " +
			"перенеси его в откатную половину")
	} else {
		b.WriteString(". Уменьшение — это ХОРОШО, и потому оно тоже находка: храповик " +
			"обязан двигаться СОЗНАТЕЛЬНО. Опусти GrantRemovalRatchet до нового числа " +
			"тем же изменением, которым закрыл прощённое, — иначе прощение переживёт " +
			"свой предмет")
	}
	return b.String()
}

// ── ПЕРЕНОС ВЫДАЧИ МЕЖДУ РОЛЯМИ ──────────────────────────────────────────────
//
// Приёмка службы отвергла исход «перенести выдачи на роли-преемники» как ТИХОЕ
// расширение прав: выдача на снятую роль дала бы доступ к ресурсу, которого
// выдававший не называл, а согласия у него никто не спрашивал. Решение обязано
// быть ИСПОЛНЕНО, а не только объявлено, — иначе оно живёт ровно до первой
// миграции, которая «просто перевесит» выдачи.

// reGrantUpdateHead — начало оператора, переставляющего поля выдачи.
//
// Разбор идёт по ПРИСВАИВАНИЯМ, а не по всему оператору: `role_id` стоит в
// условии отбора у КАЖДОГО оператора мягкого отзыва, и предикат по всему
// тексту объявил бы переносом дедупликацию выдач.
var (
	reGrantUpdateHead = regexp.MustCompile(`(?i)update\s+(?:kaname\s*\.\s*)?access_bindings\b\s+set\b`)
	reGrantAssignRole = regexp.MustCompile(`(?i)\brole_id\s*=`)
	reGrantWhereOrEnd = regexp.MustCompile(`(?i)\bwhere\b|;`)
)

// AuditGrantRoleReassignment — миграции, переставляющие выдачу с одной роли на
// другую, и число осмотренных операторов.
//
// Второе число обязательно: ноль переносов при нуле прочитанных операторов
// означает «распознаватель ослеп», а не «переносов нет».
func AuditGrantRoleReassignment(corpus []GrantMigrationSource) (moves []string, statements int) {
	for _, m := range corpus {
		up := SQLBlankStrings(MigrationUpSection(m.Body))
		for _, loc := range reGrantUpdateHead.FindAllStringIndex(up, -1) {
			statements++
			rest := up[loc[1]:]
			stop := len(rest)
			if g := reGrantWhereOrEnd.FindStringIndex(rest); g != nil {
				stop = g[0]
			}
			if reGrantAssignRole.MatchString(rest[:stop]) {
				moves = append(moves, m.Name)
				break
			}
		}
	}
	sort.Strings(moves)
	return moves, statements
}
