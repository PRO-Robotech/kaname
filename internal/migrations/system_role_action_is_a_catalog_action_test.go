// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// system_role_action_is_a_catalog_action_test.go — ДЕЙСТВИЕ строки прав
// системной роли обязано существовать в каталоге прав (задача продукта #1827).
//
// # Что неверно без этого гейта
//
// Строка прав — объявление роли, наблюдаемое арендатором. Край резолвит
// действие в отношение ПО КАТАЛОГУ ПРАВ; действие, которого каталог не несёт,
// не спрашивается на пути запроса никогда. Роль, где такое действие осталось бы
// единственным, не дала бы ничего — при том что её имя обещает право. Это
// «принято-и-проигнорировано» (`api-conventions.md`) на уровне посева.
//
// # Почему судится СВОД цепочки, а не текст каждой миграции
//
// Применённую миграцию править нельзя (ban #5), поэтому негодная строка снимается
// НОВОЙ миграцией. Гейт, судящий текст файлов по отдельности, остался бы красным
// навсегда: базовая миграция несёт исходный литерал и после снятия. Судится
// поэтому СОСТОЯНИЕ, к которому цепочка приводит: присвоения складываются в
// порядке применения, побеждает последнее.
//
// # Формы записи названы, и незнакомая — НАХОДКА, а не молчание
//
// Распознаватель знает две формы присвоения (вставка строки роли и присвоение
// массива прав правкой), и обе объявлены ниже. Форма, о которой он не знает, не
// даёт ни красного, ни зелёного — она даёт МОЛЧАНИЕ, и предмет уходит из-под
// наблюдения, ничего не нарушив (`testing.md` §«Гейт на класс» п. 7). Поэтому
// оператор вставки либо правки, называющий таблицу ролей и столбец прав и НЕ
// разобранный ни одной из двух форм, объявляется находкой прямо.
//
// # Источник действий — та же встроенная копия каталога, которую грузит сервис
//
// Второй перечень действий здесь не заводится: он разошёлся бы с каталогом
// молча. Читается ровно то, что `seed.LoadPermissionRegistry` грузит в бою.

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// reRoleInsert — ПЕРВАЯ законная форма присвоения: вставка строки роли.
var reRoleInsert = regexp.MustCompile(
	`(?is)^INSERT\s+INTO\s+kaname\.roles\s*\(([^)]*)\)\s*VALUES\s*\((.*)\)$`)

// reRolePermsUpdate — ВТОРАЯ законная форма: присвоение массива прав правкой
// одной строки. Массив пишется литералом намеренно: свод цепочки обязан быть
// вычислим ЧТЕНИЕМ, а выражение над jsonb пришлось бы исполнять.
var reRolePermsUpdate = regexp.MustCompile(
	`(?is)^UPDATE\s+kaname\.roles\s+SET\s+permissions\s*=\s*'(\[.*?\])'\s*::\s*jsonb\s+WHERE\s+id\s*=\s*'([^']+)'$`)

// reLineComment — построчный комментарий SQL. Снимается ОБЯЗАТЕЛЬНО: без этого
// разбор считает собственное объяснение предмета за предмет.
var reLineComment = regexp.MustCompile(`--.*`)

// roleAssignment — последнее присвоение прав одной роли и файл, который его дал.
type roleAssignment struct {
	file  string
	perms []string
}

// foldRolePermissions складывает цепочку миграций в состояние «роль → права».
//
// ordered — имена файлов В ПОРЯДКЕ ПРИМЕНЕНИЯ. Возвращает состояние, перечень
// неразобранных операторов (находки формы) и объём осмотренного.
func foldRolePermissions(ordered []string, bodies map[string]string) (
	state map[string]roleAssignment, unknownForms []string, stmtsTouched int,
) {
	state = map[string]roleAssignment{}
	for _, name := range ordered {
		code := reLineComment.ReplaceAllString(upSection(bodies[name]), "")
		for _, raw := range strings.Split(code, ";") {
			stmt := strings.TrimSpace(reSpaceRun.ReplaceAllString(raw, " "))
			if stmt == "" || !strings.Contains(stmt, "kaname.roles") ||
				!strings.Contains(stmt, "permissions") {
				continue
			}
			verb := strings.ToUpper(strings.Fields(stmt)[0])
			if verb != "INSERT" && verb != "UPDATE" {
				continue // объявление таблицы, комментарий столбца, индекс — не присвоение
			}
			stmtsTouched++
			if m := reRoleInsert.FindStringSubmatch(stmt); m != nil {
				id, perms, ok := rolePermsOfInsert(m[1], m[2])
				if ok {
					state[id] = roleAssignment{file: name, perms: perms}
					continue
				}
			}
			if m := reRolePermsUpdate.FindStringSubmatch(stmt); m != nil {
				var perms []string
				if json.Unmarshal([]byte(m[1]), &perms) == nil {
					state[m[2]] = roleAssignment{file: name, perms: perms}
					continue
				}
			}
			unknownForms = append(unknownForms,
				name+": оператор пишет права роли формой, которой разбор не знает: "+head(stmt))
		}
	}
	return state, unknownForms, stmtsTouched
}

var reSpaceRun = regexp.MustCompile(`\s+`)

// upSection — ПРЯМОЙ ход миграции и только он.
//
// Обратный ход возвращает снятое, то есть несёт негодное присвоение НАМЕРЕННО.
// Читая файл целиком, свод взял бы его как последнее — и объявил бы починку
// несостоявшейся. Разрез делается ДО снятия комментариев: разделитель goose сам
// записан комментарием.
func upSection(body string) string {
	if i := strings.Index(body, "-- +goose Down"); i >= 0 {
		return body[:i]
	}
	return body
}

func head(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// rolePermsOfInsert достаёт идентификатор роли и её права из вставки.
func rolePermsOfInsert(colList, valList string) (id string, perms []string, ok bool) {
	cols := strings.Split(colList, ",")
	vals := splitSQLValues(valList)
	if len(cols) != len(vals) {
		return "", nil, false
	}
	byCol := map[string]string{}
	for i, c := range cols {
		byCol[strings.TrimSpace(c)] = strings.TrimSpace(vals[i])
	}
	rawID, okID := sqlStringLiteral(byCol["id"])
	rawPerms, okPerms := sqlStringLiteral(byCol["permissions"])
	if !okID || !okPerms {
		return "", nil, false
	}
	if json.Unmarshal([]byte(rawPerms), &perms) != nil {
		return "", nil, false
	}
	return rawID, perms, true
}

// splitSQLValues режет список значений по запятым ВНЕ строковых литералов.
func splitSQLValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '\'':
			if i+1 < len(s) && s[i+1] == '\'' {
				cur.WriteString("''")
				i++
				continue
			}
			inQuote = false
			cur.WriteByte(c)
		case !inQuote && c == '\'':
			inQuote = true
			cur.WriteByte(c)
		case !inQuote && c == ',':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

func sqlStringLiteral(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
		return "", false
	}
	return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), true
}

// actionFindings — судья: действие каждой строки прав обязано быть действием
// каталога либо подстановкой.
func actionFindings(state map[string]roleAssignment, actions map[string]bool) []string {
	var out []string
	ids := make([]string, 0, len(state))
	for id := range state {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := state[id]
		for _, p := range a.perms {
			segs := strings.Split(p, ".")
			act := segs[len(segs)-1]
			if act == "*" || actions[act] {
				continue
			}
			out = append(out, a.file+": роль "+id+" — строка прав "+p+
				" называет действие "+act+
				", которого каталог прав не несёт: край не резолвит его в отношение, "+
				"и на пути запроса это право не спрашивается никогда")
		}
	}
	return out
}

// catalogActions — действия каталога прав из ТОЙ ЖЕ встроенной копии, которую
// грузит сервис.
func catalogActions(t *testing.T) map[string]bool {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err, "встроенный каталог прав не прочитан")
	out := map[string]bool{}
	for _, e := range reg.All() {
		if e.Permission == "" {
			continue
		}
		segs := strings.Split(e.Permission, ".")
		out[segs[len(segs)-1]] = true
	}
	return out
}

// TestSystemRolePermissionActionExistsInTheCatalog — свод цепочки не оставляет
// ни одной строки прав с действием вне каталога.
func TestSystemRolePermissionActionExistsInTheCatalog(t *testing.T) {
	bodies, read := iamMigrationCorpus(t)
	ordered := make([]string, 0, len(bodies))
	for name := range bodies {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered) // порядок применения goose = лексикографический порядок имён

	state, unknown, stmts := foldRolePermissions(ordered, bodies)
	actions := catalogActions(t)

	require.NotZerof(t, len(actions), "каталог прав не дал ни одного действия — "+
		"сверять было бы не с чем, и «ноль находок» означало бы «ноль прочитанного»")
	require.NotZerof(t, len(state), "в %d прочитанных миграциях не разобрано ни одного "+
		"присвоения прав роли — предпосылка гейта сломана", read)
	require.Emptyf(t, unknown, "форма присвоения прав, неизвестная разбору:\n%s",
		strings.Join(unknown, "\n"))

	findings := actionFindings(state, actions)
	require.Emptyf(t, findings, "строк прав с действием вне каталога — %d:\n%s",
		len(findings), strings.Join(findings, "\n"))

	distinct := map[string]bool{}
	for _, a := range state {
		for _, p := range a.perms {
			distinct[p] = true
		}
	}
	t.Logf("перепись: миграций прочитано %d, операторов о правах ролей %d, "+
		"ролей в своде %d, различных строк прав %d, действий каталога %d, находок 0",
		read, stmts, len(state), len(distinct), len(actions))
}
