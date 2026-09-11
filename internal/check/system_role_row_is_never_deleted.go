// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_role_row_is_never_deleted.go — разбор прод-кода kaname на предмет
// удаления строки СИСТЕМНОЙ роли (порт с монорепо
// `internal/repohygiene/systemrolerowisneverdeleted.go`, снят вынесением
// службы доступа — `kacho#2597`; решение
// `docs/engineering/architecture/role-withdrawal-is-a-mark.md`, задача
// продукта #1913).
//
// # Предмет
//
// Роль, объявленная манифестом модуля, системная BY CONSTRUCTION: применитель
// ставит `IsSystem: true`, а `roles.is_system` вычисляется из `cluster_id`.
// Значит вопрос «как снять роль модуля» есть вопрос «что делает прод-код со
// строкой системной роли», и у него два взаимоисключающих ответа: удалить
// строку либо пометить её снятой. Линия выбрала ВТОРОЙ:
//
//  1. **роль в работе не удалится вовсе.** Выдачи ссылаются на роль ключом
//     `access_bindings_role_fk … ON DELETE RESTRICT`; удаление роли, за которой
//     стоит хоть одна строка выдачи, отвергается `SQLSTATE 23503`;
//  2. **если бы не отвергалось — три проекции уехали бы МОЛЧА**: селекторы
//     правил, проекция глаголов и проекция объявленных сегментов;
//  3. **отзыв перестал бы достигать ПРЕДЪЯВЛЕНИЯ наблюдаемо.** У снятой
//     пометкой строки есть что читать на пути запроса; у удалённой читать
//     нечего.
//
// # Что здесь считается находкой — ОДНА ось, и она про оператор
//
// Оператор `DELETE` над таблицей `roles`, не сужённый на ПОЛЬЗОВАТЕЛЬСКУЮ
// роль. Сужение опознаётся в ДВУХ законных написаниях: `is_system = false`
// (и `NOT is_system`) — прямо по вычисляемой колонке; `cluster_id IS NULL` —
// по кластерному якорю, из которого она и вычисляется.
//
// Ось судит СТРОКОВЫЙ ЛИТЕРАЛ узла разбора, а не текст файла: слово `DELETE`
// стоит и в комментариях, объясняющих сам запрет. Оператор отличается от
// ПРОЗЫ, цитирующей оператор, по ПРОДОЛЖЕНИЮ за именем таблицы (`WHERE`,
// `RETURNING`, `USING`, `;`, конец литерала) — привязки к началу строки
// недостаточно.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь-константа
// (`iamGoPrefix = "services/iam/"` → обход всего дерева модуля без префикса,
// код лежит от корня). Осталось дословно: обе регулярки сужения и продолжения,
// форма распознавателя (`ScanRoleDeletes`), имя держателя
// `TestSystemRoleRowIsNeverDeleted`.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. **миграции.** Каждая снимала роль удалением до решения — это СТАТУС-КВО,
//     который решение и заменяет, а не находка сегодняшнего дерева;
//  2. **каскад по чужому ключу.** Строка роли уезжает вместе со своим ярусом
//     (аккаунт, проект). Для СИСТЕМНОЙ роли ярус — кластер;
//  3. **запрос, собранный из кусков в рантайме** либо приехавший параметром.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// RoleDeleteSite — координата находки.
type RoleDeleteSite struct {
	File string
	Line int
	What string
}

// RoleDeleteCensus — объём осмотренного одним файлом.
type RoleDeleteCensus struct {
	StringLiterals int
	Comments       int
	Statements     int
	Guarded        int
}

// roleDeleteStmtRe — оператор удаления над таблицей ролей.
var roleDeleteStmtRe = regexp.MustCompile(`(?im)^\s*(with\b[^\n]*\n\s*)?delete\s+from\s+(kaname\.)?roles\b`)

// roleDeleteTailRe — продолжение, по которому оператор отличается от прозы.
var roleDeleteTailRe = regexp.MustCompile(`(?is)^\s*($|;|--|\)|where\b|returning\b|using\b|as\b)`)

// roleDeleteGuardRe — сужение на пользовательскую роль в двух законных
// написаниях (`0056_role_definition_tier.sql`:
// `GENERATED ALWAYS AS (cluster_id IS NOT NULL)`).
var roleDeleteGuardRe = regexp.MustCompile(`(?i)(is_system\s*=\s*false|not\s+is_system\b|cluster_id\s+is\s+null)`)

// ScanRoleDeletes разбирает один файл Go.
func ScanRoleDeletes(path string, src []byte) (sites []RoleDeleteSite, census RoleDeleteCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
	if perr != nil {
		return nil, RoleDeleteCensus{}, perr
	}
	for _, g := range f.Comments {
		census.Comments += len(g.List)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		census.StringLiterals++
		text := roleDeleteLitText(lit.Value)
		stmts := 0
		for _, m := range roleDeleteStmtRe.FindAllStringIndex(text, -1) {
			if roleDeleteTailRe.MatchString(text[m[1]:]) {
				stmts++
			}
		}
		if stmts == 0 {
			return true
		}
		census.Statements += stmts
		if len(roleDeleteGuardRe.FindAllString(text, -1)) >= stmts {
			census.Guarded += stmts
			return true
		}
		sites = append(sites, RoleDeleteSite{
			File: path, Line: fset.Position(lit.Pos()).Line, What: roleDeleteFirstLineOf(lit.Value),
		})
		return true
	})
	return sites, census, nil
}

// roleDeleteLitText — содержимое литерала без кавычек.
func roleDeleteLitText(v string) string {
	if u, err := strconv.Unquote(v); err == nil {
		return u
	}
	return strings.Trim(v, "`\"")
}

// roleDeleteFirstLineOf — начало литерала для текста находки.
func roleDeleteFirstLineOf(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "`\""))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return strings.TrimSpace(s)
}
