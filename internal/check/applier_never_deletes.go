// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// applier_never_deletes.go — разбор пакета применителя ролей на предмет
// удаления строки роли (приёмка
// `docs/engineering/acceptance/roles-come-as-data-not-migrations.md` §3.1,
// держатель Г3; сценарий MOD-RD-15).
//
// Порт с монорепо (`internal/repohygiene/applierneverdeletes.go`, снят
// вынесением службы — `kacho#2597`). Осталось дословно: имя функции гейта
// (`TestMODRD15ApplierNeverDeletesARoleRow`), сам разбор (обе оси, оба
// образца) и текст находки. Изменилось: пакет-цель — `internal/apps/kaname/moduleroles`
// (в монорепо — `services/iam/internal/apps/kaname/moduleroles`), путь-константа
// без префикса `services/iam/`.
//
// # Предмет
//
// Роль с выдачами удалить нельзя (`ON DELETE RESTRICT`) — применитель встал бы
// на первой же роли, которой кто-то пользуется. Форма отзыва роли выбрана
// решением: строка ПОМЕЧАЕТСЯ снятой, а не удаляется
// (`docs/engineering/architecture/role-withdrawal-is-a-mark.md`).
//
// # Что здесь считается находкой — ДВЕ оси, и первая сильнее
//
//  1. порт применителя объявляет ОДНОЗНАЧНО удаляющий глагол НАД СТРОКОЙ РОЛИ
//     (судит имена методов интерфейса: глагол + предмет глагола);
//  2. в пакете стоит оператор `DELETE` над таблицей ролей строковым литералом
//     узла разбора, а не подстрокой текста.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
// Запрос, собранный из кусков в рантайме, и запрос, приехавший параметром —
// первое не встречается в дереве, второе ловит первая ось: чтобы позвать чужое
// удаление, порт обязан его объявить.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// ApplierDeleteSite — координата находки.
type ApplierDeleteSite struct {
	File string
	Line int
	// Kind — ось: `port-verb` либо `sql-literal`.
	Kind string
	// What — что именно найдено: имя метода либо начало литерала.
	What string
}

// ApplierDeleteCensus — объём осмотренного одним файлом.
type ApplierDeleteCensus struct {
	InterfaceMethods int
	StringLiterals   int
	Comments         int
}

// applierDeleteVerbRe — имена методов, ОДНОЗНАЧНО означающие удаление.
//
// `Retire` здесь НЕТ намеренно: в этом дереве отзыв роли модуля выбрал форму
// ПОМЕТКИ (`RetireRole` — `UPDATE`), и слово `retire` двузначно на всём
// остальном дереве (три таблицы каталога несут `retired_at` под пометку, а
// десять миграций `_retire*` действительно удаляют строки — но не строку
// РОЛИ). Судит существительное-предмет, а не глагол «retire».
var applierDeleteVerbRe = regexp.MustCompile(`^(Delete|Remove|Drop|Purge)`)

// applierRoleRowNoun — ЕДИНСТВЕННОЕ объявление ПРЕДМЕТА обеих осей: строка
// роли. Ось 2 выводит из него имя таблицы (`roles`), ось 1 — существительное
// метода (`Role`/`Roles`).
const applierRoleRowNoun = "role"

// applierRoleRowSubjectRe — существительное, называющее СТРОКУ РОЛИ (камельным
// словом, а не подстрокой: `RoleVerbs` несёт корень `Role`, но это проекция,
// её снятие законно).
var applierRoleRowSubjectRe = regexp.MustCompile(
	`(?:^|[a-z0-9])` + strings.ToUpper(applierRoleRowNoun[:1]) + applierRoleRowNoun[1:] + `s?$`)

// ApplierPortVerbDeletesTheRoleRow — предикат оси 1: удаляет ли метод порта
// СТРОКУ РОЛИ. Второе значение — почему, дословно для текста находки.
func ApplierPortVerbDeletesTheRoleRow(name string) (bool, string) {
	loc := applierDeleteVerbRe.FindStringIndex(name)
	if loc == nil {
		return false, ""
	}
	subject := name[loc[1]:]
	if subject == "" {
		return true, "предмет не назван"
	}
	if applierRoleRowSubjectRe.MatchString(subject) {
		return true, "предмет — строка роли"
	}
	return false, ""
}

// applierDeleteSQLRe — оператор удаления над таблицей ролей в строковом
// литерале, привязанный к НАЧАЛУ строки (возможно, после отступа/CTE): проза
// об этом же запрете несёт то же слово ПОСРЕДИ предложения, и образец без
// привязки краснел бы на собственном объяснении.
var applierDeleteSQLRe = regexp.MustCompile(
	`(?im)^\s*(with\b[^\n]*\n\s*)?delete\s+from\s+(kaname\.)?` + applierRoleRowNoun + `s\b`)

// ScanApplierDeletes разбирает один файл пакета применителя.
func ScanApplierDeletes(path string, src []byte) (sites []ApplierDeleteSite, census ApplierDeleteCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
	if perr != nil {
		return nil, ApplierDeleteCensus{}, perr
	}
	for _, g := range f.Comments {
		census.Comments += len(g.List)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.InterfaceType:
			if v.Methods == nil {
				return true
			}
			for _, m := range v.Methods.List {
				for _, name := range m.Names {
					census.InterfaceMethods++
					if hit, why := ApplierPortVerbDeletesTheRoleRow(name.Name); hit {
						sites = append(sites, ApplierDeleteSite{
							File: path, Line: fset.Position(name.Pos()).Line,
							Kind: "port-verb", What: name.Name + " (" + why + ")",
						})
					}
				}
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			census.StringLiterals++
			if applierDeleteSQLRe.MatchString(applierLitText(v.Value)) {
				sites = append(sites, ApplierDeleteSite{
					File: path, Line: fset.Position(v.Pos()).Line,
					Kind: "sql-literal", What: applierFirstLineOf(v.Value),
				})
			}
		}
		return true
	})
	return sites, census, nil
}

// applierLitText — содержимое литерала БЕЗ кавычек. Обязательно: образец
// привязан к началу строки, а `v.Value` несёт открывающую кавычку.
func applierLitText(v string) string {
	if u, err := strconv.Unquote(v); err == nil {
		return u
	}
	return strings.Trim(v, "`\"")
}

// applierFirstLineOf — начало литерала для текста находки.
func applierFirstLineOf(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "`\""))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return strings.TrimSpace(s)
}
