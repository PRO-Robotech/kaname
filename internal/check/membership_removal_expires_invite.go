// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_removal_expires_invite.go — MAIL-46 приёмки ID-MAIL-1: глагол,
// снимающий участие, ОБЕСЦЕНИВАЕТ невыкупленное приглашение.
//
// # Предмет
//
// Строка приглашения ГЛОБАЛЬНА, членства — по аккаунту. Сняв членство и оставив
// строку ждущей выкупа, продукт оставляет приглашение действующим: первый вход
// человека переводит строку в состояние участника и со-коммитит указатель на
// ТОТ САМЫЙ аккаунт, из которого его исключили. Заметить это неоткуда — отказа
// нет, красного нет, человек просто оказывается там, где ему быть не положено.
//
// # Предикат судит ИСХОД, а не ИМЯ
//
// Требование приёмки сформулировано по исходу — «человек перестал быть
// участником», — поэтому и гейт ищет исход: оператор, СНИМАЮЩИЙ СТРОКУ
// ЧЛЕНСТВА, в каком бы глаголе он ни стоял. Новый глагол того же смысла
// попадает под гейт по построению, а переименование прежнего его не снимает —
// тогда как перечень имён разошёлся бы с деревом молча на первом же заведённом
// глаголе.
//
// # Что считается обесцениванием
//
// Запись СРОКА на строку приглашения (`invite_expires_at`) — то самое плечо,
// которое делает её невыкупаемой. Оно обязано стоять в ТОЙ ЖЕ функции: между
// двумя операторами, разнесёнными по функциям, появляется окно, в котором
// первый вход видит членств ноль и срок живым.
//
// # Чего гейт НЕ видит — названо прямо
//
// Снятие членства каскадом чужого ограничения либо триггером базы этим разбором
// не опознаётся: он читает код Go, а не схему. Граница закрыта с другой
// стороны — интеграционной пробой
// (`internal/repo/kaname/pg/invite_revoked_on_removal_integration_test.go`),
// которая судит ИСХОД на живой базе, чем бы членство ни снималось.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// membershipRowTable — таблица, строка которой и ЕСТЬ участие.
const membershipRowTable = "memberships"

// inviteDeadlineColumn — колонка, запись в которую обесценивает невыкупленное
// приглашение.
const inviteDeadlineColumn = "invite_expires_at"

// membershipDeleteRe — оператор, СНИМАЮЩИЙ строку участия. Привязан к началу
// строки (возможно, после отступа либо `WITH …`): проза об этом же предмете
// несёт те же слова посреди предложения, и образец без привязки краснел бы на
// собственном объяснении.
var membershipDeleteRe = regexp.MustCompile(
	`(?im)^\s*delete\s+from\s+(kaname\.)?` + membershipRowTable + `\b`)

// inviteDeadlineWriteRe — запись срока на строку приглашения.
var inviteDeadlineWriteRe = regexp.MustCompile(
	`(?i)\b` + inviteDeadlineColumn + `\s*=`)

// MembershipRemovalSite — координата функции, снимающей участие.
type MembershipRemovalSite struct {
	// File — путь от корня модуля, через косую черту.
	File string
	// Line — строка объявления функции.
	Line int
	// Func — имя функции.
	Func string
	// Devalues — обесценивает ли она невыкупленное приглашение.
	Devalues bool
}

// MembershipRemovalCensus — объём осмотренного.
type MembershipRemovalCensus struct {
	// Read — не-тестовых файлов Go прочитано.
	Read int
	// Funcs — функций осмотрено.
	Funcs int
	// Literals — строковых литералов осмотрено.
	Literals int
	// Removing — функций, снимающих строку участия.
	Removing int
	// Devaluing — из них обесценивающих невыкупленное приглашение.
	Devaluing int
}

// String — перепись одной строкой. Величин ДВЕ по существу — «снимающих
// найдено · из них обесценивающих», — и одна не заменяет другую: без первой
// «ноль находок» неотличимо от «ноль прочитанного».
func (c MembershipRemovalCensus) String() string {
	return fmt.Sprintf(
		"перепись: глаголов, снимающих участие, найдено %d · из них обесценивают "+
			"невыкупленное приглашение %d (файлов Go прочитано %d, функций осмотрено %d, "+
			"строковых литералов осмотрено %d)",
		c.Removing, c.Devaluing, c.Read, c.Funcs, c.Literals)
}

// ScanMembershipRemovalFile разбирает ОДИН файл.
func ScanMembershipRemovalFile(rel string, src []byte) (sites []MembershipRemovalSite, census MembershipRemovalCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, rel, src, 0)
	if perr != nil {
		return nil, MembershipRemovalCensus{}, perr
	}

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		census.Funcs++
		var removes, devalues bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.Literals++
			text := lit.Value
			if u, uerr := strconv.Unquote(text); uerr == nil {
				text = u
			} else {
				text = strings.Trim(text, "`\"")
			}
			if membershipDeleteRe.MatchString(text) {
				removes = true
			}
			if inviteDeadlineWriteRe.MatchString(text) {
				devalues = true
			}
			return true
		})
		if !removes {
			continue
		}
		census.Removing++
		if devalues {
			census.Devaluing++
		}
		sites = append(sites, MembershipRemovalSite{
			File: rel, Line: fset.Position(fn.Pos()).Line,
			Func: fn.Name.Name, Devalues: devalues,
		})
	}
	return sites, census, nil
}

// ScanMembershipRemovals обходит не-тестовое дерево Go модуля.
func ScanMembershipRemovals(root string) (sites []MembershipRemovalSite, census MembershipRemovalCensus, err error) {
	tracked, terr := treecorpus.Under(root)
	if terr != nil {
		return nil, census, fmt.Errorf("состав дерева: %w", terr)
	}
	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, census, fmt.Errorf("путь %s: %w", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !strings.HasSuffix(slashed, ".go") || strings.HasSuffix(slashed, "_test.go") {
			continue
		}
		raw, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			return nil, census, fmt.Errorf("чтение %s: %w", slashed, berr)
		}
		census.Read++
		s, c, serr := ScanMembershipRemovalFile(slashed, raw)
		if serr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", slashed, serr)
		}
		census.Funcs += c.Funcs
		census.Literals += c.Literals
		census.Removing += c.Removing
		census.Devaluing += c.Devaluing
		sites = append(sites, s...)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, census, nil
}
