// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// address_admission_gates.go — гейты дерева приёмки
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`
// (задача PRO-Robotech/kaname#456, §9 пп. 4, 15; §8 инв. 4, 5, 11) и условий
// аудита поверхности службы:
//
//   - у отметки подтверждения ОДИН писатель — глагол подтверждения
//     ([MarkWriterCalls]): ни хук поставщика, ни зеркало, ни посев отметку не
//     ставят, и флаг «подтверждён» поставщика не переносится;
//   - каждая полоса выдачи удостоверения человеку спрашивает правило выдачи
//     ([IssuanceLaneFindings]);
//   - каждая форма двери решения объявлена одной строкой переписи, и форма
//     «под предикатом» зовёт предикат допуска ([DoorFormFindings]);
//   - каждый писатель очереди НАШИХ писем списывает окно раньше постановки
//     ([MailWriterFindings]);
//   - посадка не пишет в строки людей ([PeopleRowWrites]).
//
// Все гейты судят УЗЛЫ разбора, а не подстроки: слово в комментарии или в
// тексте ошибки вызовом не является. Каждый печатает объём осмотренного, и
// пустой обход — находка, а не зелёное.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// callNamed — позиция и имя вызова `<x>.<name>(…)` либо `<name>(…)`.
type callNamed struct {
	pos  token.Pos
	recv string // идентификатор слева от точки; "" у голого вызова
	name string
}

// callsIn — вызовы в теле узла, в порядке исходника.
func callsIn(n ast.Node) []callNamed {
	var out []callNamed
	ast.Inspect(n, func(x ast.Node) bool {
		c, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := c.Fun.(type) {
		case *ast.SelectorExpr:
			recv := ""
			if id, ok := f.X.(*ast.Ident); ok {
				recv = id.Name
			}
			out = append(out, callNamed{pos: c.Pos(), recv: recv, name: f.Sel.Name})
		case *ast.Ident:
			out = append(out, callNamed{pos: c.Pos(), name: f.Name})
		}
		return true
	})
	return out
}

// parsedFile — разобранный исходник с его путём.
type parsedFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

func parseAll(files map[string]string) ([]parsedFile, error) {
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	out := make([]parsedFile, 0, len(rels))
	for _, rel := range rels {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, rel, files[rel], parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("разбор %s: %w", rel, err)
		}
		out = append(out, parsedFile{rel: rel, fset: fset, file: f})
	}
	return out, nil
}

// funcsOf — объявления функций и методов файла.
func funcsOf(f *ast.File) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
			out = append(out, fd)
		}
	}
	return out
}

// ─── Один писатель отметки ──────────────────────────────────────────────────

// MarkWriterCalls — координаты ВЫЗОВОВ писателя отметки подтверждения
// (`MarkEmailVerified`) в непроверочном коде и число разобранных файлов.
// Объявления метода вызовами не считаются.
func MarkWriterCalls(files map[string]string) (calls []string, parsed int, err error) {
	pfs, err := parseAll(files)
	if err != nil {
		return nil, 0, err
	}
	for _, pf := range pfs {
		for _, c := range callsIn(pf.file) {
			if c.name == "MarkEmailVerified" && c.recv != "" {
				calls = append(calls, fmt.Sprintf("%s:%d", pf.rel, pf.fset.Position(c.pos).Line))
			}
		}
	}
	return calls, len(pfs), nil
}

// ─── Полосы выдачи спрашивают правило ───────────────────────────────────────

// IssuanceLane — полоса выдачи удостоверения человеку и функция, в которой она
// спрашивает правило выдачи.
type IssuanceLane struct {
	Name string
	File string
	Func string
}

// issuanceRuleCalls — вердикт правила выдачи (`internal/revocationpolicy`).
var issuanceRuleCalls = map[string]bool{"AtIssuance": true, "OwnerAdmission": true}

// IssuanceLaneFindings — каждая объявленная полоса существует и спрашивает
// правило выдачи; пустой перечень — находка.
func IssuanceLaneFindings(files map[string]string, lanes []IssuanceLane) (inspected int, findings []string, err error) {
	if len(lanes) == 0 {
		return 0, []string{"перечень полос выдачи пуст — судить нечего"}, nil
	}
	for _, l := range lanes {
		src, ok := files[l.File]
		if !ok {
			findings = append(findings, fmt.Sprintf("полоса %s: файла %s в дереве нет", l.Name, l.File))
			continue
		}
		pfs, perr := parseAll(map[string]string{l.File: src})
		if perr != nil {
			return inspected, nil, perr
		}
		var found, asks bool
		for _, fd := range funcsOf(pfs[0].file) {
			if fd.Name.Name != l.Func {
				continue
			}
			found = true
			inspected++
			for _, c := range callsIn(fd.Body) {
				if c.recv == "revocationpolicy" && issuanceRuleCalls[c.name] {
					asks = true
				}
			}
		}
		switch {
		case !found:
			findings = append(findings, fmt.Sprintf("полоса %s: функции %s в %s нет", l.Name, l.Func, l.File))
		case !asks:
			findings = append(findings, fmt.Sprintf("полоса %s: %s.%s выдаёт мимо правила выдачи (revocationpolicy)", l.Name, l.File, l.Func))
		}
	}
	return inspected, findings, nil
}

// ─── Формы двери решения ─────────────────────────────────────────────────────

// DoorRow — строка переписи формы двери решения.
type DoorRow string

const (
	// DoorUnderPredicate — отвечает вердиктом либо держателями: зовёт
	// предикат допуска.
	DoorUnderPredicate DoorRow = "под предикатом"
	// DoorRecords — отвечает записями для разбора и текста отказа.
	DoorRecords DoorRow = "отвечает записями"
	// DoorLiveness — о живости формы.
	DoorLiveness DoorRow = "живость"
)

// doorPredicateCalls — вызовы, которыми форма судит допуск: сам предикат, его
// перечень держателей и делегирование другой форме под предикатом.
var doorPredicateCalls = map[string]bool{
	"Subject": true, "Subjects": true, "admittedHolders": true, "CheckWithContext": true,
}

// DoorFormFindings — перепись экспортированных методов двери (`*Client` в
// src) против объявления: форма без строки, строка без формы, форма «под
// предикатом», не зовущая предиката. Печатаемое число — осмотрено форм.
func DoorFormFindings(src string, declared map[string]DoorRow) (inspected map[DoorRow]int, findings []string, err error) {
	pfs, err := parseAll(map[string]string{"own_gates.go": src})
	if err != nil {
		return nil, nil, err
	}
	inspected = map[DoorRow]int{}
	seen := map[string]bool{}
	for _, fd := range funcsOf(pfs[0].file) {
		if fd.Recv == nil || !fd.Name.IsExported() || !recvIs(fd, "Client") {
			continue
		}
		name := fd.Name.Name
		if name == "SubjectAdmitted" {
			// Сам предикат, выставленный двери службы: формой вопроса не является.
			continue
		}
		seen[name] = true
		row, ok := declared[name]
		if !ok {
			findings = append(findings, fmt.Sprintf("форма двери %s не объявлена строкой переписи", name))
			continue
		}
		inspected[row]++
		if row != DoorUnderPredicate {
			continue
		}
		var calls bool
		for _, c := range callsIn(fd.Body) {
			if (c.recv == "admission" || c.recv == "c") && doorPredicateCalls[c.name] {
				calls = true
			}
		}
		if !calls {
			findings = append(findings, fmt.Sprintf("форма двери %s объявлена «под предикатом», а предиката допуска не зовёт", name))
		}
	}
	for name := range declared {
		if !seen[name] {
			findings = append(findings, fmt.Sprintf("строка переписи %s без формы двери", name))
		}
	}
	if len(seen) == 0 {
		findings = append(findings, "форм двери не найдено — обход пуст")
	}
	sort.Strings(findings)
	return inspected, findings, nil
}

func recvIs(fd *ast.FuncDecl, typ string) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	switch t := fd.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		id, ok := t.X.(*ast.Ident)
		return ok && id.Name == typ
	case *ast.Ident:
		return t.Name == typ
	}
	return false
}

// ─── Писатели очереди наших писем списывают окно ─────────────────────────────

// MailWriterCensus — перепись писателей очереди писем.
type MailWriterCensus struct {
	FilesParsed int
	// Writers — функции, ставящие письмо в очередь (`invite_mail_outbox.Emit*Tx`).
	Writers []string
	// ChargedHere — списывают окно сами, раньше постановки.
	ChargedHere int
	// ChargedByCaller — поставлены вызывающим, списавшим предел раньше.
	ChargedByCaller int
}

// MailWriterFindings — каждый писатель очереди наших писем списывает окно
// раньше постановки: сам (`chargeInviteMailWindowTx`) либо каждый его
// вызывающий (`InsertVerificationCodePaced` — предел писем подтверждения,
// решаемый вставкой строки кода). Пустая перепись — находка.
func MailWriterFindings(files map[string]string) (MailWriterCensus, []string, error) {
	pfs, err := parseAll(files)
	if err != nil {
		return MailWriterCensus{}, nil, err
	}
	var census MailWriterCensus
	census.FilesParsed = len(pfs)
	var findings []string
	// Сначала — все функции и их вызовы: вызывающие писателя ищутся по имени
	// метода.
	type fn struct {
		rel   string
		name  string
		decl  *ast.FuncDecl
		calls []callNamed
		fset  *token.FileSet
	}
	var all []fn
	for _, pf := range pfs {
		for _, fd := range funcsOf(pf.file) {
			all = append(all, fn{rel: pf.rel, name: fd.Name.Name, decl: fd, calls: callsIn(fd.Body), fset: pf.fset})
		}
	}
	chargedBefore := func(calls []callNamed, at token.Pos, charge string) bool {
		for _, c := range calls {
			if c.name == charge && c.pos < at {
				return true
			}
		}
		return false
	}
	for _, f := range all {
		for _, c := range f.calls {
			if c.recv != "invite_mail_outbox" || !strings.HasPrefix(c.name, "Emit") || !strings.HasSuffix(c.name, "Tx") {
				continue
			}
			where := fmt.Sprintf("%s:%d %s", f.rel, f.fset.Position(c.pos).Line, f.name)
			census.Writers = append(census.Writers, where)
			if chargedBefore(f.calls, c.pos, "chargeInviteMailWindowTx") {
				census.ChargedHere++
				continue
			}
			// Писатель поставлен вызывающими: каждый обязан решить предел
			// раньше вызова писателя.
			var callers, charged int
			for _, g := range all {
				for _, gc := range g.calls {
					if gc.name != f.name || gc.recv == "" || g.rel == f.rel && g.name == f.name {
						continue
					}
					callers++
					if chargedBefore(g.calls, gc.pos, "InsertVerificationCodePaced") {
						charged++
					} else {
						findings = append(findings, fmt.Sprintf("%s:%d %s зовёт писателя очереди %s, не решив предел писем раньше",
							g.rel, g.fset.Position(gc.pos).Line, g.name, f.name))
					}
				}
			}
			switch {
			case callers == 0:
				findings = append(findings, where+": писатель очереди писем не списывает окно адресата и не имеет вызывающих, решивших предел")
			case charged == callers:
				census.ChargedByCaller++
			}
		}
	}
	if len(census.Writers) == 0 {
		findings = append(findings, "писателей очереди писем не найдено — обход пуст")
	}
	return census, findings, nil
}

// ─── Посадка не пишет в строки людей ─────────────────────────────────────────

// peopleRowWrite — оператор записи в строки людей, их членств, выдач и выдач
// администратора облака.
var peopleRowWrite = regexp.MustCompile(`(?i)\b(UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+(kaname\.)?(users|memberships|access_bindings|access_binding_subjects|cluster_admin_grants)\b`)

// PeopleRowWrites — операторы записи в строки людей в секции НАКАТА миграции;
// строки комментария не считаются. Второе число — осмотрено строк наката.
func PeopleRowWrites(sql string) (writes []string, upLines int) {
	// Разрез наката — у его единственного объявления (`migrations.MigrationUpText`).
	up := migrations.MigrationUpText(sql)
	for n, line := range strings.Split(up, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		upLines++
		if peopleRowWrite.MatchString(trimmed) {
			writes = append(writes, fmt.Sprintf("строка %d: %s", n+1, trimmed))
		}
	}
	return writes, upLines
}
