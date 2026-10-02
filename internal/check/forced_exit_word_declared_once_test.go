// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// forced_exit_word_declared_once_test.go — ПРОБА РАЗБОРА ДЕРЕВА: слово
// причины принудительного выхода объявлено ОДИН раз, доменом (приёмка
// `docs/engineering/acceptance/forced-exit-has-its-own-session-end-reason.md`,
// KN-SER-10, решение Р3; задача kaname#334).
//
// # Предмет
//
// Слово `admin-force-logout` служба пишет в два места: умолчание свободной
// причины отсечки и причина снятия записи сессии. Оба обязаны ссылаться на
// ОДНО объявление домена, а не повторять литерал: второе написание одного
// значения расходится с первым молча, и расходится то, которое правили не
// последним.
//
// Утверждается три факта о не-тестовом Go-дереве модуля:
//
//  1. узел строкового литерала с этим значением в нём ровно ОДИН, и это
//     значение константы в объявлении домена (`internal/domain/human_session.go`);
//  2. `force_logout.go` ссылается на эту константу селектором пакета домена;
//  3. селектора `domain.RevokeReasonLogout` в `force_logout.go` нет.
//
// # Почему разбор узлов, а не поиск по тексту
//
// Текстовый поиск по модулю находит слово и в комментарии сгенерированного
// контракта (`pkg/api/.../internal_iam_service.pb.go`). Разбор ходит по узлам
// `ast.BasicLit`, и комментарий в счёт не идёт по построению. Селектор
// судится по ПУТИ ИМПОРТА, а не по имени пакета: псевдоним импорта домена —
// та же ссылка, а одноимённый селектор чужого пакета — не она.
//
// Имя константы проба берёт из найденного объявления, а не выписывает у себя:
// своя копия имени была бы вторым объявлением.
//
// # Слепая зона названа
//
// Слово, собранное сложением строк (`"admin-" + "force-logout"`), разбор не
// видит: узла с таким значением нет. Затенение имени импорта локальной
// переменной — тоже.
//
// # Где лежит разбор
//
// Разбор объявлен в этом тестовом файле, а не рядом, в не-тестовом файле
// пакета, как у соседей (`assurance_method_vocabulary.go`). Слово проба
// выписывает дословно из приёмки, а не берёт у домена: константа с другим
// значением обязана её ронять, а не тянуть за собой. В не-тестовом файле
// `internal/check` этот литерал стал бы вторым узлом того самого прод-корпуса,
// который проба судит. Способность упасть и смолчать доказана инъекцией —
// forced_exit_word_declared_once_injection_test.go.
package check_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// forcedExitWord — слово причины, как его называет приёмка (Р1).
	forcedExitWord = "admin-force-logout"
	// forcedExitDomainImport — путь пакета, где слово объявляется.
	forcedExitDomainImport = "github.com/PRO-Robotech/kaname/internal/domain"
	// forcedExitDomainDeclRel — файл объявления (KN-SER-10, первое «Тогда»).
	forcedExitDomainDeclRel = "internal/domain/human_session.go"
	// forcedExitVerbRel — глагол, которому запрещено повторять литерал.
	forcedExitVerbRel = "internal/apps/kaname/api/internal_iam/force_logout.go"
	// forcedExitRetiredSelector — имя, на которое глагол ссылаться не вправе.
	forcedExitRetiredSelector = "RevokeReasonLogout"
)

// errForcedExitEmptyCorpus — обход не прочитал ни одного файла: вердикта нет.
var errForcedExitEmptyCorpus = errors.New("обход пуст: файлов Go не прочитано ни одного — «находок ноль» значило бы «прочитано ноль»")

// forcedExitWordSite — координата узла.
type forcedExitWordSite struct {
	File string
	Line int
	// Const — имя константы, если узел — её значение в группе const.
	Const string
}

func (s forcedExitWordSite) String() string {
	if s.Const != "" {
		return fmt.Sprintf("%s:%d (значение константы %s)", s.File, s.Line, s.Const)
	}
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}

// forcedExitWordVerdict — исход разбора корпуса.
type forcedExitWordVerdict struct {
	// Files — файлов разобрано.
	Files int
	// Literals — узлы строкового литерала со словом, по всему корпусу.
	Literals []forcedExitWordSite
	// DeclName — имя константы домена, чьё значение — слово; пусто, если
	// объявления нет.
	DeclName string
	// References — селекторы глагола на DeclName через импорт домена.
	References []forcedExitWordSite
	// Retired — селекторы глагола на RevokeReasonLogout через импорт домена.
	Retired []forcedExitWordSite
	// VerbSeen — глагол был в корпусе.
	VerbSeen bool
}

// Findings — нарушения трёх утверждений KN-SER-10, каждое с координатой.
func (v forcedExitWordVerdict) Findings() []string {
	var out []string
	switch {
	case len(v.Literals) == 0:
		out = append(out, fmt.Sprintf("узлов литерала %q в дереве 0: слово не объявлено ни доменом, ни кем-либо", forcedExitWord))
	case len(v.Literals) > 1:
		coords := make([]string, 0, len(v.Literals))
		for _, s := range v.Literals {
			coords = append(coords, s.String())
		}
		out = append(out, fmt.Sprintf("узлов литерала %q в дереве %d при требуемом одном: %s",
			forcedExitWord, len(v.Literals), strings.Join(coords, "; ")))
	}
	for _, s := range v.Literals {
		if s.File != forcedExitDomainDeclRel || s.Const == "" {
			out = append(out, fmt.Sprintf("литерал %q вне объявления домена (%s): %s",
				forcedExitWord, forcedExitDomainDeclRel, s))
		}
	}
	if v.DeclName != "" && len(v.References) == 0 {
		out = append(out, fmt.Sprintf("%s не ссылается на объявление домена %s: селекторов на него 0",
			forcedExitVerbRel, v.DeclName))
	}
	for _, s := range v.Retired {
		out = append(out, fmt.Sprintf("селектор domain.%s в глаголе принудительного выхода: %s",
			forcedExitRetiredSelector, s))
	}
	return out
}

// judgeForcedExitWord разбирает корпус «относительный путь → тело» и
// возвращает исход. Пустой корпус и корпус без глагола — отказ, а не
// зелёное: судить отсутствие литерала в файле, которого не читали, нельзя.
func judgeForcedExitWord(corpus map[string]string) (forcedExitWordVerdict, error) {
	var v forcedExitWordVerdict
	if len(corpus) == 0 {
		return v, errForcedExitEmptyCorpus
	}
	rels := make([]string, 0, len(corpus))
	for rel := range corpus {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	parsed := map[string]*ast.File{}
	fsets := map[string]*token.FileSet{}
	for _, rel := range rels {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, rel, corpus[rel], parser.ParseComments)
		if err != nil {
			return v, fmt.Errorf("разбор %s: %w", rel, err)
		}
		parsed[rel], fsets[rel] = f, fset
		v.Files++
	}

	for _, rel := range rels {
		f, fset := parsed[rel], fsets[rel]
		// Узел — значение константы в группе const: имя берётся из объявления.
		constOf := map[*ast.BasicLit]string{}
		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, val := range vs.Values {
					if lit, ok := val.(*ast.BasicLit); ok && i < len(vs.Names) {
						constOf[lit] = vs.Names[i].Name
					}
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err != nil || s != forcedExitWord {
				return true
			}
			site := forcedExitWordSite{File: rel, Line: fset.Position(lit.Pos()).Line, Const: constOf[lit]}
			v.Literals = append(v.Literals, site)
			if rel == forcedExitDomainDeclRel && site.Const != "" && v.DeclName == "" {
				v.DeclName = site.Const
			}
			return true
		})
	}

	verb, ok := parsed[forcedExitVerbRel]
	if !ok {
		return v, fmt.Errorf("предпосылка не выполнена: глагола %s в корпусе нет — судить его селекторы нечем", forcedExitVerbRel)
	}
	v.VerbSeen = true
	local := domainImportName(verb)
	if local == "" {
		// Глагол не импортирует домен: ни ссылки, ни запрещённого селектора в
		// нём нет — это исход (находка «ссылок 0»), а не отказ.
		return v, nil
	}
	fset := fsets[forcedExitVerbRel]
	ast.Inspect(verb, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != local {
			return true
		}
		site := forcedExitWordSite{File: forcedExitVerbRel, Line: fset.Position(sel.Pos()).Line}
		switch {
		case sel.Sel.Name == forcedExitRetiredSelector:
			v.Retired = append(v.Retired, site)
		case v.DeclName != "" && sel.Sel.Name == v.DeclName:
			v.References = append(v.References, site)
		}
		return true
	})
	return v, nil
}

// domainImportName — имя, под которым файл видит пакет домена; пусто, если
// не импортирует (либо импортирует точкой или подчёркиванием).
func domainImportName(f *ast.File) string {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != forcedExitDomainImport {
			continue
		}
		if imp.Name == nil {
			return "domain"
		}
		if imp.Name.Name == "." || imp.Name.Name == "_" {
			return ""
		}
		return imp.Name.Name
	}
	return ""
}

// TestForcedExitWord_KN_SER_10_IsDeclaredOnceByTheDomain — KN-SER-10 на дереве.
func TestForcedExitWord_KN_SER_10_IsDeclaredOnceByTheDomain(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	v, err := judgeForcedExitWord(corpus)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	t.Logf("перепись: файлов не-тестового Go разобрано %d; узлов литерала %q найдено %d; "+
		"объявление домена: %q; ссылок глагола на него %d; селекторов domain.%s в глаголе %d",
		v.Files, forcedExitWord, len(v.Literals), v.DeclName, len(v.References),
		forcedExitRetiredSelector, len(v.Retired))

	if findings := v.Findings(); len(findings) != 0 {
		t.Fatalf("слово причины принудительного выхода объявлено НЕ один раз доменом — %d находок:\n  %s\n\n"+
			"Слово объявляется константой в %s; умолчание причины отсечки и причина снятия "+
			"записи сессии в %s ссылаются на неё (приёмка KN-SER-10, Р3).",
			len(findings), strings.Join(findings, "\n  "), forcedExitDomainDeclRel, forcedExitVerbRel)
	}
}
