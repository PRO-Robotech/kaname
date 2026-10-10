// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_single_enqueuer.go — гейт `mail_single_enqueuer` (замысел issue-2917 З1,
// И1, И28): порождённые функции постановки `feedgen.Send*` зовёт только пакет
// `internal/apps/kaname/mail`.
//
// # Предмет
//
// Решение «ставить строку ленты или нет» принимает только mail.Enqueue: флаг
// почты, окно адресата и лимит шаблона судятся там. Ссылка на Send* из любого
// другого пакета — письмо мимо этого решения: при выключенном флаге оно
// ушло бы сторожем ленты вместо исхода Disabled, а окно адресата его бы не
// увидело.
//
// # Что считается ссылкой — разбор импортов, а не поиск слова
//
// Признак — ПОЛНЫЙ путь импорта каталога шаблонов (`<модуль>/` + FeedgenDir),
// а не имя пакета: одноимённый пакет другого модуля нашим каталогом не
// является. В файле, импортирующем каталог, ссылка — узел селектора
// `<имя импорта>.Send<Имя>`: вызов и значение функции без вызова дают один
// узел, псевдоним импорта берётся из объявления импорта. Импорт с точкой
// делает ссылку неотличимой от своего идентификатора — это ОТКАЗ формы с
// координатой, а не тишина. Экспорт лимитов шаблона (`feedgen.<Шаблон>…PerDay`,
// З19) ссылкой не является: имя не начинается с Send.
//
// Допустимое место — ровно каталог MailPackageDir; его подкаталоги — другие
// пакеты и законным местом не являются. Тестовые файлы не судятся: пробы
// законно зовут Send* напрямую.
//
// # Перепись
//
// Печатается всегда: отслеживаемых файлов, прочитано не-тестовых файлов Go,
// функций Send* объявлено в каталоге шаблонов, пакетов, импортирующих каталог
// (число и перечень), ссылок в пакете mail, ссылок вне него. Предпосылки — в
// пробе гейта: пустой обход, ноль объявленных Send* и ноль ссылок в самом
// пакете mail — отказ, а не зелёный.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

const (
	// MailPackageDir — единственное законное место ссылок на Send*.
	MailPackageDir = "internal/apps/kaname/mail"
	// FeedgenDir — каталог порождённых функций постановки (вывод notifygen).
	FeedgenDir = MailPackageDir + "/feedgen"
	// enqueuerSendPrefix — приставка имени порождённой функции постановки.
	enqueuerSendPrefix = "Send"
)

// EnqueuerSendRef — ссылка на порождённую функцию постановки.
type EnqueuerSendRef struct {
	// File — путь от корня модуля через косую черту; Line — строка узла.
	File string
	Line int
	// Ref — ссылка дословно (`feedgen.SendInvite`) либо «импорт с точкой».
	Ref string
	// DotImport — форма, при которой ссылка неотличима от своего
	// идентификатора: отказ формы.
	DotImport bool
}

// Dir — каталог пакета файла ссылки.
func (r EnqueuerSendRef) Dir() string { return path.Dir(r.File) }

// EnqueuerFinding — находка гейта.
type EnqueuerFinding struct {
	Ref EnqueuerSendRef
}

func (f EnqueuerFinding) String() string {
	if f.Ref.DotImport {
		return fmt.Sprintf("%s:%d — импорт с точкой каталога шаблонов %s: ссылка на Send* неотличима от "+
			"своего идентификатора, и разбор не может её судить. Импортируйте каталог по имени; постановка — "+
			"только через mail.Enqueuer (design.md З1)", f.Ref.File, f.Ref.Line, FeedgenDir)
	}
	return fmt.Sprintf("%s:%d — %s вне пакета %s: письмо, поставленное мимо mail.Enqueue, обходит флаг почты, "+
		"окно адресата и лимит шаблона. Соберите письмо конструктором mail.Letter и поставьте Enqueue "+
		"(design.md З1, И1)", f.Ref.File, f.Ref.Line, f.Ref.Ref, MailPackageDir)
}

// EnqueuerCensus — объём осмотренного.
type EnqueuerCensus struct {
	Tracked       int
	Read          int
	DeclaredSends int
	// Importers — каталоги пакетов, импортирующих каталог шаблонов (не-тестовые
	// файлы), без самого каталога шаблонов.
	Importers  []string
	MailRefs   int
	OutsideRef int
}

func (c EnqueuerCensus) String() string {
	return fmt.Sprintf("перепись mail_single_enqueuer: отслеживаемых файлов %d · не-тестовых файлов Go прочитано %d · "+
		"функций Send* в %s %d · пакетов, импортирующих каталог шаблонов, %d %v · ссылок на Send* в %s %d · вне его %d",
		c.Tracked, c.Read, FeedgenDir, c.DeclaredSends, len(c.Importers), c.Importers, MailPackageDir, c.MailRefs, c.OutsideRef)
}

// EnqueuerFileCensus — вклад одного файла в перепись.
type EnqueuerFileCensus struct {
	Imports       bool
	DeclaredSends int
}

// ScanSingleEnqueuerFile разбирает один не-тестовый файл rel модуля module.
func ScanSingleEnqueuerFile(rel string, src []byte, module string) ([]EnqueuerSendRef, EnqueuerFileCensus, error) {
	var census EnqueuerFileCensus
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, census, err
	}
	if path.Dir(rel) == FeedgenDir {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && isSendName(fd.Name.Name) {
				census.DeclaredSends++
			}
		}
		return nil, census, nil
	}

	want := module + "/" + FeedgenDir
	var names []string
	var refs []EnqueuerSendRef
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil || p != want {
			continue
		}
		census.Imports = true
		switch {
		case imp.Name == nil:
			names = append(names, path.Base(p))
		case imp.Name.Name == ".":
			refs = append(refs, EnqueuerSendRef{
				File: rel, Line: fset.Position(imp.Pos()).Line, Ref: "импорт с точкой", DotImport: true,
			})
		case imp.Name.Name == "_":
		default:
			names = append(names, imp.Name.Name)
		}
	}
	if len(names) == 0 {
		return refs, census, nil
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || !isSendName(sel.Sel.Name) {
			return true
		}
		for _, name := range names {
			if x.Name == name {
				refs = append(refs, EnqueuerSendRef{
					File: rel, Line: fset.Position(sel.Pos()).Line, Ref: x.Name + "." + sel.Sel.Name,
				})
			}
		}
		return true
	})
	return refs, census, nil
}

// isSendName — имя порождённой функции постановки: Send и заглавная буква.
func isSendName(name string) bool {
	rest, ok := strings.CutPrefix(name, enqueuerSendPrefix)
	return ok && rest != "" && rest[0] >= 'A' && rest[0] <= 'Z'
}

// ScanSingleEnqueuer обходит отслеживаемые не-тестовые файлы Go дерева root.
func ScanSingleEnqueuer(root string) ([]EnqueuerSendRef, EnqueuerCensus, error) {
	var census EnqueuerCensus
	tracked, err := treecorpus.Under(root)
	if err != nil {
		return nil, census, fmt.Errorf("состав дерева: %w", err)
	}
	census.Tracked = len(tracked)
	module, err := TreeModulePath(root)
	if err != nil {
		return nil, census, err
	}
	importers := map[string]bool{}
	var refs []EnqueuerSendRef
	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, census, fmt.Errorf("путь %s: %w", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !strings.HasSuffix(slashed, ".go") || strings.HasSuffix(slashed, "_test.go") {
			continue
		}
		src, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git этого дерева
		if berr != nil {
			return nil, census, fmt.Errorf("чтение %s: %w", slashed, berr)
		}
		census.Read++
		r, c, serr := ScanSingleEnqueuerFile(slashed, src, module)
		if serr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", slashed, serr)
		}
		census.DeclaredSends += c.DeclaredSends
		if c.Imports {
			importers[path.Dir(slashed)] = true
		}
		for _, ref := range r {
			if ref.Dir() == MailPackageDir && !ref.DotImport {
				census.MailRefs++
			} else {
				census.OutsideRef++
			}
		}
		refs = append(refs, r...)
	}
	for dir := range importers {
		census.Importers = append(census.Importers, dir)
	}
	sort.Strings(census.Importers)
	return refs, census, nil
}

// AdjudicateSingleEnqueuer — находки: ссылка вне MailPackageDir и любой
// импорт с точкой.
func AdjudicateSingleEnqueuer(refs []EnqueuerSendRef) []EnqueuerFinding {
	var out []EnqueuerFinding
	for _, r := range refs {
		if r.DotImport || r.Dir() != MailPackageDir {
			out = append(out, EnqueuerFinding{Ref: r})
		}
	}
	return out
}
