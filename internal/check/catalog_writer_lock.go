// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_writer_lock.go — всякий прод-писатель строк `kaname.catalog_*`
// берёт глобальный транзакционный замок каталога (приёмка
// `docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md` §7,
// объём О11, держатель Г1; kacho#1034).
//
// Порт с монорепо (`internal/repohygiene/catalogwriterlock.go`, снят
// вынесением службы — `kacho#2597` с заявлением «обход служб жив, но
// исполняемых операторов записи в этот каталог ноль». Заявление было верно
// ТОЛЬКО для монорепо (там дерево служб доступа исчезло) — приёмка сама
// называет отсутствие держателя пунктом Н5 и требует его. Механизм в
// дереве службы ЖИВ дословно: `internal/repo/kaname/pg/catalog_writer.go`
// несёт `CatalogLockKey`/`LockCatalog` (`pg_advisory_xact_lock`) и три
// `UpsertModule`/`UpsertResource`/`UpsertVerb` на том же получателе
// (`catalogWriter`) — единица суждения по-прежнему сходится. Осталось
// дословно: весь алгоритм (регулярки, разбор, единица суждения, тексты
// находок). Изменилось: путь-константа без префикса `services/iam/`, обход
// — от корня СВОЕГО репозитория целиком (предмет запрета — «ВСЯКИЙ
// прод-писатель», не только сегодняшний).
//
// # Предмет
//
// Подтверждение применения (отпечаток состояния модуля) есть CAS ТОЛЬКО
// потому, что между чтением отпечатка и записью строк не может встать второй
// писатель. Обеспечивает это не сравнение, а `pg_advisory_xact_lock`, взятый
// В ТЕЛЕ КАКОГО-ЛИБО МЕТОДА писателя (гейт не проверяет порядок — это держит
// интеграционная проба, не разбор).
//
// # Единица суждения — ТИП (получатель метода), а не файл и не пакет-вызывающий
//
// Замок и запись могут лежать в РАЗНЫХ методах ОДНОГО получателя в ОДНОМ
// пакете (как здесь: `LockCatalog` и `UpsertModule` — оба методы
// `catalogWriter` в `internal/repo/kaname/pg`) — тогда они СХОДЯТСЯ в одну
// единицу суждения и гейт молчит. Замок, взятый ЧУЖИМ пакетом (например,
// вызывающим use-case, держащим порт `CatalogWriter`), этот гейт НЕ видит —
// он не о том, кто ЗОВЁТ замок, а о том, что писатель СПОСОБЕН его взять
// (несёт метод, который это делает).
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CatalogSource — один прод-файл на вход разбора. Инъекция подаёт
// синтетический состав, не трогая рабочую копию.
type CatalogSource struct {
	Path string
	Src  []byte
}

// CatalogWriteFinding — координата находки: писатель без замка.
type CatalogWriteFinding struct {
	File string
	Line int
	Unit string
	What string
	Why  string
}

// CatalogWriteCensus — объём осмотренного.
type CatalogWriteCensus struct {
	Files          int
	Parsed         int
	Funcs          int
	Executors      int
	StringLiterals int
	Comments       int
	TextMatches    int
	TextFiles      int
	Executed       int
	ExecutingFiles int
	WriteUnits     int
	LockedUnits    int
	LockSites      int
}

// catalogWriteStmtRe — оператор ЗАПИСИ над строкой каталога, привязанный к
// началу строки (проза о запрете несёт те же слова посреди предложения).
var catalogWriteStmtRe = regexp.MustCompile(
	`(?im)^\s*(with\b[^\n]*\n\s*)?(insert\s+into|update)\s+(kaname\.)?catalog_(module|resource|verb)\b`)

var catalogXactLockRe = regexp.MustCompile(`(?i)\bpg_advisory_xact_lock\s*\(`)
var catalogSessionLockRe = regexp.MustCompile(`(?i)\bpg_advisory_lock\s*\(`)

// CatalogLockKeyIdent — имя константы ключа.
const CatalogLockKeyIdent = "CatalogLockKey"

// CatalogLockKeyValue — её значение (принимается и литералом).
const CatalogLockKeyValue = "kaname.module_catalog"

var catalogExecSelectors = map[string]bool{
	"Exec": true, "Query": true, "QueryRow": true,
	"SendBatch": true, "Queue": true, "CopyFrom": true,
}

// catalogUnitState — что известно об одной единице суждения.
type catalogUnitState struct {
	unit        string
	writes      []CatalogWriteFinding
	xactLocked  bool
	sessionOnly bool
	wrongKey    bool
}

// ScanCatalogWriteLocking разбирает состав прод-файлов и отвечает, какие
// единицы пишут строки каталога, не запирая его. Файлы группируются ПО
// ПАКЕТУ (каталогу).
func ScanCatalogWriteLocking(files []CatalogSource) ([]CatalogWriteFinding, CatalogWriteCensus, error) {
	var census CatalogWriteCensus

	byPkg := map[string][]CatalogSource{}
	var pkgs []string
	for _, f := range files {
		dir := filepath.ToSlash(filepath.Dir(f.Path))
		if _, seen := byPkg[dir]; !seen {
			pkgs = append(pkgs, dir)
		}
		byPkg[dir] = append(byPkg[dir], f)
		census.Files++
	}
	sort.Strings(pkgs)

	var findings []CatalogWriteFinding
	for _, dir := range pkgs {
		f, c, err := scanCatalogPackage(dir, byPkg[dir])
		if err != nil {
			return nil, census, err
		}
		findings = append(findings, f...)
		census.Parsed += c.Parsed
		census.Funcs += c.Funcs
		census.Executors += c.Executors
		census.StringLiterals += c.StringLiterals
		census.Comments += c.Comments
		census.TextMatches += c.TextMatches
		census.TextFiles += c.TextFiles
		census.Executed += c.Executed
		census.ExecutingFiles += c.ExecutingFiles
		census.WriteUnits += c.WriteUnits
		census.LockedUnits += c.LockedUnits
		census.LockSites += c.LockSites
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, census, nil
}

func scanCatalogPackage(dir string, files []CatalogSource) ([]CatalogWriteFinding, CatalogWriteCensus, error) {
	var census CatalogWriteCensus
	fset := token.NewFileSet()

	type parsed struct {
		rel  string
		file *ast.File
	}
	var ps []parsed
	for _, src := range files {
		file, err := parser.ParseFile(fset, src.Path, src.Src, parser.ParseComments)
		if err != nil {
			return nil, census, err
		}
		census.Parsed++
		ps = append(ps, parsed{rel: filepath.ToSlash(src.Path), file: file})
	}

	sqlNames := map[string]bool{}
	for _, p := range ps {
		ast.Inspect(p.file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.ValueSpec:
				for i, name := range v.Names {
					if i < len(v.Values) && catalogLiteralWrites(v.Values[i]) {
						sqlNames[name.Name] = true
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range v.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || i >= len(v.Rhs) {
						continue
					}
					if catalogLiteralWrites(v.Rhs[i]) {
						sqlNames[id.Name] = true
					}
				}
			}
			return true
		})
	}

	for _, p := range ps {
		hit := false
		for _, g := range p.file.Comments {
			census.Comments += len(g.List)
		}
		ast.Inspect(p.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.StringLiterals++
			if catalogWriteStmtRe.MatchString(catalogLitText(lit.Value)) {
				census.TextMatches++
				hit = true
			}
			return true
		})
		if hit {
			census.TextFiles++
		}
	}

	executors := map[string]bool{}
	for {
		grew := false
		for _, p := range ps {
			for _, decl := range p.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if executors[fn.Name.Name] {
					continue
				}
				if catalogFuncForwardsAParamToAnExecutor(fn, executors) {
					executors[fn.Name.Name] = true
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	census.Executors = len(executors)

	units := map[string]*catalogUnitState{}
	unitOf := func(name string) *catalogUnitState {
		if u, ok := units[name]; ok {
			return u
		}
		u := &catalogUnitState{unit: name}
		units[name] = u
		return u
	}

	for _, p := range ps {
		fileExecuted := 0
		for _, decl := range p.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			census.Funcs++
			name := dir + "::" + catalogUnitName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !catalogCallExecutes(call, executors) {
					return true
				}
				for _, arg := range call.Args {
					if !catalogArgWrites(arg, sqlNames) {
						continue
					}
					u := unitOf(name)
					u.writes = append(u.writes, CatalogWriteFinding{
						File: p.rel,
						Line: fset.Position(arg.Pos()).Line,
						Unit: catalogUnitName(fn),
						What: catalogFirstLine(arg, sqlNames),
					})
					census.Executed++
					fileExecuted++
				}
				if kind, key := catalogCallLocks(call); kind != "" {
					u := unitOf(name)
					census.LockSites++
					switch {
					case kind == "xact" && key:
						u.xactLocked = true
					case kind == "xact":
						u.wrongKey = true
					default:
						u.sessionOnly = true
					}
				}
				return true
			})
		}
		if fileExecuted > 0 {
			census.ExecutingFiles++
		}
	}

	var findings []CatalogWriteFinding
	for _, u := range units {
		if len(u.writes) == 0 {
			continue
		}
		census.WriteUnits++
		if u.xactLocked {
			census.LockedUnits++
			continue
		}
		why := "замка каталога не берёт вовсе"
		switch {
		case u.sessionOnly:
			why = "берёт СЕССИОННЫЙ замок (`pg_advisory_lock`): он не снимается " +
				"откатом, и оборванный применитель запирает каталог до возврата " +
				"соединения в пул"
		case u.wrongKey:
			why = "берёт транзакционный замок на ЧУЖОМ ключе: два писателя на разных " +
				"ключах проходят одновременно, и «замок взят» становится утверждением " +
				"о вызове, а не о свойстве"
		}
		w := u.writes[0]
		w.Why = why
		findings = append(findings, w)
	}
	return findings, census, nil
}

func catalogFuncForwardsAParamToAnExecutor(fn *ast.FuncDecl, known map[string]bool) bool {
	params := map[string]bool{}
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, n := range field.Names {
				params[n.Name] = true
			}
		}
	}
	if len(params) == 0 {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !catalogCallExecutes(call, known) {
			return true
		}
		for _, arg := range call.Args {
			id, ok := arg.(*ast.Ident)
			if ok && params[id.Name] {
				found = true
			}
		}
		return true
	})
	return found
}

func catalogCallExecutes(call *ast.CallExpr, known map[string]bool) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return catalogExecSelectors[fn.Sel.Name] || known[fn.Sel.Name]
	case *ast.Ident:
		return known[fn.Name]
	}
	return false
}

func catalogArgWrites(arg ast.Expr, sqlNames map[string]bool) bool {
	if catalogLiteralWrites(arg) {
		return true
	}
	id, ok := arg.(*ast.Ident)
	return ok && sqlNames[id.Name]
}

func catalogLiteralWrites(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	return catalogWriteStmtRe.MatchString(catalogLitText(lit.Value))
}

// catalogCallLocks — вызов берёт консультативный замок. Первое значение —
// форма (`xact`/`session`, пусто = не замок), второе — назван ли ТОТ ключ.
func catalogCallLocks(call *ast.CallExpr) (kind string, rightKey bool) {
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		text := catalogLitText(lit.Value)
		switch {
		case catalogXactLockRe.MatchString(text):
			kind = "xact"
		case catalogSessionLockRe.MatchString(text):
			if kind == "" {
				kind = "session"
			}
		}
	}
	if kind == "" {
		return "", false
	}
	for _, arg := range call.Args {
		switch v := arg.(type) {
		case *ast.Ident:
			if v.Name == CatalogLockKeyIdent {
				rightKey = true
			}
		case *ast.SelectorExpr:
			if v.Sel.Name == CatalogLockKeyIdent {
				rightKey = true
			}
		case *ast.BasicLit:
			if v.Kind == token.STRING && strings.Contains(catalogLitText(v.Value), CatalogLockKeyValue) {
				rightKey = true
			}
		}
	}
	return kind, rightKey
}

func catalogUnitName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		if n := catalogRecvTypeName(fn.Recv.List[0].Type); n != "" {
			return n
		}
	}
	return "func:" + fn.Name.Name
}

func catalogRecvTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return catalogRecvTypeName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return catalogRecvTypeName(v.X)
	case *ast.IndexListExpr:
		return catalogRecvTypeName(v.X)
	}
	return ""
}

func catalogLitText(v string) string {
	if u, err := strconv.Unquote(v); err == nil {
		return u
	}
	return strings.Trim(v, "`\"")
}

func catalogFirstLine(arg ast.Expr, sqlNames map[string]bool) string {
	lit, ok := arg.(*ast.BasicLit)
	if !ok {
		if id, ok := arg.(*ast.Ident); ok && sqlNames[id.Name] {
			return "оператор по имени `" + id.Name + "`"
		}
		return "оператор"
	}
	s := strings.TrimSpace(catalogLitText(lit.Value))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return strings.TrimSpace(s)
}
