// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// write_tx_opener.go — пишущая транзакция службы открывается только
// открывающим `journalwrite.Begin`, а журналируемая таблица пулом мимо транзакции не
// пишется (NTF-3, Р2; сценарий NTF3-63).
//
// # Предмет
//
// Строка ресурсного журнала без инициатора базой не принимается, а инициатора
// выставляет первым оператором тот, кто транзакцию открывает. Открывающий у
// службы один — `internal/journalwrite`; он выставляет
// инициатора принципала либо его отсутствие ЛОКАЛЬНО к транзакции, и потому
// ни одна пишущая транзакция службы не наследует настройку соединения.
//
// Пробы службы опираются на это свойство: посев проб получает инициатора
// ролевой настройкой контейнера (`internal/testsupport/journalfixture`), и
// транзакция продукта, открытая мимо открывающего, унаследовала бы её —
// запись без инициатора прошла бы в пробе и отказала бы в установке. Этот гейт
// делает такую транзакцию непредставимой в дереве.
//
// # Что находка — по ТИПУ получателя, а не по имени
//
// Разбор типизирован: получатель вызова судится типом — пул и соединение pgx
// (`*pgxpool.Pool`, `*pgxpool.Conn`, `*pgx.Conn`) и `database/sql`
// (`*sql.DB`, `*sql.Conn`). Порт `service.TxBeginner`, транзакция и любой иной
// тип с методом `Begin` предметом не являются, и имя поля (`pool`, `master`,
// `e`) ничего не решает.
//
//   - W1 — `Begin`, `BeginTx`, `BeginFunc`, `BeginTxFunc` на таком получателе
//     вне файла открывающего; законна только читающая транзакция, объявленная
//     в самом вызове составным литералом (`AccessMode: pgx.ReadOnly` либо
//     `ReadOnly: true`);
//   - W2 — `Exec`, `Query`, `QueryRow` на таком получателе, чей текст оператора
//     (значение константы, вычисленное проверкой типов) пишет журналируемую
//     таблицу: неявная транзакция одиночного оператора инициатора не несёт;
//   - W3 — тот же вызов, чей текст не константа: судить его нечем, и он
//     перечисляется, а не прощается;
//   - W1 в форме функции — `pgx.BeginFunc` и `pgx.BeginTxFunc`, которым такой
//     получатель передан доводом: та же транзакция, иная форма записи;
//   - W4 — чужой открывающий: функция пакета вне модуля, открывающая пишущую
//     транзакцию на переданном ей пуле (`corelib/db.NewTransactor`). Открытие
//     живёт в чужом пакете и в дереве службы не видно ни одной из форм выше;
//     этой формой посев модулей писал журнал без инициатора (kaname#484).
//
// Перечень журналируемых таблиц ВЫВОДИТСЯ из цепи миграций — таблицы, на
// которых живёт триггер функции `resource_journal_emit*` (созданный и не
// снятый), — а не выписывается здесь.
//
// # Чего разбор НЕ видит — названо
//
//   - записи функцией базы, вызванной оператором `SELECT f(…)` пулом: текст не
//     называет таблицу;
//   - каскада удаления в журналируемую таблицу из оператора над другой
//     таблицей пулом мимо транзакции;
//   - чужого пакета, открывающего транзакцию на переданном пуле, которого нет
//     в перечне [writeOpenerForeignOpeners]. Такие передачи пересчитываются
//     (`передач пула чужому пакету`), а не прощаются молча. На ревизии этой
//     правки их 16: наблюдаемость пула и очередей, ворота числа соединений и
//     версии схемы, хранилище и сверщик операций, отправщик аудита, повторная
//     отправка и очистка очереди отношений, очистка ресурсного журнала, чтение
//     состояния потолков. Пишут они операции, аудит, очередь отношений и сам
//     журнал (удалением); журналируемых таблиц среди них нет.
package check

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// WriteOpenerFile — файл единственного открывающего, от корня модуля.
const WriteOpenerFile = "internal/journalwrite/journalwrite.go"

// writeOpenerStarterTypes — типы получателя, у которых открытие транзакции и
// одиночный оператор — предмет гейта.
var writeOpenerStarterTypes = map[string]bool{
	"*github.com/jackc/pgx/v5/pgxpool.Pool": true,
	"*github.com/jackc/pgx/v5/pgxpool.Conn": true,
	"*github.com/jackc/pgx/v5.Conn":         true,
	"*database/sql.DB":                      true,
	"*database/sql.Conn":                    true,
}

// modulePath — путь модуля службы: функция пакета вне него — чужая.
const modulePath = "github.com/PRO-Robotech/kaname"

// writeOpenerFuncBegins — функции пакета pgx, открывающие транзакцию на
// переданном получателе (W1 в форме функции).
var writeOpenerFuncBegins = map[string]bool{
	"github.com/jackc/pgx/v5.BeginFunc":   true,
	"github.com/jackc/pgx/v5.BeginTxFunc": true,
}

// writeOpenerForeignOpeners — функции чужих пакетов, открывающие ПИШУЩУЮ
// транзакцию на переданном пуле (W4).
var writeOpenerForeignOpeners = map[string]bool{
	"github.com/PRO-Robotech/corelib/db.NewTransactor": true,
}

var (
	writeOpenerBeginMethods = map[string]bool{"Begin": true, "BeginTx": true, "BeginFunc": true, "BeginTxFunc": true}
	writeOpenerStmtMethods  = map[string]bool{"Exec": true, "Query": true, "QueryRow": true,
		"ExecContext": true, "QueryContext": true, "QueryRowContext": true}
)

// WriteOpenerSite — координата находки.
type WriteOpenerSite struct {
	File   string
	Line   int
	Rule   string // W1 | W2 | W3
	Method string
	What   string
}

func (s WriteOpenerSite) String() string {
	return fmt.Sprintf("%s %s:%d %s — %s", s.Rule, s.File, s.Line, s.Method, s.What)
}

// WriteOpenerCensus — объём осмотренного.
type WriteOpenerCensus struct {
	Packages       int
	Files          int
	StarterCalls   int // вызовов на типах-получателях: методов и функций-открывающих
	BeginCalls     int
	ReadOnlyBegins int
	OpenerBegins   int // открытий внутри файла открывающего (помощником и источником)
	StmtCalls      int
	JudgedStmts    int // с константным текстом
	// ForeignHandoffs — передач пула или соединения функции чужого пакета,
	// не названной ни открывающей, ни чужим открывающим: зона, которую разбор
	// не судит, — числом.
	ForeignHandoffs int
	JournaledTables []string
}

func (c WriteOpenerCensus) String() string {
	return fmt.Sprintf("пакетов %d · файлов %d · вызовов на пуле/соединении %d "+
		"(открытий %d, из них читающих %d, в открывающем %d; операторов %d, "+
		"с константным текстом %d) · передач пула чужому пакету %d · журналируемых таблиц %d [%s]",
		c.Packages, c.Files, c.StarterCalls, c.BeginCalls, c.ReadOnlyBegins, c.OpenerBegins,
		c.StmtCalls, c.JudgedStmts, c.ForeignHandoffs, len(c.JournaledTables), strings.Join(c.JournaledTables, ", "))
}

// journalTriggerCreateRe / journalTriggerDropRe — триггер функции журнала на
// таблице схемы службы.
var (
	journalTriggerCreateRe = regexp.MustCompile(
		`(?is)CREATE\s+TRIGGER\s+(\w+)\s+[^;]*?\bON\s+kaname\.(\w+)[^;]*?EXECUTE\s+FUNCTION\s+kaname\.resource_journal_emit\w*\s*\(`)
	journalTriggerDropRe = regexp.MustCompile(`(?i)DROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?(\w+)\s+ON\s+kaname\.(\w+)`)
)

// JournaledTables выводит перечень журналируемых таблиц из цепи миграций:
// триггер функции журнала, созданный и не снятый позже. Возвращает и число
// прочитанных файлов миграций.
//
// Файлы цепи читаются через корень каталога (os.Root): файл, уводящий чтение
// за каталог миграций (символическая ссылка наружу), отвергается ошибкой.
func JournaledTables(migrationsDir string) (_ []string, _ int, err error) {
	root, err := os.OpenRoot(migrationsDir)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if cerr := root.Close(); err == nil {
			err = cerr
		}
	}()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, 0, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)         // порядок применения цепи — порядок имён
	live := map[string]string{} // триггер → таблица
	for _, n := range names {
		b, err := root.ReadFile(n)
		if err != nil {
			return nil, 0, err
		}
		// Прямой ход без комментариев: триггер, названный в комментарии или
		// в откате, живым не является.
		up := migrations.MigrationUpSection(string(b))
		for _, m := range journalTriggerCreateRe.FindAllStringSubmatch(up, -1) {
			live[m[1]] = m[2]
		}
		for _, m := range journalTriggerDropRe.FindAllStringSubmatch(up, -1) {
			if live[m[1]] == m[2] {
				delete(live, m[1])
			}
		}
	}
	set := map[string]bool{}
	for _, t := range live {
		set[t] = true
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, len(names), nil
}

// journaledWriteRe — оператор записи в одну из таблиц.
func journaledWriteRe(tables []string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)\b(?:insert\s+into|update|delete\s+from|merge\s+into)\s+(?:kaname\.)?(?:` +
		strings.Join(tables, "|") + `)\b`)
}

// ScanWriteOpeners разбирает пакеты `patterns` модуля `root` с типами.
// `overlay` — синтетические файлы проб инъекции (путь → содержимое).
func ScanWriteOpeners(root string, patterns []string, tables []string, overlay map[string][]byte) ([]WriteOpenerSite, WriteOpenerCensus, error) {
	census := WriteOpenerCensus{JournaledTables: tables}
	if len(tables) == 0 {
		return nil, census, fmt.Errorf("перечень журналируемых таблиц пуст: судить запись нечем")
	}
	writeRe := journaledWriteRe(tables)
	cfg := &packages.Config{
		Mode:    packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:     root,
		Overlay: overlay,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, census, err
	}
	opener := filepath.Join(root, filepath.FromSlash(WriteOpenerFile))
	var sites []WriteOpenerSite
	var loadErrs []string
	for _, p := range pkgs {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	}
	if len(loadErrs) > 0 {
		return nil, census, fmt.Errorf("пакеты не разобраны: %s", strings.Join(loadErrs, "; "))
	}
	for _, p := range pkgs {
		census.Packages++
		assigns := writeOpenerAssignments(p)
		for i, f := range p.Syntax {
			path := p.CompiledGoFiles[i]
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "internal/testsupport/") {
				continue
			}
			census.Files++
			inOpener := path == opener
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if inOpener {
					// Открытие помощником фундамента либо источником, которому
					// он передан: оба — открытия ОТКРЫВАЮЩЕГО.
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "journaltx" && sel.Sel.Name == "Begin" {
						census.OpenerBegins++
					}
					if sel.Sel.Name == "BeginTx" {
						census.OpenerBegins++
					}
				}
				if fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func); ok && fn.Pkg() != nil {
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil {
						writeOpenerJudgeFunc(p, call, fn, rel, inOpener, &census, &sites)
						return true
					}
				}
				isBegin := writeOpenerBeginMethods[sel.Sel.Name]
				isStmt := writeOpenerStmtMethods[sel.Sel.Name]
				if !isBegin && !isStmt {
					return true
				}
				tv, ok := p.TypesInfo.Types[sel.X]
				if !ok || !writeOpenerStarterTypes[types.TypeString(tv.Type, nil)] {
					return true
				}
				census.StarterCalls++
				pos := p.Fset.Position(call.Pos())
				site := WriteOpenerSite{File: rel, Line: pos.Line, Method: sel.Sel.Name}
				if isBegin {
					census.BeginCalls++
					if inOpener {
						return true
					}
					if writeOpenerReadOnly(call) {
						census.ReadOnlyBegins++
						return true
					}
					site.Rule = "W1"
					site.What = "пишущая транзакция открыта мимо открывающего " + WriteOpenerFile +
						": инициатора журнала она не выставляет и наследует настройку соединения"
					sites = append(sites, site)
					return true
				}
				census.StmtCalls++
				sqlArg := writeOpenerSQLArg(call)
				if sqlArg == nil {
					return true
				}
				text, ok := writeOpenerSQLText(p.TypesInfo, assigns, sqlArg)
				if !ok {
					site.Rule = "W3"
					site.What = "текст оператора на пуле не выводится из констант — пишет ли он журналируемую таблицу, не судимо"
					sites = append(sites, site)
					return true
				}
				census.JudgedStmts++
				if m := writeRe.FindString(text); m != "" {
					site.Rule = "W2"
					site.What = fmt.Sprintf("оператор %q пишет журналируемую таблицу пулом мимо пишущей транзакции", strings.Join(strings.Fields(m), " "))
					sites = append(sites, site)
				}
				return true
			})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, census, nil
}

// writeOpenerJudgeFunc судит вызов функции ПАКЕТА (не метода), которой
// передан получатель-пул или соединение: открытие в форме функции pgx (W1),
// чужой открывающий (W4), иначе — передача чужому пакету, пересчитанная.
// Функции модуля службы не судятся здесь: их тела разбираются сами.
func writeOpenerJudgeFunc(p *packages.Package, call *ast.CallExpr, fn *types.Func, rel string,
	inOpener bool, census *WriteOpenerCensus, sites *[]WriteOpenerSite) {
	starter := false
	for _, a := range call.Args {
		if tv, ok := p.TypesInfo.Types[a]; ok && writeOpenerStarterTypes[types.TypeString(tv.Type, nil)] {
			starter = true
			break
		}
	}
	if !starter {
		return
	}
	full := fn.Pkg().Path() + "." + fn.Name()
	pos := p.Fset.Position(call.Pos())
	site := WriteOpenerSite{File: rel, Line: pos.Line, Method: fn.Name()}
	switch {
	case writeOpenerFuncBegins[full]:
		census.StarterCalls++
		census.BeginCalls++
		if inOpener {
			return
		}
		if writeOpenerReadOnly(call) {
			census.ReadOnlyBegins++
			return
		}
		site.Rule = "W1"
		site.What = "пишущая транзакция открыта функцией pgx мимо открывающего " + WriteOpenerFile +
			": инициатора журнала она не выставляет и наследует настройку соединения"
		*sites = append(*sites, site)
	case writeOpenerForeignOpeners[full]:
		census.StarterCalls++
		site.Rule = "W4"
		site.What = "пул передан чужому открывающему " + full +
			": его транзакция открыта мимо " + WriteOpenerFile + " и инициатора журнала не выставляет"
		*sites = append(*sites, site)
	case fn.Pkg().Path() != modulePath && !strings.HasPrefix(fn.Pkg().Path(), modulePath+"/"):
		census.ForeignHandoffs++
	}
}

// writeOpenerSQLText — текст оператора, выведенный из констант: значение
// константного выражения; формат `fmt.Sprintf` с константной строкой формата
// (подставляемое — перечни колонок и условия, а имя таблицы стоит в формате);
// сцепление `+`, где неконстантные части заменены пробелом. Иное — не судимо.
func writeOpenerSQLText(info *types.Info, assigns map[types.Object][]ast.Expr, e ast.Expr) (string, bool) {
	return writeOpenerSQLTextDepth(info, assigns, e, 0)
}

func writeOpenerSQLTextDepth(info *types.Info, assigns map[types.Object][]ast.Expr, e ast.Expr, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	if tv, ok := info.Types[e]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return constant.StringVal(tv.Value), true
	}
	switch v := e.(type) {
	case *ast.Ident, *ast.SelectorExpr:
		// Переменная, параметр или поле: судятся ВСЕ значения, которые ей
		// даёт пакет; хоть одно не выводится — не судимо всё.
		var obj types.Object
		if id, ok := v.(*ast.Ident); ok {
			obj = info.Uses[id]
		} else {
			obj = info.Uses[v.(*ast.SelectorExpr).Sel]
		}
		rhs := assigns[obj]
		if len(rhs) == 0 {
			return "", false
		}
		parts := make([]string, 0, len(rhs))
		for _, r := range rhs {
			t, ok := writeOpenerSQLTextDepth(info, assigns, r, depth+1)
			if !ok {
				return "", false
			}
			parts = append(parts, t)
		}
		return strings.Join(parts, " ; "), true
	case *ast.ParenExpr:
		return writeOpenerSQLTextDepth(info, assigns, v.X, depth+1)
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Sprintf" && len(v.Args) > 0 {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
				return writeOpenerSQLTextDepth(info, assigns, v.Args[0], depth+1)
			}
		}
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, lok := writeOpenerSQLTextDepth(info, assigns, v.X, depth+1)
		r, rok := writeOpenerSQLTextDepth(info, assigns, v.Y, depth+1)
		if !lok && !rok {
			return "", false
		}
		return l + " " + r, true
	}
	return "", false
}

// writeOpenerAssignments — значения, которые пакет даёт переменной, полю или
// параметру: объявление со значением, `:=`, `=`; поле — элементом составного
// литерала; параметр — аргументом каждого вызова функции в пакете.
func writeOpenerAssignments(p *packages.Package) map[types.Object][]ast.Expr {
	out := map[types.Object][]ast.Expr{}
	for _, f := range p.Syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.ValueSpec:
				for i, name := range v.Names {
					if i < len(v.Values) {
						if obj := p.TypesInfo.Defs[name]; obj != nil {
							out[obj] = append(out[obj], v.Values[i])
						}
					}
				}
			case *ast.CompositeLit:
				var st *types.Struct
				if tv, ok := p.TypesInfo.Types[v]; ok {
					st, _ = tv.Type.Underlying().(*types.Struct)
				}
				for i, el := range v.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						// Позиционный литерал структуры: элемент i — поле i.
						if st != nil && i < st.NumFields() {
							out[st.Field(i)] = append(out[st.Field(i)], el)
						}
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok {
						if obj := p.TypesInfo.Uses[key]; obj != nil {
							out[obj] = append(out[obj], kv.Value)
						}
					}
				}
			case *ast.CallExpr:
				var fnID *ast.Ident
				switch f := v.Fun.(type) {
				case *ast.Ident:
					fnID = f
				case *ast.SelectorExpr:
					fnID = f.Sel
				}
				if fnID == nil {
					return true
				}
				fn, ok := p.TypesInfo.Uses[fnID].(*types.Func)
				if !ok {
					return true
				}
				sig, ok := fn.Type().(*types.Signature)
				if !ok || sig.Variadic() {
					return true
				}
				for i, a := range v.Args {
					if i < sig.Params().Len() {
						out[sig.Params().At(i)] = append(out[sig.Params().At(i)], a)
					}
				}
			case *ast.AssignStmt:
				if len(v.Lhs) != len(v.Rhs) {
					return true
				}
				for i, l := range v.Lhs {
					id, ok := l.(*ast.Ident)
					if !ok {
						continue
					}
					obj := p.TypesInfo.Defs[id]
					if obj == nil {
						obj = p.TypesInfo.Uses[id]
					}
					if obj != nil {
						out[obj] = append(out[obj], v.Rhs[i])
					}
				}
			}
			return true
		})
	}
	return out
}

// writeOpenerSQLArg — аргумент текста оператора: второй (после контекста).
func writeOpenerSQLArg(call *ast.CallExpr) ast.Expr {
	if len(call.Args) < 2 {
		return nil
	}
	return call.Args[1]
}

// writeOpenerReadOnly — параметры транзакции объявлены в вызове составным
// литералом, и режим доступа — только чтение.
func writeOpenerReadOnly(call *ast.CallExpr) bool {
	for _, a := range call.Args {
		lit, ok := a.(*ast.CompositeLit)
		if !ok {
			if u, ok := a.(*ast.UnaryExpr); ok && u.Op == token.AND {
				lit, ok = u.X.(*ast.CompositeLit)
				if !ok {
					continue
				}
			} else {
				continue
			}
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "AccessMode":
				if s, ok := kv.Value.(*ast.SelectorExpr); ok && s.Sel.Name == "ReadOnly" {
					return true
				}
			case "ReadOnly":
				if id, ok := kv.Value.(*ast.Ident); ok && id.Name == "true" {
					return true
				}
			}
		}
	}
	return false
}
