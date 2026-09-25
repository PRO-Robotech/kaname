// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_verdict_single_reader.go — «отозвано ли семейство выпуска» решает
// ОДИН читатель, и каждая поверхность предъявления спрашивает его через ОДНО
// правило (задача PRO-Robotech/kaname#319, решение К10 вариант А).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ И ПОЧЕМУ ОН ГЕЙТ, А НЕ ВНИМАНИЕ
//
// Решение о доступе по семейству принимают три поверхности: `IsRevoked`
// службы отзыва, авторитет отзыва на внутреннем слушателе и читатель
// предъявленного на публичном. Одно решение держится одним читателем только
// тогда, когда второго написания нет нигде:
//
//   - оператор, читающий запись выпуска, — ОДИН литерал в дереве. Второй
//     литерал (свой запрос у одной из поверхностей) разошёлся бы с первым молча
//     — например, забыв, что снятое семейство оставляет у записи ПУСТУЮ
//     живость, — и обе копии были бы зелены на своих пробах;
//   - порт чтения семейства зовёт ТОЛЬКО правило (`internal/tokenrevocation`).
//     Поверхность, позвавшая порт мимо правила, завела бы свою политику на
//     пустой идентификатор и на неответ хранилища;
//   - каждая поверхность ЗАКРЫТОГО перечня зовёт правило. Поверхность, правила
//     не зовущая, семейства не спрашивает вовсе;
//   - у решения нет ВТОРОГО ХРАНИЛИЩА. Правило читает утверждения токена, и
//     каждое прочитанное утверждение решено поимённо: ключ отсечки субъекта или
//     клиента либо идентификатор выпуска — единственный вход к записи выпуска.
//     Утверждение, несущее семейство, превратило бы отсечку по ключу во второе
//     хранилище решения о семействе со своим писателем и своей уборкой (К10,
//     вариант А: семейство судит только запись выпуска). Перечень сверяется в
//     обе стороны: решённое утверждение, которого правило больше не читает, —
//     тоже находка (правило без `jti` о семействе не спрашивает);
//   - у решения нет ПУСТОГО хранилища. Отсутствие записи правило читает как
//     «семейству не принадлежит», поэтому выпуск церемонии, не пишущий запись,
//     выпускает токен, который отзыв семейства не снимает. Реализация порта
//     выпуска фундамента (`IssueAccessToken` либо `StoreAccessToken` из
//     `corelib/oauthceremony`, порты есть с тега v1.10.0-rc.1) при нуле
//     вызовов писателя записи в дереве — находка. Реализаций на этой ревизии
//     ноль, и это законно: печатается переписью. Предпосылка оси — объявление
//     писателя в дереве: без него ось ослепла бы молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ УЗЕЛ РАЗОБРАННОГО ДЕРЕВА, А НЕ ТЕКСТ ФАЙЛА
//
// Литерал — узел `BasicLit`, вызов — узел `CallExpr`. Упоминание в комментарии
// (в том числе в этом) находкой не является.
//
// Читающим считается литерал, который ОТКРЫВАЕТСЯ словом `SELECT` либо `WITH`
// и называет таблицу выпусков. Вставка и уборка открываются иначе и читателями
// не считаются: у них другой предмет.
//
// Утверждение считается прочитанным правилом, когда в файле каталога правила
// индексируется параметр типа `jwt.MapClaims`: литералом, константой пакета
// либо переменной цикла по перечню-литералу пакета.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО
//
//  1. оператор, собранный из кусков во время исполнения: разбор читает
//     литерал, а не результат конкатенации. Довод держать оператор ОДНОЙ
//     константой, каким он и написан;
//  2. чтение таблицы выпусков ПОДЗАПРОСОМ внутри вставки, правки или удаления:
//     такой литерал открывается не словом чтения. В дереве таких нет;
//  3. вызов порта через переменную функционального типа (`f := r.FamilyRevoked`
//     без вызова на месте): узел вызова здесь другой. В дереве таких нет;
//  4. утверждение, прочитанное правилом не индексом параметра `jwt.MapClaims`:
//     методом (`GetIssuedAt` — момент выпуска, ключом не служит), через
//     переменную иного объявленного типа или через копию состава. Индекс, имя
//     которого разбор не разрешил, — находка, а не молчание;
//  5. второе хранилище семейства ВНЕ правила — поверхность, сама читающая
//     утверждение семейства и спрашивающая хранилище мимо правила. Его ловит
//     только ось «поверхность зовёт правило» и пробы поверхностей, а не эта;
//  6. что писатель позван ИМЕННО на пути выдачи и ДО ответа: ось судит, что
//     вызов в дереве есть, а порядок держит сквозная проба выпуска (kaname#396);
//  7. порт выпуска под другим именем метода: имена взяты из фундамента
//     (`corelib/oauthceremony`, порты есть с тега v1.10.0-rc.1), и
//     переименование там ослепило бы ось.
//
// Перечень границ, названный не полностью, хуже отсутствующего: он создаёт
// уверенность.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
)

// FamilyVerdictRulePackage — каталог правила отзыва, единственного вправе
// звать порт чтения семейства.
const FamilyVerdictRulePackage = "internal/tokenrevocation"

// familyVerdictRuleImport — путь импорта правила.
const familyVerdictRuleImport = "github.com/PRO-Robotech/kaname/internal/tokenrevocation"

// familyVerdictPortMethod — имя метода порта чтения семейства.
const familyVerdictPortMethod = "FamilyRevoked"

// familyVerdictRuleFuncs — функции правила, через которые поверхность
// спрашивает о семействе: общее правило отзыва и его половина по семейству.
var familyVerdictRuleFuncs = map[string]bool{"Revoked": true, "FamilyRevoked": true}

// issuanceTableMarkers — признаки таблицы выпусков в литерале. Имя
// принимается и со схемой, и без неё.
var issuanceTableMarkers = []string{"kaname.access_tokens", " access_tokens"}

// familyVerdictClaimDecisions — ЗАКРЫТЫЙ перечень утверждений, которые правило
// вправе читать, с решением по каждому. Утверждение, заведённое в правиле без
// записи здесь, — находка: оно могло бы нести семейство.
//
// #nosec G101 -- ключи — ИМЕНА утверждений токена (они же контракт подписанта
// и переименованию не подлежат), значения — проза решения для текста находки;
// ни одно не участвует в проверке подлинности.
var familyVerdictClaimDecisions = map[string]string{
	"sub":                  "ключ отсечки: субъект",
	"kaname_user_token_id": "ключ отсечки: клиент пользовательского токена",
	"kaname_sa_key_id":     "ключ отсечки: клиент ключа служебной учётки",
	"jti":                  "идентификатор выпуска: единственный вход к записи выпуска",
}

// issuanceWriterMethod — писатель записи выпуска: идентификатор выпуска →
// семейство.
const issuanceWriterMethod = "RecordAccessToken"

// issuancePortMethods — методы портов выпуска фундамента
// (`corelib/oauthceremony` с тега v1.10.0-rc.1:
// `AccessTokenIssuer.IssueAccessToken`, `AccessTokenVault.StoreAccessToken`),
// реализация которых выпускает либо кладёт токен доступа церемонии.
var issuancePortMethods = map[string]bool{"IssueAccessToken": true, "StoreAccessToken": true}

// FamilyVerdictSite — координата находки или узла переписи.
type FamilyVerdictSite struct {
	File string
	Line int
}

// FamilyVerdictCensus — перепись обхода. Объём осмотренного печатается:
// «находок ноль» без него неотличимо от «не смотрели».
type FamilyVerdictCensus struct {
	FilesParsed  int
	LiteralsSeen int
	CallsSeen    int
	// Readers — литералы, читающие таблицу выпусков.
	Readers []FamilyVerdictSite
	// Bypasses — вызовы порта чтения семейства вне правила.
	Bypasses []FamilyVerdictSite
	// RuleCallers — каталоги, чьи файлы зовут правило.
	RuleCallers map[string]bool
	// ClaimsRead — утверждения, которые правило читает: имя → первая координата.
	ClaimsRead map[string]FamilyVerdictSite
	// UnresolvedClaims — индексы состава в правиле, имени которых разбор не
	// разрешил.
	UnresolvedClaims []FamilyVerdictSite
	// IssuancePorts — не-тестовые реализации порта выпуска.
	IssuancePorts []FamilyVerdictSite
	// WriterDecls — объявления писателя записи выпуска.
	WriterDecls []FamilyVerdictSite
	// WriterCalls — вызовы писателя записи выпуска.
	WriterCalls []FamilyVerdictSite
}

// FamilyVerdict разбирает названные непроверочные файлы (путь относительно
// корня модуля → исходник) и переписывает читателей семейства.
func FamilyVerdict(files map[string]string) (FamilyVerdictCensus, error) {
	out := FamilyVerdictCensus{RuleCallers: map[string]bool{}, ClaimsRead: map[string]FamilyVerdictSite{}}
	fset := token.NewFileSet()

	var parsedRule []ruleFile
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		f, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			return out, fmt.Errorf("разбор %s: %w", name, err)
		}
		out.FilesParsed++
		inRule := path.Dir(name) == FamilyVerdictRulePackage
		ruleName := localImportName(f, familyVerdictRuleImport, "tokenrevocation")
		recordIssuanceDecls(fset, name, f, &out)
		if inRule {
			parsedRule = append(parsedRule, ruleFile{name: name, file: f})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				out.LiteralsSeen++
				text, uerr := strconv.Unquote(node.Value)
				if uerr != nil {
					text = node.Value
				}
				if readsIssuances(text) {
					out.Readers = append(out.Readers, FamilyVerdictSite{
						File: name, Line: fset.Position(node.Pos()).Line,
					})
				}
			case *ast.CallExpr:
				out.CallsSeen++
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == issuanceWriterMethod {
					out.WriterCalls = append(out.WriterCalls, FamilyVerdictSite{
						File: name, Line: fset.Position(node.Pos()).Line,
					})
				}
				if pkg, isIdent := sel.X.(*ast.Ident); isIdent && ruleName != "" && pkg.Name == ruleName {
					if familyVerdictRuleFuncs[sel.Sel.Name] {
						out.RuleCallers[path.Dir(name)] = true
					}
					return true
				}
				if sel.Sel.Name == familyVerdictPortMethod && !inRule {
					out.Bypasses = append(out.Bypasses, FamilyVerdictSite{
						File: name, Line: fset.Position(node.Pos()).Line,
					})
				}
			}
			return true
		})
	}
	censusRuleClaims(fset, parsedRule, &out)
	return out, nil
}

// FamilyVerdictFindings судит перепись против ЗАКРЫТОГО перечня поверхностей.
// Пусто — норма.
func FamilyVerdictFindings(c FamilyVerdictCensus, surfaces []string) []string {
	var found []string
	if c.FilesParsed == 0 {
		return []string{"обход дал ноль файлов: судить нечего — это «не смотрели», а не «чисто»"}
	}
	switch len(c.Readers) {
	case 0:
		found = append(found, "читателей записи выпуска НОЛЬ: ответа о семействе не из чего "+
			"взяться, либо оператор переименован или собран из кусков — гейт потерял предмет")
	case 1:
	default:
		var at []string
		for _, r := range c.Readers {
			at = append(at, fmt.Sprintf("%s:%d", r.File, r.Line))
		}
		found = append(found, fmt.Sprintf("читателей записи выпуска %d, а решение о семействе обязано "+
			"читаться ОДНИМ оператором — второе написание разойдётся с первым молча: %s",
			len(c.Readers), strings.Join(at, ", ")))
	}
	for _, b := range c.Bypasses {
		found = append(found, fmt.Sprintf("%s:%d: порт чтения семейства позван мимо правила %s — "+
			"у поверхности своя политика на пустой идентификатор и на неответ хранилища",
			b.File, b.Line, FamilyVerdictRulePackage))
	}
	for _, s := range surfaces {
		if !c.RuleCallers[s] {
			found = append(found, fmt.Sprintf("поверхность %s не зовёт правило отзыва: о семействе "+
				"выпуска она не спрашивает вовсе", s))
		}
	}
	found = append(found, claimFindings(c)...)
	found = append(found, issuanceFindings(c)...)
	return found
}

// claimFindings — ось «у решения нет второго хранилища».
func claimFindings(c FamilyVerdictCensus) []string {
	var found []string
	read := make([]string, 0, len(c.ClaimsRead))
	for claim := range c.ClaimsRead {
		read = append(read, claim)
	}
	sort.Strings(read)
	for _, claim := range read {
		if _, decided := familyVerdictClaimDecisions[claim]; !decided {
			at := c.ClaimsRead[claim]
			found = append(found, fmt.Sprintf("%s:%d: правило читает утверждение %q, решения о котором нет: "+
				"ключ отсечки, несущий семейство, — второе хранилище решения о семействе (К10, вариант А: "+
				"семейство судит только запись выпуска по jti). Решение — в перечне гейта",
				at.File, at.Line, claim))
		}
	}
	for _, u := range c.UnresolvedClaims {
		found = append(found, fmt.Sprintf("%s:%d: правило читает утверждение, имени которого разбор не "+
			"разрешил: решено ли оно, сказать нельзя", u.File, u.Line))
	}
	decided := make([]string, 0, len(familyVerdictClaimDecisions))
	for claim := range familyVerdictClaimDecisions {
		decided = append(decided, claim)
	}
	sort.Strings(decided)
	for _, claim := range decided {
		if _, ok := c.ClaimsRead[claim]; !ok {
			found = append(found, fmt.Sprintf("перечень решений называет утверждение %q (%s), которого "+
				"правило не читает: либо правило потеряло вопрос, либо перечень пережил свой предмет",
				claim, familyVerdictClaimDecisions[claim]))
		}
	}
	return found
}

// issuanceFindings — ось «у решения нет пустого хранилища».
func issuanceFindings(c FamilyVerdictCensus) []string {
	var found []string
	if len(c.WriterDecls) == 0 {
		found = append(found, fmt.Sprintf("объявления писателя записи выпуска %s в дереве нет: ось «выпуск "+
			"пишет запись» потеряла предмет", issuanceWriterMethod))
	}
	if len(c.WriterCalls) == 0 {
		for _, p := range c.IssuancePorts {
			found = append(found, fmt.Sprintf("%s:%d: реализация порта выпуска при нуле вызовов %s в дереве: "+
				"токен без записи выпуска правило читает как «семейству не принадлежит», и отзыв семейства "+
				"его не снимает", p.File, p.Line, issuanceWriterMethod))
		}
	}
	return found
}

// recordIssuanceDecls переписывает объявления писателя записи и реализации
// порта выпуска в файле.
func recordIssuanceDecls(fset *token.FileSet, name string, f *ast.File, out *FamilyVerdictCensus) {
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		site := FamilyVerdictSite{File: name, Line: fset.Position(fn.Pos()).Line}
		switch {
		case fn.Name.Name == issuanceWriterMethod:
			out.WriterDecls = append(out.WriterDecls, site)
		case issuancePortMethods[fn.Name.Name]:
			out.IssuancePorts = append(out.IssuancePorts, site)
		}
	}
}

// ruleFile — разобранный файл каталога правила.
type ruleFile struct {
	name string
	file *ast.File
}

// censusRuleClaims переписывает утверждения, которые читает правило.
//
// Имена разрешаются по объявлениям уровня пакета во ВСЕХ файлах каталога
// правила: строковые константы и перечни-литералы строк.
func censusRuleClaims(fset *token.FileSet, rule []ruleFile, out *FamilyVerdictCensus) {
	consts := map[string]string{}
	lists := map[string][]string{}
	for _, rf := range rule {
		for _, d := range rf.file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if v, ok := stringLit(vs.Values[i]); ok && gd.Tok == token.CONST {
						consts[id.Name] = v
					}
					if cl, ok := vs.Values[i].(*ast.CompositeLit); ok && gd.Tok == token.VAR {
						var elems []string
						for _, e := range cl.Elts {
							if v, ok := stringLit(e); ok {
								elems = append(elems, v)
							}
						}
						lists[id.Name] = elems
					}
				}
			}
		}
	}
	note := func(claim string, pos token.Pos, file string) {
		if _, seen := out.ClaimsRead[claim]; !seen {
			out.ClaimsRead[claim] = FamilyVerdictSite{File: file, Line: fset.Position(pos).Line}
		}
	}
	for _, rf := range rule {
		for _, d := range rf.file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			claimParams := mapClaimsParams(fn)
			if len(claimParams) == 0 {
				continue
			}
			loopLists := map[string][]string{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.RangeStmt:
					val, ok := node.Value.(*ast.Ident)
					over, isIdent := node.X.(*ast.Ident)
					if ok && isIdent {
						if elems, known := lists[over.Name]; known {
							loopLists[val.Name] = elems
						}
					}
				case *ast.IndexExpr:
					x, ok := node.X.(*ast.Ident)
					if !ok || !claimParams[x.Name] {
						return true
					}
					if v, ok := stringLit(node.Index); ok {
						note(v, node.Pos(), rf.name)
						return true
					}
					if id, ok := node.Index.(*ast.Ident); ok {
						if v, known := consts[id.Name]; known {
							note(v, node.Pos(), rf.name)
							return true
						}
						if elems, known := loopLists[id.Name]; known {
							for _, v := range elems {
								note(v, node.Pos(), rf.name)
							}
							return true
						}
					}
					out.UnresolvedClaims = append(out.UnresolvedClaims, FamilyVerdictSite{
						File: rf.name, Line: fset.Position(node.Pos()).Line,
					})
				}
				return true
			})
		}
	}
}

// mapClaimsParams — имена параметров функции объявленного типа `jwt.MapClaims`.
func mapClaimsParams(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	if fn.Type.Params == nil {
		return out
	}
	for _, field := range fn.Type.Params.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "MapClaims" {
			continue
		}
		for _, n := range field.Names {
			out[n.Name] = true
		}
	}
	return out
}

// stringLit — значение строкового литерала либо ложь.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// readsIssuances — открывается ли литерал словом чтения и называет ли он
// таблицу выпусков.
func readsIssuances(lit string) bool {
	head := strings.ToUpper(strings.TrimSpace(lit))
	if !strings.HasPrefix(head, "SELECT") && !strings.HasPrefix(head, "WITH") {
		return false
	}
	for _, m := range issuanceTableMarkers {
		if strings.Contains(lit, m) {
			return true
		}
	}
	return false
}
