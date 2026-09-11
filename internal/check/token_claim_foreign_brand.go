// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_foreign_brand.go — разбор ИМЁН КЛЕЙМ выпущенного токена: не
// называет ли клеймо, которое читает предъявитель токена БЕЗ нашего
// исходного кода, чужой платформенный бренд (порт, СУЖЕННЫЙ ДО ОСИ А, с
// монорепо `internal/repohygiene/tokenclaimforeignbrand.go`, снят вынесением
// службы доступа — `kacho#2597`; задача продукта #2127, семейство приёмки
// IAM-SEV-NAME-05).
//
// # Предмет
//
// Служба — самостоятельный продукт, ставящийся в чужом облаке. Норма
// разделения (решение владельца, kacho#2076): продукт наследует КОД, но не
// ИМЯ. Имя клейма читается оператором чужого облака без нашего исходного
// кода — достаточно раскодировать токен, — поэтому приставка имени клейма
// есть идентичность, а не код. Свой словарь — `kaname_`; чужой,
// платформенный — `kacho_`. `internal/domain/principal_claims.go` уже несёт
// три клейма формы `kaname_*` — предмет живой, не гипотетический.
//
// # Что здесь ПОРТИРОВАНО (ось А), а что НЕТ (ось Б) — сказано прямо
//
// Монорепошный предок судил ДВЕ оси: А — имя клейма принадлежит своему
// словарю; Б — у имени из своего словаря нет двойника в чужом словаре НИГДЕ
// в отслеживаемом дереве, включая не-Go текст (посевные наборы, профиль
// развёртывания, собранные коллекции проб, клиентская страница). Здесь
// перенесена ТОЛЬКО ось А — разбор Go-кода по четырём позициям чеканки и
// чтения. Ось Б требует единого свода дерева kaname И его нынешних потребителей
// (документация арендатора, коллекции проб), который на дату переноса не
// собран в одном месте; расширение до неё — отдельная работа, не сделанная
// здесь умышленно, а не забытая молча.
//
// # Позиции, которые СУДЯТСЯ (перенесены дословно)
//
//	claims := map[string]any{"kacho_user_id": …}     ← ключ состава
//	pt, _ := claims["kacho_principal_type"].(string) ← чтение по имени
//	case "kacho_mfa_at":                             ← разбор по имени
//	verifiedClaim(vt, "kacho_principal_type")        ← имя передано вызовом
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. имя клейма, собранное из частей либо взятое переменной;
//  2. приставка, отданная предикату (`strings.HasPrefix(k, "kacho_")`) — ось
//     Б предка ловила и её; здесь эта форма вне наблюдения;
//  3. не-Go текст.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// TokenClaimOwnNamespace / TokenClaimForeignNamespace — свой и чужой словарь.
const (
	TokenClaimOwnNamespace     = "kaname"
	TokenClaimForeignNamespace = "kacho"
)

// tokenClaimNameShape — форма имени клейма: словарь, подчёркивание, тело.
var tokenClaimNameShape = regexp.MustCompile(`^([a-z]+)_([a-z0-9_]+)$`)

// TokenClaimForm — в какой позиции стоит имя.
type TokenClaimForm string

const (
	TokenClaimFormKey   TokenClaimForm = "ключ состава"
	TokenClaimFormRead  TokenClaimForm = "чтение по имени"
	TokenClaimFormCase  TokenClaimForm = "разбор по имени"
	TokenClaimFormArg   TokenClaimForm = "имя в вызове"
	TokenClaimFormConst TokenClaimForm = "объявление константы"
)

// TokenClaimUse — одно употребление имени клейма чужого словаря.
type TokenClaimUse struct {
	File      string
	Line      int
	Func      string
	Namespace string
	Name      string
	Form      TokenClaimForm
}

// TokenClaimCensus — объём осмотренного одним файлом.
type TokenClaimCensus struct {
	Literals  int
	Shaped    int
	Positions int
}

// ScanTokenClaimForeignBrand разбирает один файл Go и возвращает употребления
// имени клейма из ЧУЖОГО словаря (namespace == TokenClaimForeignNamespace) в
// одной из четырёх законных позиций чеканки/чтения.
func ScanTokenClaimForeignBrand(path string, src []byte) ([]TokenClaimUse, TokenClaimCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, TokenClaimCensus{}, err
	}
	census := TokenClaimCensus{}
	var out []TokenClaimUse

	positions := map[*ast.BasicLit]TokenClaimForm{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			mt, ok := node.Type.(*ast.MapType)
			if !ok {
				return true
			}
			if id, ok := mt.Key.(*ast.Ident); !ok || id.Name != "string" {
				return true
			}
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					positions[lit] = TokenClaimFormKey
				}
			}
		case *ast.IndexExpr:
			if lit, ok := node.Index.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				positions[lit] = TokenClaimFormRead
			}
		case *ast.CaseClause:
			for _, e := range node.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					positions[lit] = TokenClaimFormCase
				}
			}
		case *ast.ValueSpec:
			// Сужение против ложного срабатывания, измеренное на дереве
			// kaname: константа с формой словаря есть и у ДРУГИХ предметов
			// (имя схемы прежней установки — константа
			// `schemaOfThePreviousInstall` в `cmd/kaname/schema_guard.go`;
			// её значение здесь намеренно не выписывается — отставленное имя
			// схемы в дереве стережёт свой гейт), а не только у
			// клейма. Объявление константы считается позицией клейма ТОЛЬКО
			// когда идентификатор Go называет её клеймом — как
			// `ClaimPrincipalType` в `internal/domain/principal_claims.go`.
			// Без этого сужения гейт был бы красным на верном коде с первого
			// прогона — а первый ложный срабат отключает гейт навсегда.
			for i, v := range node.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if i >= len(node.Names) || !strings.Contains(strings.ToLower(node.Names[i].Name), "claim") {
					continue
				}
				positions[lit] = TokenClaimFormConst
			}
		case *ast.CallExpr:
			for _, a := range node.Args {
				lit, ok := a.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if _, taken := positions[lit]; !taken {
					positions[lit] = TokenClaimFormArg
				}
			}
		}
		return true
	})

	type fnSpan struct {
		from, to token.Pos
		name     string
	}
	var spans []fnSpan
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = tokenClaimRecvName(fn.Recv.List[0].Type) + "." + name
		}
		spans = append(spans, fnSpan{fn.Pos(), fn.End(), name})
	}
	enclosing := func(p token.Pos) string {
		for _, s := range spans {
			if p >= s.from && p < s.to {
				return s.name
			}
		}
		return "уровень пакета"
	}

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		census.Literals++
		v, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		m := tokenClaimNameShape.FindStringSubmatch(v)
		if m == nil || m[1] != TokenClaimForeignNamespace {
			return true
		}
		census.Shaped++
		form, stands := positions[lit]
		if !stands {
			return true
		}
		census.Positions++
		out = append(out, TokenClaimUse{
			File: path, Line: fset.Position(lit.Pos()).Line, Func: enclosing(lit.Pos()),
			Namespace: m[1], Name: v, Form: form,
		})
		return true
	})
	return out, census, nil
}

func tokenClaimRecvName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return tokenClaimRecvName(t.X)
	default:
		return ""
	}
}
