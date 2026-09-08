// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus

// index.go — разбор одного обслуживающего пакета и обход его вызовов.
//
// # Почему обход, а не чтение файла обработчика
//
// Вопрос о доступе задаёт не транспортный метод, а use-case, который он зовёт:
// у проекта дверь стоит в GetProjectUseCase.Execute, а обработчик — три строки
// переадресации. Проверка, читающая только тело обработчика, объявила бы дырой
// каждый RPC, чья дверь стоит там, где ей и положено стоять по раскладке слоёв.
//
// # Почему обход внутрипакетный, а не сквозной
//
// Обработчик и его use-case лежат в ОДНОМ пакете (api/project несёт и
// handler.go, и get.go) — это раскладка, а не совпадение. Поэтому обхода внутри
// пакета достаточно, а полный граф по модулю потребовал бы проверки типов всего
// дерева и своей зависимости. Граница названа честно: вопрос, вынесенный в
// сосед­ний пакет и не помеченный здесь, уйдёт в «не разрешилось» — третью
// категорию, — а не в норму и не в находку.
//
// # Приёмник разрешается по ТИПУ, а не по имени поля
//
// Имя поля `get` встречается в нескольких структурах пакета, и общий словарь
// «поле → тип» склеил бы разные use-case'ы. Приёмник берётся у объявления
// метода (`func (h *Handler) …` → Handler), поэтому `h.get` разрешается в поле
// ИМЕННО Handler'а.
//
// # Локальная переменная — тоже приёмник, и её тип берётся из объявления
//
// Вопрос о доступе зовут и через локальную переменную пакетного типа
// (`authority := &pageAuthority{…}` → `authority.verdict(…)`). Записи
// `u.Метод(…)` и `v.Метод(…)` синтаксически неразличимы, поэтому тип получателя
// решает `localVarTypes`: имя, объявленное в теле, принадлежит ЕЙ, и откат к
// приёмнику по совпадению имени метода не допускается. Подробности и цена
// незнания этой формы — у `resolveCall`.

import (
	"go/ast"
	"go/token"
	"strings"
)

// pkgIndex — разобранный обслуживающий пакет.
type pkgIndex struct {
	// funcs — функции уровня пакета по имени.
	funcs map[string]*ast.FuncDecl
	// methods — методы по ключу «Тип.Метод».
	methods map[string]*ast.FuncDecl
	// fields — поля структур: «Тип.поле» → имя типа поля (без указателя и пакета).
	fields map[string]string
	// handlerTypes — типы, на которых висят методы, названные как RPC. Обычно
	// один Handler; перечень выведен, а не выписан, потому что у части служб
	// обработчик назван иначе.
	handlerTypes map[string]bool
}

// indexPackage разбирает каталог пакета и возвращает индекс и число
// разобранных не-тестовых файлов.
func indexPackage(dir string) (*pkgIndex, int, error) {
	fset := token.NewFileSet()
	parsed, err := parseDirFiles(fset, dir)
	if err != nil {
		return nil, 0, err
	}
	idx := &pkgIndex{
		funcs:        map[string]*ast.FuncDecl{},
		methods:      map[string]*ast.FuncDecl{},
		fields:       map[string]string{},
		handlerTypes: map[string]bool{},
	}
	files := 0
	for _, f := range parsed {
		files++
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					idx.funcs[d.Name.Name] = d
					continue
				}
				recv, ok := receiverType(d.Recv.List[0].Type)
				if !ok {
					continue
				}
				idx.methods[recv+"."+d.Name.Name] = d
				if strings.Contains(recv, "Handler") {
					idx.handlerTypes[recv] = true
				}
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, isTS := spec.(*ast.TypeSpec)
					if !isTS {
						continue
					}
					st, isStruct := ts.Type.(*ast.StructType)
					if !isStruct {
						continue
					}
					for _, field := range st.Fields.List {
						typeName, okT := bareTypeName(field.Type)
						if !okT {
							continue
						}
						for _, nm := range field.Names {
							idx.fields[ts.Name.Name+"."+nm.Name] = typeName
						}
					}
				}
			}
		}
	}
	return idx, files, nil
}

// narrowsPage отвечает, сужает ли путь обслуживания страницу построчно.
//
// Спрашивается ТОЛЬКО у полосы `scope_filtered`: там дверь единичного вопроса
// не задаёт намеренно, и авторизация принадлежит обработчику.
//
// Второй результат — разрешился ли метод вообще. false означает «не
// выполнилось»: метода с таким именем на обработчике нет, и утверждать по нему
// что-либо нельзя ни в одну сторону — ни что дверь есть, ни что её нет.
func (p *pkgIndex) narrowsPage(rpcMethod string) (string, bool) {
	return p.findOnServingPath(rpcMethod, pageNarrowingMatcher)
}

// findOnServingPath ищет на пути обслуживания RPC вызов, который распознаёт
// matcher, и возвращает его свидетельство.
//
// Второй результат — разрешился ли метод вообще. false означает «не
// выполнилось»: метода с таким именем на обработчике нет, и утверждать по нему
// нельзя ничего ни в одну сторону.
func (p *pkgIndex) findOnServingPath(rpcMethod string, m callMatcher) (string, bool) {
	var entry *ast.FuncDecl
	var recv string
	for t := range p.handlerTypes {
		if fn, ok := p.methods[t+"."+rpcMethod]; ok {
			entry, recv = fn, t
			break
		}
	}
	if entry == nil {
		return "", false
	}
	return p.walk(entry, recv, map[token.Pos]bool{}, 0, m), true
}

// callMatcher — распознаватель одного вызова. Пустая строка означает «это не
// то, что я ищу»; непустая — свидетельство, которое уедет в перепись.
//
// Параметр, а не зашитый перечень: обходов по пути обслуживания ДВА и они
// спрашивают РАЗНОЕ — сужается ли страница построчно (полоса данных) и есть ли
// решатель доступа (полоса освобождённых). Общий обход с двумя перечнями внутри
// склеил бы два вопроса в один, и свидетельство одного стало бы ответом на
// другой.
type callMatcher func(call *ast.CallExpr) string

// pageNarrowingMatcher — распознаватель сужения страницы построчно.
func pageNarrowingMatcher(call *ast.CallExpr) string {
	if name, isQualified := qualifiedCallName(call.Fun); isQualified {
		if form, hit := pageNarrowingCalls[name]; hit {
			return name + " (" + form + ")"
		}
	}
	// Третья форма: прямой вопрос к порту отношений.
	if isRelationPortQuestion(call) {
		return "порт отношений: Check(ctx, субъект, отношение, объект)"
	}
	return ""
}

// isRelationPortQuestion — вопрос к модели напрямую через порт отношений.
//
// Распознаётся ЧИСЛОМ АРГУМЕНТОВ, а не именем приёмника: имя поля у порта своё
// в каждом пакете, и перечень имён был бы тем местом, которое забывают
// дополнить.
func isRelationPortQuestion(call *ast.CallExpr) bool {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	return isSel && sel.Sel.Name == relationPortQuestion && len(call.Args) == relationPortArgs
}

const maxDepth = 12

// walk обходит тело функции и всё, что из неё достижимо внутри пакета, и
// возвращает имя найденного вызова сужения страницы. Пустая строка означает,
// что не найдено ни одного.
// ОБХОДА ЗАПОМИНАЕТ ОБЪЯВЛЕНИЕ, А НЕ ЕГО ИМЯ.
//
// Ключом посещённого была пара «приёмник.имя», и она СКЛЕИВАЛА функцию уровня
// пакета с одноимённым методом текущего приёмника: в этом дереве такая пара
// существует (`requireGrantAuthority` — и метод-переходник use-case'а, и
// функция пакета, которую он зовёт), поэтому обход входил в переходник, метил
// ключ и НЕ ВХОДИЛ в функцию, где и стоит вопрос к модели. Свидетельство
// терялось молча: гейт объявлял находкой RPC, у которого решатель есть.
//
// Позиция объявления уникальна by construction, поэтому склейки не бывает.
func (p *pkgIndex) walk(fn *ast.FuncDecl, recv string, seen map[token.Pos]bool, depth int, m callMatcher) string {
	if fn == nil || fn.Body == nil || depth > maxDepth {
		return ""
	}
	locals := localVarTypes(fn)
	evidence := ""
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if evidence != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ev := m(call); ev != "" {
			evidence = ev
			return false
		}
		if next, nrecv, okNext := p.resolveCall(call.Fun, recv, locals); okNext {
			key := next.Pos()
			if !seen[key] {
				seen[key] = true
				if ev := p.walk(next, nrecv, seen, depth+1, m); ev != "" {
					evidence = ev
					return false
				}
			}
		}
		return true
	})
	return evidence
}

// resolveCall разрешает вызов в объявление внутри пакета.
//
// Разбираются три формы, покрывающие раскладку слоёв этого дерева:
//
//	f(...)            — функция уровня пакета;
//	h.поле.Метод(...) — метод use-case'а, лежащего в поле приёмника;
//	v.Метод(...)      — метод приёмника ЛИБО метод локальной переменной
//	                    пакетного типа; какой именно, решает locals.
//
// ЛОКАЛЬНАЯ ПЕРЕМЕННАЯ — ТРЕТЬЯ ЗАКОННАЯ ФОРМА, И НЕЗНАНИЕ ЕЁ МОЛЧАЛИВО.
//
// Прежде обе записи `v.Метод(...)` разрешались ОДИНАКОВО — в метод приёмника, —
// поэтому вызов у локальной переменной пакетного типа не разрешался вовсе:
// метода с таким именем у приёмника нет, обход в него не входил, и всё, что за
// ним стояло, уходило из-под наблюдения. Не красное и не зелёное — молчание.
//
// Цена измерена: `ListByRole` спрашивал право построчно через функцию уровня
// пакета и распознавался («порт отношений: Check(…)»); правка стоимости
// страницы (#2054) собрала те же вопросы в памятку запроса и стала звать их
// методом ЛОКАЛЬНОЙ переменной — `authority.verdict(ctx, …)`. Код двери не
// потерял, а перепись объявила его находкой. Ложная находка обесценивает
// перепись целиком: инструмент, у которого находка не подтверждается, перестают
// читать.
//
// Приоритет у локальной переменной, и это анти-маска: если имя объявлено в
// теле, вызов принадлежит ЕЙ, а не приёмнику. Откат к приёмнику здесь означал
// бы, что метод чужого типа засчитывается по совпадению имени.
func (p *pkgIndex) resolveCall(fun ast.Expr, recv string, locals map[string]string) (*ast.FuncDecl, string, bool) {
	switch f := fun.(type) {
	case *ast.Ident:
		if fn, ok := p.funcs[f.Name]; ok {
			return fn, recv, true
		}
	case *ast.SelectorExpr:
		// h.поле.Метод(...)
		inner, ok := f.X.(*ast.SelectorExpr)
		if !ok {
			ident, isIdent := f.X.(*ast.Ident)
			if !isIdent {
				return nil, "", false
			}
			// v.Метод(...) — локальная переменная пакетного типа.
			if local, isLocal := locals[ident.Name]; isLocal && local != "" {
				if fn, hit := p.methods[local+"."+f.Sel.Name]; hit {
					return fn, local, true
				}
				// Тип известен, метода у него нет: вызов чужой, и приписывать
				// его приёмнику по совпадению имени нельзя.
				return nil, "", false
			}
			// приёмник.Метод(...) — метод того же типа.
			if recv != "" {
				if fn, hit := p.methods[recv+"."+f.Sel.Name]; hit {
					return fn, recv, true
				}
			}
			return nil, "", false
		}
		if _, isIdent := inner.X.(*ast.Ident); !isIdent {
			return nil, "", false
		}
		fieldType, hit := p.fields[recv+"."+inner.Sel.Name]
		if !hit {
			return nil, "", false
		}
		if fn, okM := p.methods[fieldType+"."+f.Sel.Name]; okM {
			return fn, fieldType, true
		}
	}
	return nil, "", false
}

// qualifiedCallName возвращает имя вида «пакет.Функция» для вызова через
// селектор пакета.
func qualifiedCallName(fun ast.Expr) (string, bool) {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name + "." + sel.Sel.Name, true
}

// receiverType достаёт имя типа приёмника из *T или T.
func receiverType(t ast.Expr) (string, bool) {
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	ident, ok := t.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// bareTypeName достаёт имя типа поля, снимая указатель. Типы из чужих пакетов
// (селектор) не возвращаются: их объявления в этом пакете нет, и обходить
// нечего.
func bareTypeName(t ast.Expr) (string, bool) {
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	ident, ok := t.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// localVarTypes — типы ЛОКАЛЬНЫХ переменных функции, объявленных так, что тип
// читается СИНТАКСИЧЕСКИ, без проверки типов всего дерева.
//
// Разбираются формы, которыми в этом дереве заводят значение пакетного типа:
//
//	v := &T{...}   v := T{...}   v := new(T)   var v T   var v *T
//
// Форма, о которой распознаватель не знает, даёт не красное и не зелёное, а
// молчание, поэтому граница названа честно: значение, полученное из вызова
// (`v := newAuthority()`), из поля или из аргумента, здесь НЕ разрешается —
// такой вызов остаётся неразрешённым ровно как прежде. Расширять перечень
// вперёд предмета нельзя: запас есть слепая зона, выданная авансом, и он не
// истечёт сам.
//
// НЕОДНОЗНАЧНОЕ ИМЯ СНИМАЕТСЯ, А НЕ УГАДЫВАЕТСЯ. Если одно имя связано в теле с
// РАЗНЫМИ типами (переприсваивание, затенение в блоке), значение становится
// пустым, и вызов через него не разрешается вовсе. Выбор «последнего» дал бы
// вердикт, зависящий от порядка обхода, — то есть неповторимый.
func localVarTypes(fn *ast.FuncDecl) map[string]string {
	out := map[string]string{}
	bind := func(name, typ string) {
		if name == "" || name == "_" || typ == "" {
			return
		}
		if prev, seen := out[name]; seen && prev != typ {
			out[name] = "" // неоднозначно — не разрешаем
			return
		}
		out[name] = typ
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok != token.DEFINE || len(s.Lhs) != len(s.Rhs) {
				return true
			}
			for i, lhs := range s.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				bind(ident.Name, localTypeOfExpr(s.Rhs[i]))
			}
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				return true
			}
			for _, spec := range gd.Specs {
				vs, isVS := spec.(*ast.ValueSpec)
				if !isVS || vs.Type == nil {
					continue
				}
				typ, okT := bareTypeName(vs.Type)
				if !okT {
					continue
				}
				for _, nm := range vs.Names {
					bind(nm.Name, typ)
				}
			}
		}
		return true
	})
	return out
}

// localTypeOfExpr — имя пакетного типа, если правая часть определения его
// называет прямо. Пустая строка означает «тип синтаксически не назван».
func localTypeOfExpr(rhs ast.Expr) string {
	switch e := rhs.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return localTypeOfExpr(e.X)
		}
	case *ast.CompositeLit:
		if e.Type == nil {
			return ""
		}
		if name, ok := bareTypeName(e.Type); ok {
			return name
		}
	case *ast.CallExpr:
		// new(T) — единственная форма вызова, называющая тип синтаксически.
		if ident, ok := e.Fun.(*ast.Ident); ok && ident.Name == "new" && len(e.Args) == 1 {
			if name, okT := bareTypeName(e.Args[0]); okT {
				return name
			}
		}
	}
	return ""
}
