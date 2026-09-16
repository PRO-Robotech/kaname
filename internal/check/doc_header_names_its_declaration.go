// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// doc_header_names_its_declaration.go — разбор шапок объявлений на ОДИН факт:
// то ли объявление названо шапкой, над которым она стоит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Шапка этого дерева пишется формой «Имя — что это»: имя стоит первым словом, и
// по нему читатель находит объявление, не разбирая тело. Форма даёт и обратное:
// шапка, отвязавшаяся от своего объявления, продолжает выглядеть исправной.
//
// Отвязывается она одним движением — между шапкой и её объявлением вставляют
// новое объявление со СВОЕЙ шапкой, а пустая строка между двумя блоками
// теряется. Go склеивает соседние строки комментария в ОДНУ группу, и вся она
// достаётся объявлению снизу. Тогда `go doc` печатает чужую шапку у одного
// имени и НИ ОДНОЙ у другого — при том что текст обеих на месте и дословно
// верен.
//
// Второй путь тот же по исходу: объявление переименовали, шапку не тронули.
//
// Почему это не косметика. Читатель, которому шапка уже ОТВЕТИЛА, что перед
// ним, дальше не проверяет — ровно как с комментарием о защите
// (`guard_named_in_comment.go`). Наблюдалось на посадочной настройке: шапка
// `APIServerConfig` с разбором двух форм адреса слушателя стояла над
// `SubscriptionConfig`, а у самой `APIServerConfig` шапки не было вовсе
// (kaname#118). Перепись по прод-дереву нашла тот же класс ещё в 22 местах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ШАПКОЙ — ФОРМА НАЗВАНА, А НЕ ПОДРАЗУМЕВАЕТСЯ
//
// Шапкой считается первая строка группы комментария вида
//
//	Имя — текст      (тире, длинное)
//	Имя – текст      (тире, среднее)
//	Имя - текст      (дефис)
//
// где «Имя» — идентификатор Go. Разделитель обязателен: без него первое слово
// прозы («Package», «Returns») стало бы находкой на ровном месте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМЫ ОБЪЯВЛЕНИЯ ПЕРЕЧИСЛЕНЫ ПОИМЁННО
//
// Форма, о которой распознаватель не знает, даёт не красное и не зелёное, а
// МОЛЧАНИЕ: объявление уезжает вне наблюдения. Читаются ВСЕ формы, у которых
// шапка вообще бывает:
//
//	func F(…)                     — FuncDecl
//	func (r T) M(…)               — FuncDecl с получателем; имя — метода
//	type T …                      — GenDecl с одним TypeSpec, шапка на GenDecl
//	type ( A …; B … )             — блок; шапка на КАЖДОМ TypeSpec отдельно
//	const C = … / var V = …       — GenDecl с одним ValueSpec, шапка на GenDecl
//	const ( A = …; B = … )        — блок; шапка на КАЖДОМ ValueSpec отдельно
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. **шапка без разделителя** — каноническая форма Go «// F returns …». В этом
//     дереве её почти нет (перепись печатает обе величины: шапок формы с
//     разделителем и объявлений с шапкой вообще), а распознать её нельзя, не
//     принимая за имя первое слово всякой прозы;
//  2. **объявление с НЕСКОЛЬКИМИ именами в одной спецификации** (`var a, b = …`):
//     шапка вправе называть любое из них, поэтому находкой считается лишь то,
//     чьё имя не совпало НИ С ОДНИМ;
//  3. **правдивость самого текста** шапки. Гейт судит, к тому ли объявлению она
//     прикреплена, а не то, верно ли она его описывает.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
)

// DocHeaderSite — одна прочитанная шапка вместе с объявлением, которому она
// досталась.
type DocHeaderSite struct {
	File string
	Line int
	// Named — имя, которое шапка называет первым словом.
	Named string
	// Declared — имена, объявленные узлом, которому шапка досталась. Их больше
	// одного только у `var a, b = …`.
	Declared []string
	// Form — форма объявления: `func` · `method` · `type` · `const` · `var`.
	// Печатается переписью: «ноль находок» обязано быть отличимо от «форму не
	// узнали».
	Form string
}

// Matches — называет ли шапка то объявление, над которым стоит.
func (s DocHeaderSite) Matches() bool {
	for _, d := range s.Declared {
		if d == s.Named {
			return true
		}
	}
	return false
}

// DocHeaderCensus — объём осмотренного одним файлом.
type DocHeaderCensus struct {
	// Decls — объявлений прочитано (всех форм перечня выше).
	Decls int
	// Documented — из них с группой комментария над ними.
	Documented int
	// Headers — из них формы «Имя <разделитель> текст».
	Headers int
}

// docHeaderRe — первая строка шапки: идентификатор, пробел, разделитель, пробел.
var docHeaderRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)[ \t]+[—–-][ \t]`)

// ScanDocHeaders разбирает один файл и возвращает ВСЕ прочитанные шапки формы
// «Имя — текст» вместе с объёмом осмотренного. Находки не отбираются здесь
// намеренно: отбор делает вызывающий, и тот же предикат зовёт инъекция.
func ScanDocHeaders(path string, src []byte) (sites []DocHeaderSite, census DocHeaderCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
	if perr != nil {
		return nil, DocHeaderCensus{}, perr
	}
	add := func(doc *ast.CommentGroup, names []string, form string, pos token.Pos) {
		census.Decls++
		if doc == nil {
			return
		}
		census.Documented++
		first := strings.SplitN(strings.TrimSpace(doc.Text()), "\n", 2)[0]
		m := docHeaderRe.FindStringSubmatch(first)
		if m == nil {
			return
		}
		census.Headers++
		sites = append(sites, DocHeaderSite{
			File:     path,
			Line:     fset.Position(pos).Line,
			Named:    m[1],
			Declared: names,
			Form:     form,
		})
	}
	for _, d := range f.Decls {
		switch n := d.(type) {
		case *ast.FuncDecl:
			form := "func"
			if n.Recv != nil {
				form = "method"
			}
			add(n.Doc, []string{n.Name.Name}, form, n.Pos())
		case *ast.GenDecl:
			for _, spec := range n.Specs {
				// Шапка блока достаётся ЕДИНСТВЕННОЙ спецификации: у блока из
				// нескольких она общая и ни одного имени не называет.
				doc := specDoc(spec)
				if doc == nil && len(n.Specs) == 1 {
					doc = n.Doc
				}
				switch s := spec.(type) {
				case *ast.TypeSpec:
					add(doc, []string{s.Name.Name}, "type", s.Pos())
				case *ast.ValueSpec:
					names := make([]string, 0, len(s.Names))
					for _, id := range s.Names {
						names = append(names, id.Name)
					}
					form := "var"
					if n.Tok == token.CONST {
						form = "const"
					}
					add(doc, names, form, s.Pos())
				}
			}
		}
	}
	return sites, census, nil
}

// specDoc — шапка, прикреплённая к самой спецификации (форма блока).
func specDoc(spec ast.Spec) *ast.CommentGroup {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return s.Doc
	case *ast.ValueSpec:
		return s.Doc
	}
	return nil
}
