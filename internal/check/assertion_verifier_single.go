// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_verifier_single.go — разбор «сверка утверждения ключа доступа в
// дереве ОДНА» (приёмка Ф13
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`, Р13,
// §7 инв. 2, сценарий Ф13-31; задача PRO-Robotech/kaname#613).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Утверждение ключа сверяют две полосы — проверка утверждения из сессии (Ф7) и
// вход без пароля (Ф13). Обе обязаны звать ОДНОГО проверяющего
// (`internal/webauthnverify`): вторая сверка — «упрощённая для входа» либо
// копия — разошлась бы с первой молча ровно там, где расхождение опасно, и
// ни проба одной полосы, ни проба другой этого не показали бы.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ВЫЗОВ ПРИМИТИВА ПОДПИСИ, А НЕ ИМЯ ФУНКЦИИ
//
// Копия проверяющего под другим именем узнаётся по тому, что она ДЕЛАЕТ:
// зовёт примитив сверки подписи стандартной библиотеки (`ecdsa.Verify`,
// `ecdsa.VerifyASN1`, `ed25519.Verify`, `rsa.VerifyPKCS1v15`, `rsa.VerifyPSS`).
// Такой вызов в прод-коде законен только в доме проверяющего; функция дома,
// его содержащая, — «объявление сверки», и оно ОДНО. Обёртка, зовущая
// `webauthnverify.VerifyAssertion`, — вызывающий, а не вторая сверка: она
// молчит и считается в переписи вызывающих.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ НАЗВАНЫ
//
//	примитив, взятый значением (`f := ecdsa.VerifyASN1`), — узел селектора без
//	   вызова; разбор считает и его (сторона ложного красного, не молчания);
//	импорт примитива под псевдонимом распознаётся по пути импорта;
//	сверка чужой библиотекой (не стандартной) этим разбором не видна — в дереве
//	   её нет, и перепись импортов это показала бы ростом числа файлов.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// AssertionVerifierHomeRel — дом проверяющего от корня модуля.
const AssertionVerifierHomeRel = "internal/webauthnverify/"

// AssertionVerifierImport — путь импорта дома проверяющего.
const AssertionVerifierImport = "github.com/PRO-Robotech/kaname/internal/webauthnverify"

// signaturePrimitives — путь импорта → примитивы сверки подписи.
var signaturePrimitives = map[string]map[string]bool{
	"crypto/ecdsa":   {"Verify": true, "VerifyASN1": true},
	"crypto/ed25519": {"Verify": true, "VerifyWithOptions": true},
	"crypto/rsa":     {"VerifyPKCS1v15": true, "VerifyPSS": true},
}

// AssertionVerifierCensus — объём осмотренного.
type AssertionVerifierCensus struct {
	// Files — прод-файлов Go разобрано.
	Files int
	// Declarations — функции дома, зовущие примитив сверки подписи.
	Declarations []string
	// Callers — функции вне дома, зовущие `webauthnverify.VerifyAssertion`.
	Callers []string
}

// JudgeAssertionVerifiers — находки и перепись по корпусу прод-файлов Go.
func JudgeAssertionVerifiers(corpus TreeCorpus) ([]string, AssertionVerifierCensus, error) {
	var (
		c        AssertionVerifierCensus
		findings []string
	)
	fset := token.NewFileSet()
	for _, rel := range corpus.Rels() {
		f, err := parser.ParseFile(fset, rel, corpus[rel], parser.SkipObjectResolution)
		if err != nil {
			return nil, c, fmt.Errorf("%s: %w", rel, err)
		}
		c.Files++
		aliases := map[string]string{} // имя в файле → путь импорта
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if _, ok := signaturePrimitives[p]; !ok && p != AssertionVerifierImport {
				continue
			}
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			aliases[name] = p
		}
		if len(aliases) == 0 {
			continue
		}
		inHome := strings.HasPrefix(rel, AssertionVerifierHomeRel)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			where := rel + ":" + fd.Name.Name
			declared, called := false, false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				path, ok := aliases[id.Name]
				if !ok {
					return true
				}
				if signaturePrimitives[path][sel.Sel.Name] {
					if inHome {
						declared = true
					} else {
						findings = append(findings, fmt.Sprintf("%s:%d %s.%s в %s() — сверка подписи вне проверяющего "+
							"(%s): вторая сверка утверждения разошлась бы с первой молча (Ф13 Р13, §7 инв. 2)",
							rel, fset.Position(sel.Pos()).Line, id.Name, sel.Sel.Name, fd.Name.Name, AssertionVerifierHomeRel))
					}
				}
				if path == AssertionVerifierImport && sel.Sel.Name == "VerifyAssertion" && !inHome {
					called = true
				}
				return true
			})
			if declared {
				c.Declarations = append(c.Declarations, where)
			}
			if called {
				c.Callers = append(c.Callers, where)
			}
		}
	}
	sort.Strings(c.Declarations)
	sort.Strings(c.Callers)
	if len(c.Declarations) > 1 {
		findings = append(findings, fmt.Sprintf("объявлений сверки подписи в доме %d (%s), ожидалось одно — "+
			"проверяющий раздвоился внутри своего дома", len(c.Declarations), strings.Join(c.Declarations, ", ")))
	}
	return findings, c, nil
}
