// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_presentation_consumer.go — разбор «кто в прод-коде берёт предъявление
// ключа доступа вне словаря» (приёмка Ф12 Р7 редакция 11; Ф3 Р10 редакция 11;
// задача PRO-Robotech/kaname#287).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ось «заведено» дома единственного писателя
// (`internal/apps/kaname/api/humansession/completed_login.go`) выводится из
// строк способов входа, а ключ доступа — ресурс своей таблицы, и ось его не
// видит. Это безопасно, пока ни одна полоса не поднимает уровень сессии
// утверждением ключа. Событие, снимающее эту посылку, — появление в прод-коде
// ПОТРЕБИТЕЛЯ предъявления ключа; разбор ниже его и находит.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ОБРАЩЕНИЕ, А НЕ СЛОВО — ДВЕ ФОРМЫ
//
// Предъявление ключа попадает в код одним из двух путей, и оба судятся узлом
// разбора, а не текстом:
//
//	ИМЕНЕМ СЛОВАРЯ — `KeyAssertion` (утверждение с флагами) либо
//	   `MethodWebAuthn` (способ): селектор `<импорт>.<имя>` при импорте
//	   словаря под любым именем либо голое имя при импорте точкой;
//	ЗНАЧЕНИЕМ — чтение поля `Presentation` вывода проверки утверждения
//	   (`access_keys.FinishAssertionOutput`): потребитель, поднимающий уровень
//	   утверждением, скорее всего возьмёт предъявление готовым, по значению, и
//	   имени словаря не назовёт вовсе.
//
// Комментарий и строка обращением не являются by construction. Обращения
// внутри самого словаря не судятся — там предъявление объявлено.
//
// Законные места вне словаря — ведомостью (файл и функция): производитель
// (проверка утверждения строит предъявление для своего ответа) и декодер слов
// записи. Законное место само уровня сессии не пишет — файл ведомости, где
// появилась запись уровня, — находка; запись ведомости, которой нечего
// исключать, — тоже.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ НАЗВАНЫ
//
//	чтение поля судится ИМЕНЕМ поля, а не типом: одноимённое поле чужого типа
//	   будет сочтено чтением — это сторона ложного красного, не молчания;
//	слово `webauthn` строковым литералом — одиночный литерал гейт словаря
//	   (`assurance_method_vocabulary.go`) не судит, и эта проба тоже;
//	способ, взятый перебором `assurance.Methods()` без имени ключа, — узла с
//	   именем нет, разбору он не виден.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
)

// KeyPresentationNames — имена словаря, которыми берётся предъявление ключа.
var KeyPresentationNames = []string{"KeyAssertion", "MethodWebAuthn"}

// KeyPresentationField — поле вывода проверки утверждения, которым
// предъявление ключа уходит к потребителю по значению.
const KeyPresentationField = "Presentation"

// KeyPresentationLawfulUse — законное место вне словаря: функция файла и почему.
type KeyPresentationLawfulUse struct {
	// Func — функция, внутри которой обращение законно.
	Func string
	// Why — почему это место не потребитель.
	Why string
}

// KeyPresentationUse — одно обращение к предъявлению ключа с координатой.
type KeyPresentationUse struct {
	File string
	Line int
	// Func — функция, внутри которой стоит обращение; пусто — объявление пакета.
	Func string
	// Name — имя словаря, к которому обращаются.
	Name string
}

func (u KeyPresentationUse) String() string {
	if u.Func == "" {
		return fmt.Sprintf("%s:%d %s вне функции", u.File, u.Line, u.Name)
	}
	return fmt.Sprintf("%s:%d %s в %s()", u.File, u.Line, u.Name, u.Func)
}

// KeyPresentationCensus — объём осмотренного.
type KeyPresentationCensus struct {
	// Files — прочитанные файлы.
	Files int
	// FilesImportingHome — из них импортируют словарь.
	FilesImportingHome int
	// HomeDeclarations — сколько имён предъявления ключа объявлено в словаре.
	HomeDeclarations int
	// Uses — обращения вне словаря.
	Uses int
	// LawfulUses — из них в местах ведомости.
	LawfulUses int
}

func keyPresentationName(name string) bool {
	for _, n := range KeyPresentationNames {
		if n == name {
			return true
		}
	}
	return false
}

// ScanKeyPresentationUses разбирает один файл вне словаря: обращения к именам
// предъявления ключа, чтения поля вывода проверки утверждения и признак
// «словарь импортирован».
func ScanKeyPresentationUses(file string, src []byte) ([]KeyPresentationUse, bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		return nil, false, err
	}
	local, imported := "", false
	packages := map[string]bool{}
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		packages[name] = true
		if p == AssuranceHomeImport {
			imported, local = true, name
		}
	}
	byName := imported && local != "_"

	var uses []KeyPresentationUse
	at := func(n ast.Node, fn, name string) {
		uses = append(uses, KeyPresentationUse{File: file, Line: fset.Position(n.Pos()).Line, Func: fn, Name: name})
	}
	var visit func(root ast.Node, fn string)
	visit = func(root ast.Node, fn string) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				x, isIdent := v.X.(*ast.Ident)
				qualified := isIdent && packages[x.Name]
				switch {
				case byName && local != "." && qualified && x.Name == local && keyPresentationName(v.Sel.Name):
					at(v, fn, v.Sel.Name)
				case !qualified && v.Sel.Name == KeyPresentationField:
					at(v, fn, "."+KeyPresentationField)
				}
				// Имя справа от точки — поле либо метод, а не имя словаря;
				// слева может стоять ещё одно обращение.
				visit(v.X, fn)
				return false
			case *ast.Ident:
				if byName && local == "." && keyPresentationName(v.Name) {
					at(v, fn, v.Name)
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			if v.Body != nil {
				visit(v.Body, v.Name.Name)
			}
		case *ast.GenDecl:
			if v.Tok != token.IMPORT {
				visit(v, "")
			}
		}
	}
	return uses, imported, nil
}

// keyPresentationDeclarations — имена предъявления ключа, объявленные файлом
// словаря на верхнем уровне: функцией либо значением.
func keyPresentationDeclarations(file string, src []byte) (map[string]bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	for _, d := range f.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			if v.Recv == nil && keyPresentationName(v.Name.Name) {
				declared[v.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, spec := range v.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range vs.Names {
						if keyPresentationName(name.Name) {
							declared[name.Name] = true
						}
					}
				}
			}
		}
	}
	return declared, nil
}

// JudgeKeyPresentationConsumers — ВЕРДИКТ над корпусом: находки и перепись.
func JudgeKeyPresentationConsumers(
	corpus TreeCorpus, lawful map[string]KeyPresentationLawfulUse,
) ([]string, KeyPresentationCensus, error) {
	var (
		census   KeyPresentationCensus
		findings []string
		declared = map[string]bool{}
		seen     = map[string]int{}
	)
	for _, rel := range corpus.Rels() {
		census.Files++
		src := []byte(corpus[rel])
		if path.Dir(rel) == AssuranceHomeRel {
			names, err := keyPresentationDeclarations(rel, src)
			if err != nil {
				return nil, census, fmt.Errorf("разбор словаря %s: %w", rel, err)
			}
			for n := range names {
				declared[n] = true
			}
			continue
		}
		uses, imports, err := ScanKeyPresentationUses(rel, src)
		if err != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", rel, err)
		}
		if imports {
			census.FilesImportingHome++
		}
		for _, u := range uses {
			census.Uses++
			if entry, ok := lawful[rel]; ok && entry.Func != "" && entry.Func == u.Func {
				census.LawfulUses++
				seen[rel]++
				continue
			}
			findings = append(findings, fmt.Sprintf("%s — потребитель предъявления ключа вне словаря, производителя "+
				"и декодера записи: здесь уровень сессии может подняться утверждением ключа, которого ось «заведено» "+
				"(%s) не видит", u, FailureResetHomeRel))
		}
	}
	census.HomeDeclarations = len(declared)
	for rel, entry := range lawful {
		if seen[rel] == 0 {
			findings = append(findings, fmt.Sprintf("запись ведомости %q (%s(): %s) больше нечего исключать: "+
				"предъявление ключа там не берётся", rel, entry.Func, entry.Why))
		}
		src, ok := corpus[rel]
		if !ok {
			continue
		}
		writes, _, err := ScanSessionLevelWrites(rel, []byte(src))
		if err != nil {
			return nil, census, fmt.Errorf("разбор записи уровня %s: %w", rel, err)
		}
		for _, wr := range writes {
			findings = append(findings, fmt.Sprintf("%s:%d — законное место ведомости (%s()) пишет уровень сессии (%s): "+
				"предъявление ключа здесь больше не только производится либо декодируется — у него появился потребитель",
				rel, wr.Line, entry.Func, wr.Func))
		}
	}
	sort.Strings(findings)
	return findings, census, nil
}
