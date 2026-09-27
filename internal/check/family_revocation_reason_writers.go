// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_revocation_reason_writers.go — разбор «у каждого слова словаря причин
// отзыва семейства есть писатель» (задача PRO-Robotech/kaname#339, п.1
// предиката снятия; приёмка
// `docs/engineering/acceptance/client-revocation-has-its-own-family-revocation-reason.md`,
// KN-FRV-17, решение Р12).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Словарь причин отзыва семейства ЗАКРЫТ: он перечисляет исчерпывающе, и
// ограничение схемы принимает ровно его. Слово, которого никто не пишет,
// превращает перечень в обещание — оно читается как работающее и не наступает
// ни при каком входе. Два таких слова жили в словаре со дня его заведения, и
// заметить это было нечем: имя без писателя компилируется, проходит пробы
// схемы и молчит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ПИСАТЕЛЕМ — ДВЕ ВЕТВИ
//
//  1. на константу домена этого слова ссылается УЗЕЛ разбора — селектор
//     пакета домена (`domain.<имя>`) — в не-тестовом `.go` вне самого домена;
//  2. причина фундамента того же написания сопрягается адаптером порта отзыва
//     с этим словом (`ceremonyport.FamilyReasonOf`): такое слово пишется по
//     значению и константы не называет.
//
// Без второй ветви гейт назвал бы беспризорным слово, у которого писатель есть.
// Сопряжение вызывающий подаёт функцией: разбор о нём ничего не знает и
// фундамента не импортирует.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ УЗЕЛ, А НЕ ТЕКСТ
//
// Упоминание константы в комментарии или в строке писателем не является:
// комментарий в дерево узлов не входит, строка — узел литерала, а не
// селектора. Селектор судится по ПУТИ ИМПОРТА, а не по имени пакета:
// псевдоним импорта домена — та же ссылка, одноимённый селектор чужого пакета —
// не она. Имена констант и их значения берутся из объявлений домена, а не
// выписываются здесь: своя копия была бы вторым объявлением словаря.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПУСТОЙ ОБХОД — ОТДЕЛЬНЫЙ ИСХОД
//
// Ноль разобранных файлов, ноль файлов, импортирующих домен, либо пустой
// перечень — это «ноль прочитанного», а не «ноль находок», и такой исход
// обязан быть КРАСНЫМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Импорт домена точкой, затенение имени импорта локальной переменной и слово,
// собранное из частей строки, разбор не видит. В дереве таких путей к словарю
// нет; первое и третье — довод держать ссылку селектором, каким она и
// написана.
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

// FamilyReasonWord — одно слово словаря и перепись его писателей.
type FamilyReasonWord struct {
	// Word — написание слова, как его объявляет перечень домена.
	Word string
	// Constants — имена констант домена с этим значением.
	Constants []string
	// ConstantRefs — сколько узлов-селекторов домена ссылаются на эти
	// константы в осмотренных файлах.
	ConstantRefs int
	// Conjugated — сопрягается ли причина фундамента того же написания с этим
	// словом.
	Conjugated bool
}

// HasWriter — есть ли у слова писатель хотя бы по одной ветви.
func (w FamilyReasonWord) HasWriter() bool { return w.ConstantRefs > 0 || w.Conjugated }

// FamilyReasonWritersCensus — перепись обхода. Объём осмотренного печатается,
// потому что «находок ноль» без него неотличимо от «не смотрели».
type FamilyReasonWritersCensus struct {
	// FilesRead — сколько файлов подано на осмотр.
	FilesRead int
	// FilesParsed — сколько из них импортируют домен и разобраны по узлам.
	FilesParsed int
	// Words — слова в порядке перечня домена.
	Words []FamilyReasonWord
}

// Orphans — слова без писателя, в порядке перечня.
func (c FamilyReasonWritersCensus) Orphans() []string {
	var out []string
	for _, w := range c.Words {
		if !w.HasWriter() {
			out = append(out, w.Word)
		}
	}
	return out
}

// String — перепись одной строкой: объём и исход по каждому слову.
func (c FamilyReasonWritersCensus) String() string {
	parts := make([]string, 0, len(c.Words))
	for _, w := range c.Words {
		conj := "нет"
		if w.Conjugated {
			conj = "да"
		}
		parts = append(parts, fmt.Sprintf("%s: константой %d, сопряжением %s", w.Word, w.ConstantRefs, conj))
	}
	return fmt.Sprintf("файлов прочитано %d · импортирующих домен разобрано %d · слов %d — %s · без писателя — %d",
		c.FilesRead, c.FilesParsed, len(c.Words), strings.Join(parts, "; "), len(c.Orphans()))
}

// FamilyReasonConstants разбирает файлы домена и возвращает константы
// названного типа: имя → значение. Объявление без явного типа в счёт не идёт —
// у словаря тип указан у каждой константы.
func FamilyReasonConstants(domainFiles map[string]string, typeName string) (map[string]string, error) {
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, name := range familyReasonSortedKeys(domainFiles) {
		f, err := parser.ParseFile(fset, name, domainFiles[name], parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("разбор %s: %w", name, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				typ, ok := vs.Type.(*ast.Ident)
				if !ok || typ.Name != typeName || len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, n := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return nil, fmt.Errorf("%s: константа %s типа %s задана не строковым литералом — "+
							"её значение разбор не выводит", name, n.Name, typeName)
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						return nil, fmt.Errorf("%s: константа %s: %w", name, n.Name, err)
					}
					out[n.Name] = v
				}
			}
		}
	}
	return out, nil
}

// FamilyReasonWriters переписывает писателей каждого слова перечня.
//
// files — не-тестовые файлы вне домена (путь → текст); отбор делает
// вызывающий. domainImport — путь импорта пакета домена. constants — имя
// константы → значение (см. [FamilyReasonConstants]). vocabulary — перечень
// домена. conjugated — ветвь сопряжения по значению; nil означает, что
// ветви нет.
func FamilyReasonWriters(files map[string]string, domainImport string, constants map[string]string,
	vocabulary []string, conjugated func(word string) bool) (FamilyReasonWritersCensus, error) {

	out := FamilyReasonWritersCensus{FilesRead: len(files)}
	refs := map[string]int{}
	fset := token.NewFileSet()
	quoted := strconv.Quote(domainImport)

	for _, name := range familyReasonSortedKeys(files) {
		src := files[name]
		// Файл, не называющий путь импорта домена, сослаться на домен не
		// может; разбирать его незачем.
		if !strings.Contains(src, quoted) {
			continue
		}
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			return out, fmt.Errorf("разбор %s: %w", name, err)
		}
		local, ok := familyReasonImportName(f, domainImport)
		if !ok {
			continue
		}
		out.FilesParsed++
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok || x.Name != local {
				return true
			}
			if _, known := constants[sel.Sel.Name]; known {
				refs[sel.Sel.Name]++
			}
			return true
		})
	}

	byValue := map[string][]string{}
	for name, v := range constants {
		byValue[v] = append(byValue[v], name)
	}
	for _, word := range vocabulary {
		names := byValue[word]
		sort.Strings(names)
		w := FamilyReasonWord{Word: word, Constants: names}
		for _, n := range names {
			w.ConstantRefs += refs[n]
		}
		if conjugated != nil {
			w.Conjugated = conjugated(word)
		}
		out.Words = append(out.Words, w)
	}
	return out, nil
}

// FamilyReasonWriterFindings — вердикт по переписи. Пустой обход — находка
// сам по себе: «ноль прочитанного» не выдаётся за «ноль находок».
func FamilyReasonWriterFindings(c FamilyReasonWritersCensus) []string {
	var out []string
	if c.FilesRead == 0 || c.FilesParsed == 0 {
		out = append(out, fmt.Sprintf("обход пуст: файлов прочитано %d, импортирующих домен разобрано %d — "+
			"«ноль находок» здесь означало бы «ноль прочитанного»", c.FilesRead, c.FilesParsed))
	}
	if len(c.Words) == 0 {
		out = append(out, "перечень словаря пуст — судить нечего, и это не «у каждого слова есть писатель»")
	}
	for _, w := range c.Words {
		if w.HasWriter() {
			continue
		}
		consts := "констант домена с этим значением нет"
		if len(w.Constants) > 0 {
			consts = "ссылок на " + strings.Join(w.Constants, ", ") + " вне домена 0"
		}
		out = append(out, fmt.Sprintf("слово %q без писателя: %s, сопряжения по значению нет. "+
			"Слово закрытого словаря, которого никто не пишет, — обещание, а не возможность: "+
			"завести писателя либо снять слово из домена и из ограничения схемы одним изменением",
			w.Word, consts))
	}
	return out
}

// familyReasonImportName — имя, под которым файл видит пакет по пути импорта. Импорт
// точкой и пустой импорт ссылку селектором не дают.
func familyReasonImportName(f *ast.File, importPath string) (string, bool) {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return "", false
			}
			return imp.Name.Name, true
		}
		return path.Base(p), true
	}
	return "", false
}

// familyReasonSortedKeys — ключи в устойчивом порядке: перепись одного дерева не
// зависит от обхода карты.
func familyReasonSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
