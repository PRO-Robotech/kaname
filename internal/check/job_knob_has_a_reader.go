// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// job_knob_has_a_reader.go — разбор: у КАЖДОЙ величины секции фоновых заданий
// есть читатель вне пакета настроек (задача #2647).
//
// # Предмет
//
// Ручка настроек, которую принимают, валидируют и не читают, — это
// «принято-и-проигнорировано» на уровне НАСТРОЙКИ, и там
// оно тише, чем в поле запроса. Оператор, выставивший величину, получает
// УСПЕХ: значение принято, провалидировано, отказа нет. Он уверен, что изменил
// поведение. Поведение осталось прежним.
//
// Три обстоятельства делают это неотличимым от исправной работы, и все три
// наблюдались вместе на `jobs.catalog-snapshot.refresh-interval`:
//
//   - величина объявлена ДВАЖДЫ — секцией настроек и ручкой окружения в
//     композиционном корне, — а петлю ведёт одна;
//   - умолчания РАСХОДЯТСЯ (минута против пятнадцати секунд), то есть даже
//     незаданная ручка описывает поведение неверно вчетверо;
//   - страж старта у поля ЕСТЬ и отвергает непозитивное — и тем создаёт вид
//     живого механизма: «ручка работает».
//
// Наблюдаемого отличия нет ни одного: снимок обновляется, просто не с тем
// периодом. Заметить можно только замером окна отставания.
//
// # Что считается ЧИТАТЕЛЕМ, и почему собственная валидация им не является
//
// Читателем считается обращение к полю в композиционном корне — там, где
// величина попадает в механизм. Метод `Validate` самой секции читателем НЕ
// является by construction: он живёт в пакете настроек, и его вызов доказывает
// ровно то, что величину проверили, — а не то, что ею кто-то пользуется.
// Именно поэтому предикат задачи звучал «читатель ВНЕ собственной валидации»:
// у поля без механизма читателей было два, и оба — его собственная проверка.
//
// # Почему разбор УЗЛОВ, а не поиск имени
//
// Имя поля (`Interval`, `Enabled`, `Grace`) — из самых частых в дереве, и поиск
// по нему засчитал бы читателем одноимённое поле ЧУЖОЙ структуры, комментарий и
// строку журнала. Поэтому читатель опознаётся цепочкой узлов: обращение к полю
// через `…Jobs.<секция>` либо через ПСЕВДОНИМ, связанный с этой цепочкой
// (`c := cfg.Jobs.ExpiredCredentialReclaim`, дальше `c.Interval`) — ровно та
// форма, которой пользуется корень.
//
// # Граница названа: секция, переданная ЦЕЛИКОМ
//
// Секция, ушедшая в вызов целиком (`f(cfg.Jobs.X)`), пофайлово не разбирается:
// о её полях этот гейт не утверждает ничего. Такие секции НЕ прощаются молча —
// они печатаются переписью отдельной величиной, потому что «поле прочитано» и
// «секция уехала целиком, а поле, может, и не прочитано» — разные вердикты, и
// второй обязан быть видим.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// JobsConfigTypeName — структура, чьи поля суть секции фоновых заданий.
const JobsConfigTypeName = "JobsConfig"

// JobsSelectorName — поле, через которое корень добирается до секций.
const JobsSelectorName = "Jobs"

// JobSection — секция фоновых заданий и её величины.
type JobSection struct {
	// Name — имя поля в JobsConfig (оно же сегмент ключа настроек).
	Name string
	// Type — имя структуры секции.
	Type string
	// Fields — величины секции, объявленные тегом настроек.
	Fields []string
}

// JobFieldRead — прочтение величины в композиционном корне.
type JobFieldRead struct {
	Section string
	Field   string
	File    string
	Line    int
}

// JobSectionsIn разбирает объявление секций фоновых заданий.
//
// Состав ВЫВОДИТСЯ из исходника, а не выписывается: выписанный перечень секций
// разошёлся бы с деревом на первой же новой петле — и разошёлся бы молча,
// потому что гейт судил бы ровно то, что ему назвали.
func JobSectionsIn(src string) ([]JobSection, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "jobs.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("разобрать объявление секций: %w", err)
	}

	structs := map[string]*ast.StructType{}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		if st, ok := ts.Type.(*ast.StructType); ok {
			structs[ts.Name.Name] = st
		}
		return true
	})

	jobs, ok := structs[JobsConfigTypeName]
	if !ok {
		return nil, nil
	}

	var out []JobSection
	for _, f := range jobs.Fields.List {
		id, ok := f.Type.(*ast.Ident)
		if !ok || len(f.Names) != 1 {
			continue
		}
		sec := JobSection{Name: f.Names[0].Name, Type: id.Name}
		if st, ok := structs[id.Name]; ok {
			for _, sf := range st.Fields.List {
				if sf.Tag == nil || !strings.Contains(sf.Tag.Value, "mapstructure:") {
					continue
				}
				for _, nm := range sf.Names {
					sec.Fields = append(sec.Fields, nm.Name)
				}
			}
		}
		sort.Strings(sec.Fields)
		out = append(out, sec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// JobFieldReadsIn разбирает ОДИН файл корня: какие величины прочитаны и какие
// секции ушли в вызов целиком.
//
// Имя секции подаётся набором, а не угадывается: гейт судит те секции, которые
// объявлены, и на одноимённом поле чужой структуры молчит.
func JobFieldReadsIn(file, src string, sections map[string]bool) ([]JobFieldRead, []string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, fmt.Errorf("разобрать %s: %w", file, err)
	}

	// Первый проход — псевдонимы: `c := <…>.Jobs.<секция>`.
	alias := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		sec := jobSectionOf(as.Rhs[0], sections)
		if sec == "" {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok {
			alias[id.Name] = sec
		}
		return true
	})

	var (
		reads []JobFieldRead
		whole = map[string]bool{}
	)
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			// Прямая цепочка `<…>.Jobs.<секция>.<величина>`.
			if sec := jobSectionOf(v.X, sections); sec != "" {
				reads = append(reads, JobFieldRead{
					Section: sec, Field: v.Sel.Name, File: file,
					Line: fset.Position(v.Sel.Pos()).Line,
				})
				return true
			}
			// Через псевдоним: `c.Interval`.
			if id, ok := v.X.(*ast.Ident); ok {
				if sec, ok := alias[id.Name]; ok {
					reads = append(reads, JobFieldRead{
						Section: sec, Field: v.Sel.Name, File: file,
						Line: fset.Position(v.Sel.Pos()).Line,
					})
				}
			}
		case *ast.CallExpr:
			// Секция, уехавшая в вызов ЦЕЛИКОМ: о её полях вердикта нет.
			for _, a := range v.Args {
				if sec := jobSectionOf(a, sections); sec != "" {
					whole[sec] = true
				}
			}
		}
		return true
	})

	out := make([]string, 0, len(whole))
	for s := range whole {
		out = append(out, s)
	}
	sort.Strings(out)
	return reads, out, nil
}

// jobSectionOf — выражение есть `<…>.Jobs.<секция>`?
func jobSectionOf(e ast.Expr, sections map[string]bool) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || !sections[sel.Sel.Name] {
		return ""
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok || inner.Sel.Name != JobsSelectorName {
		return ""
	}
	return sel.Sel.Name
}

// JobKnobCensus — объём осмотренного и вердикт.
//
// Величин ПЯТЬ, и печатаются все: «секций N · величин M · прочитано K · секций
// целиком L · файлов корня F». Одно число скрывало бы ровно тот случай, ради
// которого гейт заведён: величина без читателя и величина, чья секция уехала
// целиком, дают одинаковый ноль находок.
type JobKnobCensus struct {
	Sections     int
	Fields       int
	Read         int
	WholeSection []string
	Files        int
	Findings     []string
}

func (c JobKnobCensus) Summary() string {
	whole := "нет"
	if len(c.WholeSection) > 0 {
		whole = strings.Join(c.WholeSection, ", ")
	}
	return fmt.Sprintf(
		"секций фоновых заданий %d · величин %d · с читателем в корне %d · "+
			"секций, переданных целиком: %s · файлов корня прочитано %d",
		c.Sections, c.Fields, c.Read, whole, c.Files)
}

// JudgeJobKnobReaders — судящее ядро. Вход подаётся ЗНАЧЕНИЯМИ: инъекция обязана
// уметь дать ему свой вход, не трогая рабочую копию, из которой запущена.
func JudgeJobKnobReaders(sections []JobSection, reads []JobFieldRead, whole []string, files int) JobKnobCensus {
	c := JobKnobCensus{Sections: len(sections), Files: files}

	read := map[string]bool{}
	for _, r := range reads {
		read[r.Section+"."+r.Field] = true
	}
	wholeSet := map[string]bool{}
	for _, s := range whole {
		wholeSet[s] = true
	}

	for _, sec := range sections {
		for _, f := range sec.Fields {
			c.Fields++
			key := sec.Name + "." + f
			if read[key] {
				c.Read++
				continue
			}
			if wholeSet[sec.Name] {
				continue
			}
			c.Findings = append(c.Findings, fmt.Sprintf(
				"ВЕЛИЧИНА БЕЗ ЧИТАТЕЛЯ `jobs.%s` (поле %s.%s) — её объявляет секция "+
					"настроек, её проверяет страж старта, и НИ ОДИН путь исполнения не "+
					"берёт её значение. Оператор, выставивший её, получает УСПЕХ и "+
					"уверен, что изменил поведение; поведение осталось прежним. Исходов "+
					"три, четвёртого нет: провязать величину в механизм · снять поле с "+
					"контракта вместе с умолчанием · отвергать заданную величину явно, "+
					"отказом старта. «Принять и выбросить» исходом не является",
				key, sec.Type, f))
		}
	}

	c.WholeSection = append(c.WholeSection, whole...)
	sort.Strings(c.WholeSection)
	sort.Strings(c.Findings)
	return c
}
