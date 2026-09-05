// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// findingcomment_test.go — комментарий кода находки НЕ перечисляет поводы, а
// отсылает к перечню нормы.
//
// # Предмет
//
// Комментарий пережил решение. Норма §2 п. 7 приёмки
// `model-generated-from-manifest.md` перечисляет поводы кода `1` ПОИМЁННО —
// сегодня их тринадцать строк, — а комментарий у кода остался с формулировкой о
// двух: «расхождение ЛИБО модуль без манифеста и без записи ведомости». Держателя
// не было: полный прогон зелен при устаревшем комментарии.
//
// # Почему отсылка, а не своё перечисление
//
// Перечень поводов есть у нормы, и он один. Второе перечисление у кода разошлось
// бы с первым молча — ровно тот класс, из которого эта задача и выведена. Поэтому
// комментарий обязан назвать КООРДИНАТУ перечня, а не воспроизводить его часть.
//
// # Что судится и чего гейт НЕ судит
//
// Судится: комментарий не перечисляет поводы подмножеством · называет координату
// нормы · координата разрешается (файл лежит в дереве, раздел в нём есть).
// Не судится, ПОЛОН ли перечень самой нормы: это предмет соседний, и он назван
// задачей — здесь он был бы вторым местом об одном предмете.
package modelrender_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const (
	// sweepFile — файл, чьи комментарии сверяем.
	sweepFile = "sweep.go"
	// normDoc — приёмка, у которой живёт перечень поводов.
	normDoc = "../../docs/engineering/acceptance/model-generated-from-manifest.md"
	// normAnchor — координата перечня внутри приёмки.
	normAnchor = "§2 п. 7"
)

// subsetMarkers — разделители, которыми перечисляют ПОДМНОЖЕСТВО поводов в одну
// строку. Форм две, обе законны в русском тексте и обе наблюдались.
var subsetMarkers = []string{" либо ", " ЛИБО "}

// findingComment — текст, описывающий код находки: doc-комментарий константы
// плюс строка таблицы исходов в комментарии блока констант. Читается РАЗБОРОМ, а
// не поиском подстроки: имя константы встречается и в прозе, и в теле функций, а
// таблица исходов стоит в комментарии БЛОКА, а не файла — поиск по шапке файла
// нашёл бы её только случайно.
func findingComment(t *testing.T, path string) (constDoc, headerRow string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("файл не разобран: %v", err)
	}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		mine := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "SweepFinding" {
				continue
			}
			mine = true
			if vs.Doc != nil {
				constDoc = vs.Doc.Text()
			}
		}
		if !mine || gd.Doc == nil {
			continue
		}
		for _, ln := range strings.Split(gd.Doc.Text(), "\n") {
			if strings.Contains(ln, "находка") && strings.Contains(ln, "1") {
				headerRow = ln
				break
			}
		}
	}
	return constDoc, headerRow
}

// auditFindingComment ВОЗВРАЩАЕТ находки: разбор, обращающийся к *testing.T,
// инъекции не поддаётся.
func auditFindingComment(constDoc, headerRow, normPath string) (findings []string, judged int) {
	for _, part := range []struct{ name, text string }{
		{"doc-комментарий константы SweepFinding", constDoc},
		{"строка кода 1 в таблице исходов шапки", headerRow},
	} {
		if strings.TrimSpace(part.text) == "" {
			findings = append(findings, "обход пуст: "+part.name+" не прочитан — "+
				"«находок 0» неотличимо от «прочитано 0»")
			continue
		}
		judged++
		for _, m := range subsetMarkers {
			if strings.Contains(part.text, m) {
				findings = append(findings, part.name+" перечисляет поводы подмножеством ("+
					strings.TrimSpace(m)+"): норма называет их поимённо и их больше двух.\n"+
					"    второе перечисление у кода разойдётся с первым молча — комментарий обязан "+
					"назвать КООРДИНАТУ перечня, а не воспроизвести его часть")
			}
		}
		if !strings.Contains(part.text, normAnchor) {
			findings = append(findings, part.name+" не называет координату перечня ("+normAnchor+"): "+
				"читателю некуда пойти за поводами")
		}
	}

	if judged == 0 {
		return findings, judged
	}
	body, err := os.ReadFile(normPath)
	if err != nil {
		findings = append(findings, "координата не разрешается: приёмка "+normPath+" не читается: "+err.Error())
		return findings, judged
	}
	if !strings.Contains(string(body), "Поводы кода `1` перечислены ПОИМЁННО") {
		findings = append(findings, "перечень поводов в приёмке "+normPath+" не найден — "+
			"комментарий отсылает туда, где предмета нет")
	}
	return findings, judged
}

func TestSweepFindingCommentPointsAtTheNormNotASubset(t *testing.T) {
	constDoc, headerRow := findingComment(t, sweepFile)
	findings, judged := auditFindingComment(constDoc, headerRow, normDoc)
	for _, f := range findings {
		t.Error(f)
	}
	if judged == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: мест, описывающих код находки, прочитано %d из 2 · находок %d", judged, len(findings))
}

// TestSweepFindingComment_CanFailAndStaysSilent — способность упасть и смолчать.
func TestSweepFindingComment_CanFailAndStaysSilent(t *testing.T) {
	good := "SweepFinding — находка: любой повод перечня " + normAnchor + " приёмки.\n"

	cases := []struct {
		name      string
		constDoc  string
		headerRow string
		norm      string
		want      string
		why       string
	}{
		{
			name: "законный близнец: отсылка к перечню", constDoc: good, headerRow: good, norm: normDoc,
			why: "положительный контроль: без него всякое красное ниже могло бы приходить от самого разбора",
		},
		{
			name:      "перечисление подмножеством",
			constDoc:  "SweepFinding — расхождение либо модуль без манифеста и без записи ведомости (" + normAnchor + ").\n",
			headerRow: good, norm: normDoc,
			want: "перечисляет поводы подмножеством",
			why:  "ровно предмет #1856: комментарий пережил решение и называет два повода из тринадцати",
		},
		{
			name:      "заглавная форма разделителя",
			constDoc:  "SweepFinding — расхождение ЛИБО модуль без манифеста (" + normAnchor + ").\n",
			headerRow: good, norm: normDoc,
			want: "перечисляет поводы подмножеством",
			why: "распознаватель обязан знать ОБЕ формы записи разделителя: строчную у константы и " +
				"заглавную в таблице шапки — знай он одну, вторая была бы вне наблюдения",
		},
		{
			name: "координата перечня не названа", constDoc: "SweepFinding — находка.\n", headerRow: good, norm: normDoc,
			want: "не называет координату перечня",
			why:  "без координаты читателю некуда пойти за поводами, и он достроит их сам",
		},
		{
			name: "координата ведёт в никуда", constDoc: good, headerRow: good, norm: "../../docs/нет-такого.md",
			want: "не читается",
			why:  "отсылка к перечню обязана резолвиться, иначе она такая же форма без содержания",
		},
		{
			name: "комментария нет вовсе", constDoc: "", headerRow: "", norm: normDoc,
			want: "обход пуст",
			why:  "«находок 0» обязано быть отличимо от «прочитано 0»",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, _ := auditFindingComment(tc.constDoc, tc.headerRow, tc.norm)
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("разбор нашёл на законном близнеце то, чего в нём нет — первое же ложное "+
						"срабатывание снимает гейт.\nнаходки:\n  %s", strings.Join(findings, "\n  "))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("разбор смолчал на инъекции — он НЕ способен упасть по этой оси.\n"+
					"что должно было ловиться: %s", tc.why)
			}
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("разбор покраснел не на том: ждали %q\nнаходки:\n  %s",
					tc.want, strings.Join(findings, "\n  "))
			}
		})
	}
}
