// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ascii_identifiers_injection_test.go — доказательство способности
// TestIdentifiersAreASCII упасть и смолчать.
//
// Обе стороны гоняют ТУ ЖЕ функцию, что и гейт по дереву
// (check.ScanNonASCIIIdents), на синтетических исходниках. Каждый мир отличается
// от своего законного близнеца ОДНИМ фактом: иначе неизвестно, какой из двух дал
// красное.
//
// Инъекция роняет ТОЛЬКО проверяемое: синтетика живёт в памяти пробы, дерева не
// касается и ни одного соседнего гейта не задевает.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestIdentifiersASCIIGateTellsNameFromText — собственная предпосылка гейта: он
// ловит ИМЯ, а не знак.
//
// Без этой пробы «нет находок» означало бы и «имена латинские», и «разбор ничего
// не увидел». Обе стороны утверждаются по каждой оси: дефект обязан находиться,
// законный близнец обязан молчать.
func TestIdentifiersASCIIGateTellsNameFromText(t *testing.T) {
	t.Parallel()

	const withDefect = `package p

func собрать(вход string) string { return вход }
`
	// Законный близнец: та же кириллица, но НЕ в именах. Каждая форма ниже
	// встречается в дереве службы тысячами и обязана остаться нетронутой — им
	// написан весь разбор находок.
	const legitimate = `package p

// Разбор по-русски: почему здесь именно так.

/* Документация тоже по-русски. */

var label = "Управление доступом"

var byKey = map[string]int{"имя": 1}

func refuse() string { return "субъект не найден" }
`

	seen, found, err := check.ScanNonASCIIIdents("withdefect.go", []byte(withDefect))
	if err != nil {
		t.Fatalf("синтетика с дефектом не разобралась: %v", err)
	}
	// собрать (объявление), вход (параметр), вход (возврат) — три узла-имени.
	if len(found) != 3 {
		t.Errorf("дефект обязан находиться: имён осмотрено %d, находок %d, ожидалось 3: %v",
			seen, len(found), found)
	}
	for _, f := range found {
		if !strings.Contains(f.Position, "withdefect.go") {
			t.Errorf("находка не называет координату: %+v — находка без координаты не есть действие", f)
		}
	}

	seen, found, err = check.ScanNonASCIIIdents("legit.go", []byte(legitimate))
	if err != nil {
		t.Fatalf("законная синтетика не разобралась: %v", err)
	}
	// Положительный контроль: имена в близнеце ЕСТЬ и осмотрены — значит «ноль
	// находок» означает отсутствие предмета, а не пустой разбор.
	if seen == 0 {
		t.Fatal("близнец не дал ни одного имени — «молчит» неотличимо от «не читал»")
	}
	if len(found) != 0 {
		t.Errorf("кириллица в комментарии, строковом литерале и ключе-строке законна, "+
			"а разбор нашёл %d: %v", len(found), found)
	}
}

// TestIdentifiersASCIIGateCatchesTheHomoglyph — ОМОГЛИФ: кириллическое «с»
// вместо латинского «c».
//
// Глазом два имени неотличимы — ради этого случая гейт и заведён, и поэтому
// омоглиф стоит отдельной пробой, а не строкой в общей. Рядом — законный
// близнец, отличающийся ОДНИМ фактом: то же имя, записанное латиницей.
func TestIdentifiersASCIIGateCatchesTheHomoglyph(t *testing.T) {
	t.Parallel()

	const homoglyph = "package p\n\nvar сount = 1\n" // «с» кириллическая
	const latinTwin = "package p\n\nvar count = 1\n" // та же строка, латиница

	_, found, err := check.ScanNonASCIIIdents("homoglyph.go", []byte(homoglyph))
	if err != nil {
		t.Fatalf("синтетика с омоглифом не разобралась: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("омоглиф обязан находиться — он и есть предмет гейта; находок %d: %v",
			len(found), found)
	}
	if found[0].Rune != 'с' {
		t.Errorf("находка не называет сам знак (%q) — без него читатель не увидит, "+
			"чем имя отличается от латинского двойника", found[0].Rune)
	}

	seen, found, err := check.ScanNonASCIIIdents("latin.go", []byte(latinTwin))
	if err != nil {
		t.Fatalf("законный близнец не разобрался: %v", err)
	}
	if seen == 0 {
		t.Fatal("у близнеца не осмотрено ни одного имени — молчание беспредметно")
	}
	if len(found) != 0 {
		t.Errorf("латинский двойник объявлен находкой: %v", found)
	}
}

// TestIdentifiersASCIIGateSeesEveryFormOfAName — формы имени, которые легко
// ускользают от поиска по образцу.
//
// Разбор видит их все как узел-идентификатор, но УТВЕРЖДАТЬ это надо, а не
// полагать: форма, о которой распознаватель не знает, даёт не красное и не
// зелёное, а молчание (`testing.md` §«Гейт на класс», п. 7). У каждой формы
// стоит законный близнец — та же конструкция с латинским именем и кириллицей в
// комментарии рядом.
func TestIdentifiersASCIIGateSeesEveryFormOfAName(t *testing.T) {
	t.Parallel()
	forms := []struct {
		name   string
		defect string
		want   string
		twin   string
	}{
		{
			name:   "поле структуры",
			defect: "package p\n\ntype T struct{ поле string }\n",
			want:   "поле",
			twin:   "package p\n\ntype T struct{ field string } // поле имени\n",
		},
		{
			name:   "метод",
			defect: "package p\n\ntype T struct{}\n\nfunc (T) метод() {}\n",
			want:   "метод",
			twin:   "package p\n\ntype T struct{}\n\n// метод разбора\nfunc (T) method() {}\n",
		},
		{
			name:   "константа",
			defect: "package p\n\nconst Предел = 1\n",
			want:   "Предел",
			twin:   "package p\n\n// Предел набора\nconst Limit = 1\n",
		},
		{
			name:   "параметр типа",
			defect: "package p\n\nfunc f[Тип any](x Тип) Тип { return x }\n",
			want:   "Тип",
			twin:   "package p\n\n// Тип задаётся вызывающим\nfunc f[T any](x T) T { return x }\n",
		},
		{
			name:   "псевдоним импорта",
			defect: "package p\n\nimport фмт \"fmt\"\n\nvar _ = фмт.Sprint\n",
			want:   "фмт",
			twin:   "package p\n\n// печать по-русски\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n",
		},
		{
			name:   "имя в объявлении группой",
			defect: "package p\n\nvar (\n\tживой = 1\n\tdead  = 2\n)\n",
			want:   "живой",
			twin:   "package p\n\nvar (\n\talive = 1 // живой\n\tdead  = 2\n)\n",
		},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			t.Parallel()
			_, found, err := check.ScanNonASCIIIdents("form.go", []byte(form.defect))
			if err != nil {
				t.Fatalf("синтетика не разобралась: %v", err)
			}
			var hit bool
			for _, f := range found {
				if strings.Contains(f.Name, form.want) {
					hit = true
				}
			}
			if !hit {
				t.Errorf("имя %q обязано находиться, найдено: %v — эта форма вне "+
					"наблюдения, и написанное в ней не находка и не чистота",
					form.want, found)
			}

			seen, found, err := check.ScanNonASCIIIdents("twin.go", []byte(form.twin))
			if err != nil {
				t.Fatalf("законный близнец не разобрался: %v", err)
			}
			if seen == 0 {
				t.Fatal("у близнеца не осмотрено ни одного имени — молчание беспредметно")
			}
			if len(found) != 0 {
				t.Errorf("законный близнец (латинское имя, кириллица в комментарии) "+
					"объявлен находкой: %v", found)
			}
		})
	}
	t.Logf("осмотрено: форм имени %d, у каждой дефект и законный близнец", len(forms))
}

// TestIdentifiersASCIIGateRefusesAnUnparsableSource — неразбираемый исходник
// отдаёт ПРИЗНАК, а не пустой успех.
//
// Без этого «имён осмотрено 0, находок 0» читалось бы как чистый файл, и целый
// исходник уходил бы из-под наблюдения молча. Признак нужен гейту, чтобы
// назвать такой файл в переписи отдельной величиной.
func TestIdentifiersASCIIGateRefusesAnUnparsableSource(t *testing.T) {
	t.Parallel()
	seen, found, err := check.ScanNonASCIIIdents("broken.go", []byte("package p\n\nfunc {\n"))
	if err == nil {
		t.Fatalf("неразбираемый исходник прошёл БЕЗ признака: осмотрено %d, находок %d — "+
			"тогда «находок нет» означает «разбор не состоялся», и отличить это нечем",
			seen, len(found))
	}
	if seen != 0 || len(found) != 0 {
		t.Errorf("при отказе разбор всё же что-то насчитал: осмотрено %d, находок %d", seen, len(found))
	}
}
