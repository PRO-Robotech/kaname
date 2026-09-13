// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_flush_parity_injection_test.go — доказательство, что гейт
// полосы производителей СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17,
// семейство `subjectchangeflushparity`).
//
// Гейт зелен на сегодняшнем дереве, и это не доказывает ничего. Поэтому его
// извлечение прогоняется здесь на синтетике, где ответ известен заранее, и
// зовётся ТА ЖЕ функция, что и гейтом, а не её копия.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestSubjectChangeProducerRecognizer_InjectionBothWays — РАСПОЗНАВАТЕЛЬ: обе
// законные формы обращения считаются, а слово в прозе — нет.
func TestSubjectChangeProducerRecognizer_InjectionBothWays(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			// ФОРМА 1 — вызов на месте.
			name: "вызов на месте — производитель",
			src: `package api
func f(ctx C, w W) { _ = w.AccessBindingsW().EmitSubjectChangeEvent(ctx, e{}) }
`,
			want: 1,
		},
		{
			// ФОРМА 2 — метод передан ЗНАЧЕНИЕМ общему развёртывателю. Именно её
			// предок сперва не видел: два живых производителя пропадали из
			// переписи не находкой, а НЕВИДИМОСТЬЮ. В этом дереве форма живая —
			// её несут delete.go и revoke.go.
			name: "метод передан значением — тоже производитель",
			src: `package api
func f(ctx C, w W) { _ = fanout(ctx, w.AccessBindings().ListSubjects, w.AccessBindingsW().EmitSubjectChangeEvent) }
`,
			want: 1,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: имя стоит в комментарии и в строке. Предикат по
			// подстроке краснел бы на собственном объяснении механизма.
			name: "имя в комментарии и в строковом литерале — НЕ производитель",
			src: `package api
// EmitSubjectChangeEvent пишет строку очереди смены субъекта.
func f() { _ = "EmitSubjectChangeEvent" }
`,
			want: 0,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: соседний метод того же порта.
			name: "соседний метод порта — НЕ производитель",
			src: `package api
func f(ctx C, w W) { _ = w.AccessBindingsW().EmitSomethingElse(ctx) }
`,
			want: 0,
		},
		{
			// Обе формы в одном файле считаются по разу каждая и ни одна дважды:
			// узел вызова СОДЕРЖИТ узел обращения, и счёт по вызовам дал бы
			// здесь три вместо двух.
			name: "обе формы в одном файле — по разу каждая",
			src: `package api
func f(ctx C, w W) {
	_ = w.AccessBindingsW().EmitSubjectChangeEvent(ctx, e{})
	_ = fanout(ctx, w.AccessBindingsW().EmitSubjectChangeEvent)
}
`,
			want: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := check.SubjectChangeProducersIn("internal/apps/kaname/api/x/y.go", tc.src)
			if err != nil {
				t.Fatalf("фикстура обязана разбираться: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("обращений найдено %d, ожидалось %d — распознаватель либо слеп "+
					"к законной форме, либо считает то, что производителем не является: %v",
					len(got), tc.want, got)
			}
			for _, p := range got {
				if p.Line == 0 {
					t.Fatalf("обращение без координаты: %+v — находка без неё посылает "+
						"читателя искать самому", p)
				}
			}
		})
	}
}

// TestSubjectChangeProducerFileFilter_InjectionBothWays — ОХВАТ: проба
// производителем не является, и чужой слой тоже.
func TestSubjectChangeProducerFileFilter_InjectionBothWays(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rel  string
		want bool
	}{
		{"internal/apps/kaname/api/group/add_member.go", true},
		// Проба называет производителя как ПРЕДМЕТ своей проверки; считать её
		// значило бы требовать самосброса по методу, которого нет в продукте.
		{"internal/apps/kaname/api/group/add_member_test.go", false},
		// Слой репозитория объявляет и реализует САМ метод; его объявление
		// производителем очереди не является.
		{"internal/repo/kaname/pg/access_binding_repo.go", false},
		{"internal/apps/kaname/api", false},
		{"internal/apps/kaname/apifoo/x.go", false},
	}
	for _, tc := range cases {
		if got := check.IsSubjectChangeProducerFile(tc.rel); got != tc.want {
			t.Errorf("%s: охват %v, ожидался %v", tc.rel, got, tc.want)
		}
	}
}

// TestSubjectChangeRoster_InjectionBothWays — СВЕРКА перечня с разбором, по
// каждой оси дефект и законный близнец.
func TestSubjectChangeRoster_InjectionBothWays(t *testing.T) {
	t.Parallel()

	p := func(file string, lines ...int) []check.SubjectChangeProducer {
		out := make([]check.SubjectChangeProducer, 0, len(lines))
		for _, l := range lines {
			out = append(out, check.SubjectChangeProducer{File: file, Line: l})
		}
		return out
	}
	base := map[string]int{"a/create.go": 1, "b/add_member.go": 1}

	t.Run("перечень сошёлся с разбором — гейт молчит", func(t *testing.T) {
		t.Parallel()
		found := append(p("a/create.go", 10), p("b/add_member.go", 20)...)
		if d := check.CompareSubjectChangeRoster(found, base); !d.Empty() {
			t.Fatalf("законный вход объявлен находкой: %+v", d)
		}
	})

	t.Run("НОВЫЙ файл-производитель — находка с координатой", func(t *testing.T) {
		t.Parallel()
		found := append(append(p("a/create.go", 10), p("b/add_member.go", 20)...),
			p("c/revoke.go", 30)...)
		d := check.CompareSubjectChangeRoster(found, base)
		if len(d.Undeclared) != 1 {
			t.Fatalf("шестой производитель обязан краснить: %+v", d)
		}
		if !strings.Contains(d.Undeclared[0], "c/revoke.go") {
			t.Fatalf("находка обязана называть координату: %q", d.Undeclared[0])
		}
		if len(d.Stale) != 0 {
			t.Fatalf("пополнение не есть устаревание: %+v", d.Stale)
		}
	})

	t.Run("ВТОРОЕ обращение в уже объявленном файле — тоже находка", func(t *testing.T) {
		t.Parallel()
		// Ось, которую перечень «по именам файлов» пропустил бы молча: полоса
		// пополняется вторым обращением ровно так же, как первым в новом файле.
		found := append(p("a/create.go", 10, 44), p("b/add_member.go", 20)...)
		d := check.CompareSubjectChangeRoster(found, base)
		if len(d.Undeclared) != 1 || !strings.Contains(d.Undeclared[0], "обращений 2, объявлено 1") {
			t.Fatalf("второе обращение в объявленном файле обязано краснить: %+v", d)
		}
	})

	t.Run("записи перечня нечего называть — находка: послабление истекает само", func(t *testing.T) {
		t.Parallel()
		found := p("a/create.go", 10)
		d := check.CompareSubjectChangeRoster(found, base)
		if len(d.Stale) != 1 || !strings.Contains(d.Stale[0], "b/add_member.go") {
			t.Fatalf("исчезнувший производитель обязан краснить записью перечня: %+v", d)
		}
		if len(d.Undeclared) != 0 {
			t.Fatalf("исчезновение не есть пополнение: %+v", d.Undeclared)
		}
	})

	t.Run("обращений стало меньше в объявленном файле — находка", func(t *testing.T) {
		t.Parallel()
		found := append(p("a/create.go", 10), p("b/add_member.go", 20)...)
		two := map[string]int{"a/create.go": 2, "b/add_member.go": 1}
		d := check.CompareSubjectChangeRoster(found, two)
		if len(d.Stale) != 1 || !strings.Contains(d.Stale[0], "обращений 1, объявлено 2") {
			t.Fatalf("убыль обязана краснить: %+v", d)
		}
	})

	t.Run("перечень пуст, а производители есть — находка, а не зелёный", func(t *testing.T) {
		t.Parallel()
		d := check.CompareSubjectChangeRoster(p("a/create.go", 10), map[string]int{})
		if len(d.Undeclared) != 1 {
			t.Fatalf("пустой перечень при живых производителях обязан краснить: %+v", d)
		}
	})

	t.Run("перепись перечня считает ОБРАЩЕНИЯ, а не файлы", func(t *testing.T) {
		t.Parallel()
		if got := check.SubjectChangeRosterTotal(map[string]int{"a.go": 2, "b.go": 3}); got != 5 {
			t.Fatalf("перечень объявляет %d обращений, а их пять — перепись назвала бы "+
				"краю неверную величину", got)
		}
	})
}

// TestSubjectChangeSelfFlushDetector_InjectionBothWays — ВТОРАЯ ПОЛОСА: судится
// узел ОБЪЯВЛЕНИЯ, а не вхождение имени.
//
// Ось заведена по НАСТУПИВШЕМУ дефекту, а не впрок. Первая редакция гейта искала
// имя подстрокой и на первом же прогоне после посадки нашла собственное
// объявление координаты (`SelfFlushSetName = "subjectChangingFQNs"`) — то есть
// объявила, что вторая полоса приехала в это дерево, покраснев на своём же
// объяснении.
func TestSubjectChangeSelfFlushDetector_InjectionBothWays(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			// ДЕФЕКТ (он же законное будущее): набор ОБЪЯВЛЕН здесь — вторая
			// полоса приехала, и гейт обязан перестать быть половиной.
			name: "объявление набора — вторая полоса здесь",
			src: `package middleware
var subjectChangingFQNs = map[string]bool{"S/Create": true}
`,
			want: true,
		},
		{
			name: "объявление через var-блок — тоже объявление",
			src: `package middleware
var (
	other              = 1
	subjectChangingFQNs = map[string]bool{}
)
`,
			want: true,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ, на котором дефект и наступил: имя стоит
			// СТРОКОЙ — это координата чужой полосы, а не она сама.
			name: "имя в строковом литерале — координата, а не объявление",
			src: `package check
const SelfFlushSetName = "subjectChangingFQNs"
`,
			want: false,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: имя в комментарии и в тексте отказа.
			name: "имя в комментарии и в сообщении — не объявление",
			src: `package check
// subjectChangingFQNs — набор самосброса у края.
func f() string { return "набор subjectChangingFQNs живёт у края" }
`,
			want: false,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: похожее имя. Судится имя целиком, а не приставка.
			name: "похожее имя — не оно",
			src: `package middleware
var subjectChangingFQNsLegacy = map[string]bool{}
`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := check.DeclaresSelfFlushSet("x/y.go", tc.src)
			if err != nil {
				t.Fatalf("фикстура обязана разбираться: %v", err)
			}
			if got != tc.want {
				t.Fatalf("объявление набора: %v, ожидалось %v — распознаватель судит слово "+
					"вместо узла, и «вторая полоса здесь» означало бы «имя где-то упомянуто»",
					got, tc.want)
			}
		})
	}
}
