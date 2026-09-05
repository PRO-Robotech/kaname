// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/validate/nameform"
)

// resource_name_canon_test.go — шесть именуемых типов iam судятся ЕДИНСТВЕННОЙ
// формой имени дерева (задача #1279, канон заведён #715).
//
// Предмет. Форма имени объявлялась в iam ВТОРОЙ раз и своим текстом
// (`^[a-z][-a-z0-9]{2,62}$`), поэтому гейт единственности формы её не видел:
// он ловит байт-идентичную копию канона, а не независимую выдумку — свою
// слепую зону он называет сам. Расхождение с каноном шло по трём осям, и все
// три наблюдались арендатором: пустое имя отвергалось вместо подстановки
// умолчания, минимальная длина была 3 вместо 1, ведущая цифра запрещалась.
// Один контракт, разное исполнение: одинаковый запрос к iam и к vpc давал
// разный ответ.
//
// Почему проба поведенческая, а не текстовая. Гейт дерева читает ОБЪЯВЛЕНИЯ и
// по построению не заметит третью форму, написанную иначе. Утверждение здесь —
// про ИСХОД проверки на каждом из шести типов: вернись любая своя регулярка,
// и хотя бы одна ось покраснеет независимо от того, как её записали.
//
// Каждая ось несёт ОБЕ стороны: без положительного контроля отрицание зеленеет
// на валидаторе, отвергающем всё, а без отрицания — на валидаторе, не
// отвергающем ничего.

// namedType — именуемый тип iam и его проверка формы.
type namedType struct {
	label    string
	validate func(string) error
}

// canonNamedTypes — все шесть типов, судимых единственной формой.
//
// Перечень выписан, а не выведен: вывести его из дерева значило бы спросить у
// той же реализации, которую проба и проверяет. Зато он проверяем — предикат
// назван в задаче: `grep -n 'validateResourceName' services/iam/internal/domain`.
//
// Имя роли (`RoleName`) в перечень НЕ входит намеренно: `roles/vpc.admin` —
// идентификатор, на который ссылаются привязки, а не косметическая метка.
// Это записанное решение (#715, комментарий владельца), и гейт единственности
// формы выводит идентификатор роли из-под себя тем же основанием.
var canonNamedTypes = []namedType{
	{"AccountName", func(v string) error { return AccountName(v).Validate() }},
	{"ProjectName", func(v string) error { return ProjectName(v).Validate() }},
	{"GroupName", func(v string) error { return GroupName(v).Validate() }},
	{"SvcAccountName", func(v string) error { return SvcAccountName(v).Validate() }},
	{"OAuthClientName", func(v string) error { return OAuthClientName(v).Validate() }},
	{"InteractiveClientName", func(v string) error { return InteractiveClientName(v).Validate() }},
}

// canonAccepted / canonRejected — образцы по трём осям расхождения плюс общие
// границы формы. Сверяются с ЕДИНСТВЕННЫМ объявлением канона, а не с
// представлением автора о нём: иначе перечень стал бы вторым местом об одном
// предмете и утверждал бы про прежнюю форму уверенно.
var canonAccepted = []struct{ label, value string }{
	{"ось 1: цифра первым символом", "9lives"},
	{"ось 2: один символ", "a"},
	{"ось 3: дефис в середине", "trail-x"},
	{"обычное имя", "probe-name"},
	{"ровно 63 символа", strings.Repeat("b", 63)},
}

var canonRejected = []struct{ label, value string }{
	{"пустое имя", ""},
	{"ось 3: дефис последним символом", "trail-"},
	{"дефис первым символом", "-lead"},
	{"заглавные буквы", "Bad-Name"},
	{"подчёркивание", "bad_name"},
	{"длиннее 63 символов", strings.Repeat("a", 64)},
}

// TestCanonSamplesAgreeWithTheSingleDeclaration — предпосылка пробы.
//
// Образцы обязаны соответствовать тому, что объявляет канон. Разойдись они — и
// всё нижеследующее утверждало бы про форму, которой в дереве нет, причём
// утверждало бы уверенно.
func TestCanonSamplesAgreeWithTheSingleDeclaration(t *testing.T) {
	for _, s := range canonAccepted {
		if !nameform.OK(s.value) {
			t.Errorf("%s (%q): объявлен здесь каноничным, но nameform.Form (%s) его ОТВЕРГАЕТ",
				s.label, s.value, nameform.Form)
		}
	}
	for _, s := range canonRejected {
		if nameform.OK(s.value) {
			t.Errorf("%s (%q): объявлен здесь негодным, но nameform.Form (%s) его ПРИНИМАЕТ",
				s.label, s.value, nameform.Form)
		}
	}
	t.Logf("образцов сверено с каноном: принимаемых %d, отвергаемых %d",
		len(canonAccepted), len(canonRejected))
}

// TestNamedTypesObeyTheSingleNameForm — шесть типов судят имя каноном, а не
// своей формой.
func TestNamedTypesObeyTheSingleNameForm(t *testing.T) {
	if len(canonNamedTypes) == 0 {
		t.Fatal("именуемых типов в перечне 0 — утверждать не о чем; " +
			"молчаливый зелёный здесь означал бы «проверено»")
	}

	checked := 0
	for _, nt := range canonNamedTypes {
		t.Run(nt.label, func(t *testing.T) {
			for _, s := range canonAccepted {
				if err := nt.validate(s.value); err != nil {
					t.Errorf("%s ОТВЕРГ каноничное имя — %s (%q): %v",
						nt.label, s.label, s.value, err)
				}
			}
			for _, s := range canonRejected {
				if err := nt.validate(s.value); err == nil {
					t.Errorf("%s ПРИНЯЛ негодное имя — %s (%q)", nt.label, s.label, s.value)
				}
			}
		})
		checked++
	}
	t.Logf("осмотрено именуемых типов: %d; на каждом утверждений: %d принимаемых + %d отвергаемых",
		checked, len(canonAccepted), len(canonRejected))
}

// TestNameRejectionNamesTheSingleForm — текст отказа называет ту форму, которая
// действует.
//
// Отказ, называющий форму, которой в дереве нет, посылает арендатора чинить имя
// по несуществующему правилу — и переживает свой предмет молча: ни один тест
// формы на такой текст не краснеет.
func TestNameRejectionNamesTheSingleForm(t *testing.T) {
	for _, nt := range canonNamedTypes {
		err := nt.validate("Bad_Name")
		if err == nil {
			t.Errorf("%s: негодное имя принято — текст отказа проверять не на чем", nt.label)
			continue
		}
		if !strings.Contains(err.Error(), nameform.Form) {
			t.Errorf("%s: отказ не называет действующую форму (%s): %q",
				nt.label, nameform.Form, err.Error())
		}
	}
	t.Logf("осмотрено текстов отказа: %d", len(canonNamedTypes))
}
