// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sibling_break_test.go — запись перечня прощает РОВНО ТОТ разрыв, который
// называет, и не прощает соседний разрыв того же правила в том же файле
// (задача kaname#474).
//
// ПРЕДМЕТ. Символ находки брался первым кавычечным вхождением вида имени, а
// сопоставление искало первую подходящую запись, не спрашивая, простила ли она
// уже что-то. Отсюда два независимых пути, которыми одна запись прощала больше
// одного разрыва:
//
//   - символ не различал соседей. У снятия и у переименования значения
//     перечисления buf печатает только НОМЕР значения, и символом становилось само
//     перечисление; у снятия поля символом было имя поля без объемлющего
//     сообщения; у переименования поля — само сообщение. Запись о значении 4
//     прощала снятие любого значения того же словаря;
//   - запись не расходовалась. Даже при точном символе одна запись прощала
//     сколько угодно находок с тем же символом — у находки, чьё сообщение
//     объемлющего символа не называет вовсе, различить их нечем.
//
// ВХОД НАСТОЯЩИЙ. Каждая фикстура `testdata/sibling/*.jsonl` снята
// `buf breaking 1.72.0 --error-format=json` по СОБСТВЕННЫМ контрактам этого
// дерева (`proto/` ревизии 8f95be6c6acb): в копии `proto/` сделана одна правка, база
// сравнения — нетронутый `proto/`. Правки:
//
//	enum-value-4-deleted              — снято значение 4 словаря CredentialKind
//	enum-values-3-4-deleted           — сняты значения 3 и 4 того же словаря
//	enum-value-4-renamed              — переименовано значение 4
//	enum-values-3-4-renamed           — переименованы значения 3 и 4
//	field-deleted-in-one-message      — снято поле page_size в ListRolesRequest
//	field-deleted-in-two-messages     — и одноимённое поле в ListRoleOperationsRequest
//	field-1-renamed                   — поле 1 ListRolesRequest переименовано
//	fields-1-2-renamed-in-one-message — и поле 2 того же сообщения
//	accessor-dropped-in-one-message   — no_standard_descriptor_accessor в ListRolesRequest
//	accessor-dropped-in-two-messages  — и в ListRoleOperationsRequest
//	reserved-name-and-range-deleted   — сняты `reserved 7; reserved "organization_id";` у Account
//	required-field-2-deleted          — снято обязательное поле 2 сообщения RequiredProbe
//	required-fields-1-2-deleted       — сняты обязательные поля 1 и 2 того же сообщения
//
// Обязательных полей в контрактах дерева нет (proto3), а форма сообщения buf о
// них своя — контейнер стоит ПЕРВЫМ. Для этой пары и в базу, и в правку добавлен
// один и тот же файл `kaname/cloud/iam/v1/required_probe.proto` (proto2, сообщение
// RequiredProbe с полями `required string a = 1; required string b = 2;`); правка
// снимает поля. Остальные контракты — те же.
//
// Пара «один разрыв / он же и сосед» отличается РОВНО ОДНИМ фактом — вторым
// снятым соседом. Фикстуры пары сняты ОТДЕЛЬНЫМИ прогонами, а не вырезаны одна из
// другой: строка одного и того же разрыва в двух прогонах у buf различается
// концом диапазона (`end_line`), и вырезанная копия была бы сочинённой.
package declaredbreak_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/tools/declaredbreak"
)

const (
	credentialKindProto = "kaname/cloud/iam/v1/credential_kind.proto"
	roleServiceProto    = "kaname/cloud/iam/v1/role_service.proto"
	requiredProbeProto  = "kaname/cloud/iam/v1/required_probe.proto"
)

func siblingFindings(t *testing.T, name string) []declaredbreak.Finding {
	t.Helper()
	p := filepath.Join("testdata", "sibling", name+".jsonl")
	f, err := os.Open(p) // #nosec G304 -- путь фикстуры задан пробой
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: фикстура настоящего вывода buf %s не прочитана: %v", p, err)
	}
	defer func() { _ = f.Close() }()
	got, err := declaredbreak.ParseFindings(f)
	if err != nil {
		t.Fatalf("настоящий вывод buf %s не разобран: %v", p, err)
	}
	if len(got) == 0 {
		t.Fatalf("фикстура %s пуста — инъекция беспредметна", p)
	}
	return got
}

func declared(rule, path, symbol string) declaredbreak.Declaration {
	return declaredbreak.Declaration{
		Rule: rule, Path: path, Symbol: symbol,
		Reason: "разрыв объявлен пробой полосы kaname#474 ровно для этого символа",
		Issue:  "kaname#474",
	}
}

func coordinates(fs []declaredbreak.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Coordinate())
	}
	sort.Strings(out)
	return out
}

func declCoordinates(ds []declaredbreak.Declaration) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Rule+" "+d.Path+" "+d.Symbol)
	}
	sort.Strings(out)
	return out
}

type siblingCase struct {
	name string
	// one — вывод buf с объявленным разрывом, two — тот же разрыв плюс сосед.
	one, two string
	// decls — записи в форме символа, которую называет шапка перечня.
	decls []declaredbreak.Declaration
	// sibling — координаты соседей: на `two` они обязаны остаться вне перечня.
	sibling []declaredbreak.Declaration
	// former — те же записи в ПРЕЖНЕЙ форме символа, которой дефект и прощал
	// соседа. nil — прежняя форма совпадает с нынешней, и дефект был только в
	// том, что запись не расходовалась.
	former []declaredbreak.Declaration
}

var siblingCases = []siblingCase{
	{
		name: "снятие значения перечисления",
		one:  "enum-value-4-deleted", two: "enum-values-3-4-deleted",
		decls:   []declaredbreak.Declaration{declared("ENUM_VALUE_NO_DELETE", credentialKindProto, "CredentialKind.4")},
		sibling: []declaredbreak.Declaration{declared("ENUM_VALUE_NO_DELETE", credentialKindProto, "CredentialKind.3")},
		former:  []declaredbreak.Declaration{declared("ENUM_VALUE_NO_DELETE", credentialKindProto, "CredentialKind")},
	},
	{
		name: "снятие одноимённого поля соседнего сообщения",
		one:  "field-deleted-in-one-message", two: "field-deleted-in-two-messages",
		decls:   []declaredbreak.Declaration{declared("FIELD_NO_DELETE", roleServiceProto, "ListRolesRequest.1")},
		sibling: []declaredbreak.Declaration{declared("FIELD_NO_DELETE", roleServiceProto, "ListRoleOperationsRequest.2")},
		former:  []declaredbreak.Declaration{declared("FIELD_NO_DELETE", roleServiceProto, "page_size")},
	},
	{
		name: "переименование значения перечисления",
		one:  "enum-value-4-renamed", two: "enum-values-3-4-renamed",
		decls:   []declaredbreak.Declaration{declared("ENUM_VALUE_SAME_NAME", credentialKindProto, "CredentialKind.4")},
		sibling: []declaredbreak.Declaration{declared("ENUM_VALUE_SAME_NAME", credentialKindProto, "CredentialKind.3")},
		former:  []declaredbreak.Declaration{declared("ENUM_VALUE_SAME_NAME", credentialKindProto, "CredentialKind")},
	},
	{
		name: "переименование соседнего поля того же сообщения",
		one:  "field-1-renamed", two: "fields-1-2-renamed-in-one-message",
		decls: []declaredbreak.Declaration{
			declared("FIELD_SAME_JSON_NAME", roleServiceProto, "ListRolesRequest.1"),
			declared("FIELD_SAME_NAME", roleServiceProto, "ListRolesRequest.1"),
		},
		sibling: []declaredbreak.Declaration{
			declared("FIELD_SAME_JSON_NAME", roleServiceProto, "ListRolesRequest.2"),
			declared("FIELD_SAME_NAME", roleServiceProto, "ListRolesRequest.2"),
		},
		former: []declaredbreak.Declaration{
			declared("FIELD_SAME_JSON_NAME", roleServiceProto, "page_limit"),
			declared("FIELD_SAME_NAME", roleServiceProto, "ListRolesRequest"),
		},
	},
	{
		name: "снятие соседнего обязательного поля",
		one:  "required-field-2-deleted", two: "required-fields-1-2-deleted",
		decls: []declaredbreak.Declaration{
			declared("FIELD_NO_DELETE", requiredProbeProto, "RequiredProbe.2"),
			declared("MESSAGE_SAME_REQUIRED_FIELDS", requiredProbeProto, "RequiredProbe.2"),
		},
		sibling: []declaredbreak.Declaration{
			declared("FIELD_NO_DELETE", requiredProbeProto, "RequiredProbe.1"),
			declared("MESSAGE_SAME_REQUIRED_FIELDS", requiredProbeProto, "RequiredProbe.1"),
		},
		former: []declaredbreak.Declaration{
			declared("FIELD_NO_DELETE", requiredProbeProto, "b"),
			declared("MESSAGE_SAME_REQUIRED_FIELDS", requiredProbeProto, "RequiredProbe"),
		},
	},
	{
		name: "параметр сообщения, чьё имя buf не печатает",
		one:  "accessor-dropped-in-one-message", two: "accessor-dropped-in-two-messages",
		decls: []declaredbreak.Declaration{declared("MESSAGE_NO_REMOVE_STANDARD_DESCRIPTOR_ACCESSOR",
			roleServiceProto, "no_standard_descriptor_accessor")},
		sibling: []declaredbreak.Declaration{declared("MESSAGE_NO_REMOVE_STANDARD_DESCRIPTOR_ACCESSOR",
			roleServiceProto, "no_standard_descriptor_accessor")},
	},
}

// TestDeclarationForgivesItsOwnBreakOnly — ЗАКОННЫЙ БЛИЗНЕЦ и ИНЪЕКЦИЯ на одной
// записи. Близнец: объявлен ровно тот разрыв, который наступил, — зелёное.
// Инъекция: наступил ещё и сосед того же правила в том же файле — сосед обязан
// остаться вне перечня, а запись — простить ровно свой разрыв.
func TestDeclarationForgivesItsOwnBreakOnly(t *testing.T) {
	var findingsRead int
	for _, c := range siblingCases {
		t.Run(c.name, func(t *testing.T) {
			one := siblingFindings(t, c.one)
			two := siblingFindings(t, c.two)
			findingsRead += len(one) + len(two)

			twin := declaredbreak.Adjudicate(one, c.decls)
			if !twin.Clean() || twin.Matched != len(one) {
				t.Errorf("законный близнец покраснел: объявлен ровно наступивший разрыв %v, "+
					"символы находок %v\n%s", declCoordinates(c.decls), coordinates(one), twin.Report())
			}

			inj := declaredbreak.Adjudicate(two, c.decls)
			if inj.Clean() {
				t.Fatalf("соседний разрыв прощён записью, которая его не называет: записей %d, "+
					"прощено %d\n%s", len(c.decls), inj.Matched, inj.Report())
			}
			if got, want := coordinates(inj.Undeclared), declCoordinates(c.sibling); strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("вне перечня обязан остаться РОВНО сосед:\n  ожидалось %v\n  получено  %v\n%s",
					want, got, inj.Report())
			}
			if inj.Matched != len(c.decls) || len(inj.Expired) != 0 {
				t.Errorf("запись обязана простить ровно свой разрыв: записей %d, прощено %d, "+
					"без предмета %d\n%s", len(c.decls), inj.Matched, len(inj.Expired), inj.Report())
			}
			rep := inj.Report()
			for _, s := range declCoordinates(c.sibling) {
				if !strings.Contains(rep, s) {
					t.Errorf("сосед не назван координатой %q:\n%s", s, rep)
				}
			}
		})
	}
	t.Logf("перепись: пар %d, находок настоящего вывода buf прочитано %d", len(siblingCases), findingsRead)
	if findingsRead == 0 {
		t.Fatal("не прочитано ни одной находки — проба беспредметна")
	}
}

// TestFormerSymbolFormForgivesNothing — ПРЕЖНЯЯ форма символа (перечисление без
// номера значения, поле без сообщения, сообщение без поля) не называет, КАКОЙ
// разрыв прощён, и потому не прощает ни одного: ни единственного, ни пары. Именно
// ею запись kaname#362 прощала снятие любого значения словаря.
func TestFormerSymbolFormForgivesNothing(t *testing.T) {
	var checked int
	for _, c := range siblingCases {
		if c.former == nil {
			continue
		}
		checked++
		t.Run(c.name, func(t *testing.T) {
			for _, fx := range []string{c.one, c.two} {
				got := siblingFindings(t, fx)
				res := declaredbreak.Adjudicate(got, c.former)
				if res.Matched > len(c.former) {
					t.Errorf("%s: записей прежней формы %d простили %d разрывов — запись прощает "+
						"больше одного\n%s", fx, len(c.former), res.Matched, res.Report())
				}
				if res.Clean() {
					t.Errorf("%s: запись прежней формы %v зелена — символ не называет, какой именно "+
						"разрыв прощён\n%s", fx, declCoordinates(c.former), res.Report())
				}
			}
		})
	}
	t.Logf("перепись: пар с прежней формой символа %d из %d", checked, len(siblingCases))
	if checked == 0 {
		t.Fatal("ни у одной пары нет прежней формы — проба беспредметна")
	}
}

// TestEachDeclarationForgivesExactlyOneBreak — ЗАКОННЫЙ БЛИЗНЕЦ расходования.
// Где buf объемлющего символа не печатает, два разрыва неразличимы, и каждый
// объявляется СВОЕЙ записью: две одинаковые записи прощают ровно два разрыва, а
// одна — ровно один.
func TestEachDeclarationForgivesExactlyOneBreak(t *testing.T) {
	two := siblingFindings(t, "accessor-dropped-in-two-messages")
	d := declared("MESSAGE_NO_REMOVE_STANDARD_DESCRIPTOR_ACCESSOR", roleServiceProto,
		"no_standard_descriptor_accessor")

	both := declaredbreak.Adjudicate(two, []declaredbreak.Declaration{d, d})
	if !both.Clean() || both.Matched != 2 {
		t.Errorf("две записи на два неразличимых разрыва обязаны простить оба:\n%s", both.Report())
	}

	single := declaredbreak.Adjudicate(two, []declaredbreak.Declaration{d})
	if single.Clean() || single.Matched != 1 || len(single.Undeclared) != 1 {
		t.Fatalf("одна запись обязана простить ровно один разрыв из двух:\n%s", single.Report())
	}
	// ТЕКСТ НАХОДКИ — часть свойства: координата второго разрыва совпадает с
	// записью перечня, и без объяснения читатель увидел бы «вне перечня» у
	// объявленного символа.
	if rep := single.Report(); !strings.Contains(rep, "запись прощает ровно один разрыв") {
		t.Errorf("находка не объясняет, почему объявленный символ остался вне перечня:\n%s", rep)
	}
}
