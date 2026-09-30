// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
)

// notify_types_test.go — типы права на уведомления объявлены РОВНО в форме
// замысла NTF-1 (kacho#2915, З17; kaname#484, полоса K1).
//
// Форма узкая намеренно (Р5): служебный принципал `service` — субъект без
// отношений, `notification_feed` несёт одно отношение `reader`, а
// `notification_namespace` — одно отношение `sender`, и оба назначаются ТОЛЬКО
// субъекту `service`. Без каскада (`from`, `or`), без подстановочного `*`, без
// `group#member`: отношение, выполнимое подстановочным знаком или группой,
// сужает не того, кого объявляет, и право отправлять уведомления от имени
// пространства получил бы всякий участник группы.
//
// Проба судит РАЗОБРАННУЮ модель (тот же разбор, что кормит план вердикта), а
// не текст: строка `define reader: [service]` в комментарии не делает тип
// объявленным.

// notifyTypeShape — ожидаемая форма: тип → отношение → единственный субъект.
var notifyTypeShape = map[string]map[string]string{
	"service":                {},
	"notification_feed":      {"reader": "service"},
	"notification_namespace": {"sender": "service"},
}

// notifyTypeShapeFindings возвращает расхождения разобранной модели с формой
// notifyTypeShape и число осмотренных типов модели.
//
// Кроме формы самих трёх типов проверяется их ИЗОЛЯЦИЯ: ни один из трёх типов
// не стоит в прямом списке отношения чужого типа. Это же закрывает каскад
// `x from p` через тип уведомлений: указатель `p` — отношение того же чужого
// типа, и цель каскада резолвится только из его прямого списка
// (authzplan.Model.PointerTargets). Иначе узкая форма здесь сочеталась бы с
// широкой дверью рядом — и право уведомлений достигалось бы каскадом.
func notifyTypeShapeFindings(m *authzplan.Model) (findings []string, typesSeen int) {
	names := make([]string, 0, len(notifyTypeShape))
	for n := range notifyTypeShape {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		want := notifyTypeShape[name]
		typ := m.Type(name)
		if typ == nil {
			findings = append(findings, fmt.Sprintf("тип %s не объявлен", name))
			continue
		}
		got := map[string]bool{}
		for _, r := range typ.Relations {
			got[r.Name] = true
			subject, expected := want[r.Name]
			if !expected {
				findings = append(findings, fmt.Sprintf("%s#%s: отношение вне формы (строка %d)", name, r.Name, r.Line))
				continue
			}
			if len(r.Terms) != 1 || r.Terms[0].Kind != authzplan.TermDirect {
				findings = append(findings, fmt.Sprintf("%s#%s: ожидался один прямой список, найдено %q (строка %d)", name, r.Name, r.Raw, r.Line))
				continue
			}
			d := r.Terms[0].Direct
			if len(d) != 1 || d[0].Type != subject || d[0].Wildcard || d[0].Userset != "" || d[0].Condition != "" {
				findings = append(findings, fmt.Sprintf("%s#%s: ожидался [%s], найдено %q (строка %d)", name, r.Name, subject, r.Raw, r.Line))
			}
		}
		for rel := range want {
			if !got[rel] {
				findings = append(findings, fmt.Sprintf("%s#%s: отношение не объявлено", name, rel))
			}
		}
	}

	for _, typ := range m.Types {
		typesSeen++
		if _, own := notifyTypeShape[typ.Name]; own {
			continue
		}
		for _, r := range typ.Relations {
			for _, term := range r.Terms {
				for _, d := range term.Direct {
					if _, hit := notifyTypeShape[d.Type]; hit {
						findings = append(findings, fmt.Sprintf("%s#%s: субъект %s вне типов уведомлений (строка %d)", typ.Name, r.Name, d.Type, r.Line))
					}
				}
			}
		}
	}
	sort.Strings(findings)
	return findings, typesSeen
}

// TestNotifyTypesAreDeclaredInTheirNarrowForm — вшитая модель несёт три типа
// права на уведомления ровно в форме З17 и нигде больше их не называет.
func TestNotifyTypesAreDeclaredInTheirNarrowForm(t *testing.T) {
	p, err := Shared()
	if err != nil {
		t.Fatalf("разбор вшитой модели: %v", err)
	}
	findings, seen := notifyTypeShapeFindings(p.Model())
	t.Logf("перепись: типов модели осмотрено %d · типов формы %d · находок %d", seen, len(notifyTypeShape), len(findings))
	if seen == 0 {
		t.Fatal("модель разобрана в ноль типов — пробе нечего читать")
	}
	if len(findings) != 0 {
		t.Fatalf("типы права на уведомления расходятся с формой З17:\n  %s", strings.Join(findings, "\n  "))
	}
}

// notifyTypesLawfulBlock — законная форма трёх типов, от которой пробы инъекции
// отличаются РОВНО одним фактом.
const notifyTypesLawfulBlock = `
type service

type notification_feed
  relations
    define reader: [service]

type notification_namespace
  relations
    define sender: [service]
`

// TestNotifyTypeShapeProbeRedsOnEachWideningAndStaysSilentOnTheLawfulForm —
// проба выше способна упасть: каждое расширение формы — находка с координатой,
// законный близнец — молчание.
//
// Синтетика строится на ВШИТОЙ модели минус её собственные три типа плюс блок:
// так близнец и инъекции отличаются от настоящего канона только блоком
// уведомлений, а не всем прочим.
func TestNotifyTypeShapeProbeRedsOnEachWideningAndStaysSilentOnTheLawfulForm(t *testing.T) {
	base := withoutNotifyTypes(t, DSL)

	parse := func(t *testing.T, block string) *authzplan.Model {
		t.Helper()
		p, err := New(beforeConditions(t, base, block))
		if err != nil {
			t.Fatalf("синтетическая модель не разобрана: %v", err)
		}
		return p.Model()
	}

	if got, _ := notifyTypeShapeFindings(parse(t, notifyTypesLawfulBlock)); len(got) != 0 {
		t.Fatalf("законная форма дала находки: %v", got)
	}

	cases := []struct {
		name, from, to, want string
	}{
		{"подстановочный знак", "define reader: [service]", "define reader: [service, service:*]", "notification_feed#reader"},
		{"группа", "define sender: [service]", "define sender: [service, group#member]", "notification_namespace#sender"},
		{"пользователь", "define reader: [service]", "define reader: [user]", "notification_feed#reader"},
		{"каскад", "define sender: [service]", "define sender: [service] or reader", "notification_namespace#sender"},
		{"лишнее отношение", "define reader: [service]", "define reader: [service]\n    define viewer: [service]", "notification_feed#viewer"},
		{"тип снят", "\ntype notification_namespace\n  relations\n    define sender: [service]\n", "\n", "тип notification_namespace не объявлен"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			block := strings.Replace(notifyTypesLawfulBlock, c.from, c.to, 1)
			if block == notifyTypesLawfulBlock {
				t.Fatalf("инъекция не применилась: %q не найдено в блоке", c.from)
			}
			if c.name == "каскад" {
				// Вычисляемое отношение того же объекта должно существовать, иначе
				// отказ придёт от разбора, а не от пробы.
				block = strings.Replace(block, "type notification_namespace\n  relations\n",
					"type notification_namespace\n  relations\n    define reader: [service]\n", 1)
			}
			got, _ := notifyTypeShapeFindings(parse(t, block))
			if len(got) == 0 {
				t.Fatalf("расширение формы (%s) не найдено", c.name)
			}
			if !strings.Contains(strings.Join(got, "\n"), c.want) {
				t.Fatalf("находка не называет координату %q: %v", c.want, got)
			}
		})
	}

	// Каскад чужого типа через тип уведомлений (`x from p`, `p: [notification_feed]`)
	// ловится проверкой прямого типа у отношения-указателя: указатель — отношение
	// ТОГО ЖЕ типа, и цель каскада резолвится только из его прямого списка
	// (authzplan.compile, ветка TermTTU). Близнец отличается одним фактом —
	// указатель ведёт в `project`.
	t.Run("чужой тип каскадирует через ленту", func(t *testing.T) {
		const smuggled = "\ntype smuggled\n  relations\n    define feed: [%s]\n    define viewer: %s from feed\n"
		twin, _ := notifyTypeShapeFindings(parse(t, notifyTypesLawfulBlock+fmt.Sprintf(smuggled, "project", "viewer")))
		if len(twin) != 0 {
			t.Fatalf("законный близнец (указатель в project) дал находки: %v", twin)
		}
		got, _ := notifyTypeShapeFindings(parse(t, notifyTypesLawfulBlock+fmt.Sprintf(smuggled, "notification_feed", "reader")))
		if !strings.Contains(strings.Join(got, "\n"), "smuggled#feed: субъект notification_feed") {
			t.Fatalf("каскад через notification_feed не найден: %v", got)
		}
	})

	t.Run("чужой тип назначает service", func(t *testing.T) {
		m := parse(t, notifyTypesLawfulBlock+"\ntype smuggled\n  relations\n    define viewer: [service]\n")
		got, _ := notifyTypeShapeFindings(m)
		if !strings.Contains(strings.Join(got, "\n"), "smuggled#viewer: субъект service") {
			t.Fatalf("назначение service чужому типу не найдено: %v", got)
		}
	})
}

// beforeConditions вставляет блок типов перед каталогом условий: типы модели
// стоят до условий, и блок, дописанный в хвост, судил бы разбор, а не пробу.
func beforeConditions(t *testing.T, dsl, block string) string {
	t.Helper()
	i := strings.Index(dsl, "\ncondition ")
	if i < 0 {
		return dsl + block
	}
	return dsl[:i] + block + dsl[i:]
}

// withoutNotifyTypes снимает из текста модели блоки трёх типов уведомлений,
// сколько их там есть (ноль — тоже законно: так проба работает и до правки
// модели). Блок — строка `type <имя>` и следующие за ней строки с отступом.
func withoutNotifyTypes(t *testing.T, dsl string) string {
	t.Helper()
	lines := strings.Split(dsl, "\n")
	out := make([]string, 0, len(lines))
	skip := false
	for _, l := range lines {
		if strings.HasPrefix(l, "type ") {
			_, own := notifyTypeShape[strings.TrimSpace(strings.TrimPrefix(l, "type "))]
			skip = own
			if skip {
				continue
			}
		}
		if skip && (strings.HasPrefix(l, " ") || l == "") {
			if l == "" {
				skip = false
			}
			continue
		}
		skip = false
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
