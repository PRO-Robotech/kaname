// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package roleexport

// namedverbs.go — ПОИМЁННАЯ форма права роли, содержательная половина
// (kacho#1844, приёмка `module-manifest-roles-and-seed-grants.md` §3.6 п. 3–5,
// сценарии MOD-RL-18/18a и MOD-RL-19/19a).
//
// # Две проверки, две единицы, две стадии — и это не педантизм
//
//	MOD-RL-19  ЦЕЛОСТНОСТЬ. Единица — НАЗВАННОЕ ВХОЖДЕНИЕ: имя, чей гейт
//	           спрашивает пару «отношение + объект» вне множества, производимого
//	           правилом роли. Второй единицы у него быть не может: покрыть такое
//	           действие классом невозможно by construction (непригодное в класс
//	           не входит), а подстановка разворачивается в ресурсы, не в имена.
//	MOD-RL-18  ЭКСПОРТ. Единица — ПОКРЫТОЕ ДЕЙСТВИЕ: перечень обязан быть полон
//	           по ПРИГОДНОМУ содержимому своего класса.
//
// Сложение находок двух проверок дало бы величину, которую нечем перемерить,
// поэтому перепись у каждой своя и печатает объём осмотренного.
//
// # Полнота считается по ПЕРЕСЕЧЕНИЮ, а не по покрытию класса
//
// Действие принадлежит классу `C` на ресурсе `R`, если оно (а) ПОМЕЧЕНО классом
// `C` разделом `resources` И (б) правило с классом `C` УДОВЛЕТВОРЯЕТ его гейт.
// Это то же определение, которым живёт стадия 1 (`classfit.go`), и второго
// здесь не заводится.
//
// Различие с `Covers` существенно и стоило бы ошибки, будь оно упущено. `Covers`
// отвечает на ДРУГОЙ вопрос — «что правило с глаголом `C` действительно
// выдаёт», — и на `vpc.subnet` класс `update` выдаёт ещё и `delete` (§2.8,
// `update ⇒ delete`), при том что `delete` помечен классом `delete`, а не
// `update`. Считай полноту по `Covers`, отказ требовал бы дописать `delete` в
// перечень, названный для класса `update`, — то есть требовал бы от автора
// назвать действие, к его классу не относящееся.
//
// # Сведение к классу — МИНИМАЛЬНОЕ, и минимальность здесь несущая
//
// Перечень, полный по своим классам, сводится к НАБОРУ ЭТИХ КЛАССОВ, из которого
// выброшен всякий класс, чьё содержимое уже покрыто остальными. Без выбрасывания
// полный перечень `[update, addCidrBlocks, removeCidrBlocks]` дал бы `[update]`,
// а `[…, delete]` — `[delete, update]`, то есть ДРУГОЕ право при том же
// покрытии, и §3.6 п. 5 («обе формы дают ровно один и тот же `Rule`») перестал
// бы выполняться.
//
// # Ни одного правила не производится — это ИСХОД, а не намерение
//
// Роль с неполным перечнем не экспортируется ЦЕЛИКОМ, а не частично: частичный
// экспорт дал бы роль ýже объявленной, и отличить её от работающей можно было бы
// только вызовом — то есть в чужой отладке.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

var (
	// ErrNamedVerbNotProducibleByRoleRule — поимённое право назвало действие,
	// чей гейт спрашивает пару, непроизводимую правилом роли модуля ни при
	// каком классе.
	//
	// Отдельный отказ, а не «класс пуст»: единица другая (названное вхождение
	// против пары «ресурс, класс»), и починка другая — право выдаётся не ролью
	// модуля вовсе.
	ErrNamedVerbNotProducibleByRoleRule = errors.New(
		"roleexport: названное действие непроизводимо правилом роли модуля")
	// ErrNamedVerbsIncompleteForClass — поимённый перечень не полон по классу.
	//
	// Принять его молча значило бы свести к классу и выдать право ШИРЕ
	// просимого; отвергнуть без имён — оставить автора без починки.
	ErrNamedVerbsIncompleteForClass = errors.New(
		"roleexport: поимённый перечень не полон по своему классу")
)

// NamedCensus — объём, осмотренный проверкой названного (MOD-RL-19).
type NamedCensus struct {
	// Roles — ролей прочитано.
	Roles int
	// Rules — правил прочитано, обеих форм. Ноль означает «читать было нечего»,
	// и без этого числа молчание проверки неотличимо от её отсутствия.
	Rules int
	// Named — правил ПОИМЁННОЙ формы: предмет проверки.
	Named int
	// Verbs — названных вхождений осмотрено: самая мелкая единица.
	Verbs int
	// Findings — находок.
	Findings int
}

// Summary — перепись словами: число в отчёте читателю ничего не говорит.
func (c NamedCensus) Summary() string {
	return fmt.Sprintf("названное: ролей %d · правил %d · из них поимённых %d · "+
		"названных вхождений %d · находок %d", c.Roles, c.Rules, c.Named, c.Verbs, c.Findings)
}

// ExportCensus — объём, осмотренный экспортом (MOD-RL-18).
type ExportCensus struct {
	// Roles — ролей прочитано.
	Roles int
	// Exported — ролей произведено.
	Exported int
	// Refused — ролей отвергнуто целиком.
	Refused int
	// Named — правил поимённой формы осмотрено.
	Named int
	// Reduced — поимённых прав, сведённых к своему классу.
	Reduced int
	// Findings — находок.
	Findings int
}

// Summary — перепись словами.
func (c ExportCensus) Summary() string {
	return fmt.Sprintf("экспорт: ролей %d · произведено %d · отвергнуто %d · "+
		"поимённых прав %d · сведено %d · находок %d",
		c.Roles, c.Exported, c.Refused, c.Named, c.Reduced, c.Findings)
}

// CheckNamedVerbs — MOD-RL-19: названное действие, чей гейт непроизводим
// правилом роли модуля, отвергается.
//
// Находки собираются ВСЕ: названная первая заставила бы автора чинить их по
// одной, по прогону на каждую, и скрыла бы, сколько их всего.
func CheckNamedVerbs(facts VerbFacts, m *manifest.Manifest, actions []Action) ([]error, NamedCensus) {
	var census NamedCensus
	if m == nil {
		return nil, census
	}
	byResource := actionsByResource(actions)

	var faults []error
	for i := range m.Roles {
		role := &m.Roles[i]
		census.Roles++
		for _, rule := range role.Rules {
			census.Rules++
			named, isNamed := rule.Right()
			if !isNamed {
				continue
			}
			census.Named++
			for _, resource := range rule.Resources {
				own := byResource[rule.Module+"."+resource]
				fgaType, _ := authzmap.ObjectType(rule.Module, resource)
				for _, verb := range named {
					census.Verbs++
					a, ok := actionOf(own, verb)
					switch {
					case !ok:
						// Каталог такого действия не знает. Это НЕ находка этой
						// проверки: её единица — производимость гейта, а гейта
						// здесь нет вовсе. Существование названного судит
						// загрузчик своей причиной, а несопоставленное действие
						// — сверка соединения; третий отказ об одном предмете
						// назвал бы автору три причины, из которых действует
						// одна.
						continue
					case a.Exempt():
						// Гейта нет: действие получает всякий аутентифицированный,
						// а не участник роли. Правом оно не выдаётся вовсе —
						// значит и непроизводимым быть не может.
						continue
					case Produces(facts, declaredClassOfVerb(m, resource, verb), fgaType, a.Relation, a.Object):
						continue
					}
					census.Findings++
					faults = append(faults, Finding{
						Kind:     ErrNamedVerbNotProducibleByRoleRule,
						Role:     role.ID,
						Module:   rule.Module,
						Resource: resource,
						Class:    declaredClassOfVerb(m, resource, verb),
						Detail: unsuitableNamedDetail(facts, role.ID, rule.Module, resource,
							verb, fgaType, a, own),
					})
				}
			}
		}
	}
	return faults, census
}

// unsuitableNamedDetail — отказ MOD-RL-19 целиком.
//
// Три вещи обязательны: ЧТО названо · ПАРА, которую спрашивает гейт · почему
// правило роли этого кортежа не пишет и чем это выдаётся вместо роли модуля.
// Отдельной строкой — что приведением к `classes:` это НЕ чинится: полнота
// перечня и производимость отношения суть разные свойства, и без этой строки
// автор пойдёт переписывать форму, а отказ придёт снова.
func unsuitableNamedDetail(facts VerbFacts, roleID, module, resource, verb, fgaType string,
	a Action, own []Action) string {
	var b strings.Builder
	fmt.Fprintf(&b, "роль %q: право называет ПОИМЁННО действие %q ресурса %q модуля %q, "+
		"а его гейт спрашивает пару %s@%s — отношение на объекте, которого правило роли "+
		"модуля не пишет ни при каком классе. ",
		roleID, verb, resource, module, a.Relation, a.Object)
	if a.Object != fgaType {
		fmt.Fprintf(&b, "Кортежи правила ложатся на объект типа ресурса (%s), а гейт "+
			"спрашивает их на %s: правило-содержимое на объект ОБЛАСТИ не пишет ничего. ",
			fgaType, a.Object)
	} else {
		fmt.Fprintf(&b, "На объекте %s правило пишет глагольные отношения объявленных "+
			"типом действий и ярус, и %s среди них нет. ", fgaType, a.Relation)
	}
	b.WriteString("Приведением к `classes:` это НЕ чинится: полнота перечня и " +
		"производимость отношения — разные свойства, и класс, содержащий непригодное " +
		"действие, его не производит тоже. ")
	if suitable := suitableClasses(facts, own, fgaType); len(suitable) > 0 {
		fmt.Fprintf(&b, "Пригодные классы этого ресурса: %s. ", strings.Join(suitable, ", "))
	}
	b.WriteString(wayOut(own, fgaType))
	return b.String()
}

// ExportRoleRules — MOD-RL-18: политика ролей манифеста, произведённая ПОСЛЕ
// проверки полноты поимённых перечней.
//
// Возвращает произведённые правила по идентификатору роли, находки и перепись.
// Роль, чей перечень не полон, в результат НЕ ПОПАДАЕТ ЦЕЛИКОМ.
func ExportRoleRules(facts VerbFacts, m *manifest.Manifest, actions []Action) (
	map[string][]domain.Rule, []error, ExportCensus) {

	var census ExportCensus
	out := map[string][]domain.Rule{}
	if m == nil {
		return out, nil, census
	}
	byResource := actionsByResource(actions)

	var faults []error
	for i := range m.Roles {
		role := &m.Roles[i]
		census.Roles++
		rules := make([]domain.Rule, 0, len(role.Rules))
		roleFaults := 0
		for _, rule := range role.Rules {
			named, isNamed := rule.Right()
			if !isNamed {
				rules = append(rules, rule.DomainRule())
				continue
			}
			census.Named++
			classes, missing := reduceNamed(facts, m, rule, named, byResource)
			if len(missing) > 0 {
				roleFaults++
				census.Findings++
				faults = append(faults, Finding{
					Kind:     ErrNamedVerbsIncompleteForClass,
					Role:     role.ID,
					Module:   rule.Module,
					Resource: strings.Join(rule.Resources, ", "),
					Class:    strings.Join(classes, ", "),
					Detail: incompleteDetail(role.ID, rule.Module, rule.Resources,
						named, classes, missing),
				})
				continue
			}
			census.Reduced++
			reduced := rule.DomainRule()
			reduced.Verbs = classes
			rules = append(rules, reduced)
		}
		if roleFaults > 0 {
			// ЦЕЛИКОМ, а не частично: частичный экспорт дал бы роль ýже
			// объявленной, и отличить её от работающей можно только вызовом.
			census.Refused++
			continue
		}
		census.Exported++
		out[role.ID] = rules
	}
	return out, faults, census
}

// reduceNamed — классы, к которым сводится поимённый перечень, и НЕДОСТАЮЩИЕ
// имена, если он не полон.
//
// Классы возвращаются отсортированными: право, зависящее от обхода карты,
// читалось бы по-разному от прогона к прогону, а строка роли обязана быть
// воспроизводимой.
func reduceNamed(facts VerbFacts, m *manifest.Manifest, rule manifest.Rule, named []string,
	byResource map[string][]Action) (classes, missing []string) {

	classSet := map[string]bool{}
	haveSet := map[string]bool{}
	for _, v := range named {
		haveSet[v] = true
	}
	missSet := map[string]bool{}

	for _, resource := range rule.Resources {
		own := byResource[rule.Module+"."+resource]
		fgaType, _ := authzmap.ObjectType(rule.Module, resource)
		// Классы, затронутые перечнем на ЭТОМ ресурсе.
		touched := map[string]bool{}
		for _, v := range named {
			if _, ok := actionOf(own, v); !ok {
				continue
			}
			touched[declaredClassOfVerb(m, resource, v)] = true
		}
		for class := range touched {
			members := classMembers(facts, m, resource, own, fgaType, class)
			if len(members) == 0 {
				continue
			}
			classSet[class] = true
			for _, mem := range members {
				if !haveSet[mem] {
					missSet[mem] = true
				}
			}
		}
	}
	for c := range classSet {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for v := range missSet {
		missing = append(missing, v)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return classes, missing
	}
	return minimalClasses(facts, m, rule, classes, byResource), nil
}

// classMembers — ПРИГОДНОЕ содержимое класса на ресурсе: действия, помеченные
// этим классом разделом `resources` И удовлетворяющие свой гейт правилом роли.
//
// Пересечение, а не любая его половина: без первого класс перестал бы быть тем,
// что автор объявил; без второго перечень требовал бы назвать действие, которого
// право не даёт (§3.6 п. 3).
func classMembers(facts VerbFacts, m *manifest.Manifest, resource string, own []Action,
	fgaType, class string) []string {

	var out []string
	for _, a := range own {
		if a.Exempt() {
			continue
		}
		if declaredClassOfVerb(m, resource, a.Verb) != class {
			continue
		}
		if !Produces(facts, class, fgaType, a.Relation, a.Object) {
			continue
		}
		out = append(out, a.Verb)
	}
	sort.Strings(out)
	return out
}

// minimalClasses — набор классов, из которого выброшен всякий класс, чьё
// пригодное содержимое уже покрыто остальными.
//
// Без него полное поимённое право и его класс давали бы РАЗНОЕ право при
// одинаковом покрытии, и §3.6 п. 5 не выполнялся бы. Обход идёт по классам с
// бо́льшим покрытием первыми: иначе результат зависел бы от порядка имён.
func minimalClasses(facts VerbFacts, m *manifest.Manifest, rule manifest.Rule,
	classes []string, byResource map[string][]Action) []string {

	// Покрытие класса — по ВСЕМ ресурсам правила: класс, лишний на одном
	// ресурсе, может быть единственным носителем действия на другом.
	coverage := map[string]map[string]bool{}
	for _, class := range classes {
		set := map[string]bool{}
		for _, resource := range rule.Resources {
			own := byResource[rule.Module+"."+resource]
			fgaType, _ := authzmap.ObjectType(rule.Module, resource)
			for _, a := range Covers(facts, own, fgaType, class) {
				set[resource+"."+a.Verb] = true
			}
		}
		coverage[class] = set
	}
	order := append([]string(nil), classes...)
	sort.SliceStable(order, func(i, j int) bool {
		li, lj := len(coverage[order[i]]), len(coverage[order[j]])
		if li != lj {
			return li > lj
		}
		return order[i] < order[j]
	})

	covered := map[string]bool{}
	var kept []string
	for _, class := range order {
		adds := false
		for k := range coverage[class] {
			if !covered[k] {
				adds = true
				break
			}
		}
		if !adds {
			continue
		}
		kept = append(kept, class)
		for k := range coverage[class] {
			covered[k] = true
		}
	}
	sort.Strings(kept)
	return kept
}

// incompleteDetail — отказ MOD-RL-18 целиком: что неполно · чего недостаёт
// ПОИМЁННО · обе годные починки.
func incompleteDetail(roleID, module string, resources, named, classes, missing []string) string {
	return fmt.Sprintf("роль %q: поимённый перечень на ресурсе %s.%s не полон по классу %s. "+
		"Названо: %s. НЕДОСТАЁТ: %s — эти действия принадлежат тому же классу и пригодны "+
		"(гейт каждого правило роли производит), поэтому принять перечень как есть значило "+
		"бы свести его к классу МОЛЧА и выдать право ШИРЕ просимого. Починки годны обе: "+
		"дописать недостающие имена ЛИБО написать `classes: [%s]` — они дают ровно одно и "+
		"то же право. Ни одного правила этой роли не произведено: частичный экспорт дал бы "+
		"роль ýже объявленной, и отличить её от работающей можно было бы только вызовом",
		roleID, module, strings.Join(resources, "|"), strings.Join(classes, ", "),
		strings.Join(named, ", "), strings.Join(missing, ", "), strings.Join(classes, ", "))
}

// declaredClassOfVerb — класс, объявленный записью действия названного ресурса.
//
// Снятое действие остаётся действием: манифест объявляет, во что оно
// разрешается, и `classOf` читает тот же раздел. Правило одно и здесь не
// переобъявляется.
func declaredClassOfVerb(m *manifest.Manifest, resource, verb string) string {
	for i := range m.Resources {
		r := &m.Resources[i]
		if r.Name != resource {
			continue
		}
		for _, v := range r.Verbs {
			if v.Name == verb {
				return declaredClass(v)
			}
		}
	}
	return classOf(m, verb)
}

// actionsByResource — действия каталога, разложенные по ключу `<модуль>.<ресурс>`.
func actionsByResource(actions []Action) map[string][]Action {
	out := map[string][]Action{}
	for _, a := range actions {
		out[a.Module+"."+a.Resource] = append(out[a.Module+"."+a.Resource], a)
	}
	return out
}

// actionOf — действие ресурса по имени.
func actionOf(own []Action, verb string) (Action, bool) {
	for _, a := range own {
		if a.Verb == verb {
			return a, true
		}
	}
	return Action{}, false
}
