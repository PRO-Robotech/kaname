// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package roleexport

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// check.go — целостность правил роли: покрывает ли каждый названный класс хотя
// бы одно ПРИГОДНОЕ действие названного ресурса (приёмка §4.1, MOD-RL-05).
//
// # Почему отказ, а не молчание
//
// Молча принятое пустое право применилось бы миграцией, легло бы строкой в
// `roles`, получило бы выдачу и ВЫГЛЯДЕЛО БЫ ДЕЙСТВУЮЩИМ. Отличить его от
// работающего можно было бы только вызовом — то есть в чужой отладке. Частичная
// неисполнимость опаснее целой: роль отвечает, поэтому её пустое право
// обнаружат позже всего.
//
// # Единица — ПАРА (ресурс, класс) у роли, и она названа
//
// У каждой проверки приёмки своя единица, и сложение находок разных проверок
// дало бы величину, которую нечем перемерить. Здесь считаются пары; перепись
// печатает и число осмотренных пар, и число находок — «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
//
// # Чего эта проверка НЕ делает — сказано прямо
//
//   - подстановки `resources: ["*"]` она не судит, и ветви под неё здесь НЕТ:
//     до проверки такое правило не доходит вовсе — домен объявляет подстановку в
//     ресурсах системной, а разбор манифеста судит правило в НЕсистемном
//     контексте (`Rule.Validate(false)`), поэтому загрузчик отвергает его
//     раньше. Ветвь без производителя входа была бы мёртвой, и её молчание
//     выглядело бы работой; предпосылка проверяется пробой
//     (`TestResourceWildcardCannotReachTheCheck`). Подстановка в ГЛАГОЛАХ
//     несистемной роли законна, и она разворачивается набором типа — тем же
//     предикатом, что у эмиттера кортежей;
//   - полноту поимённого перечня по классу (MOD-RL-18) и отказ на НАЗВАННОЕ
//     непригодное действие (MOD-RL-19) она не считает — их считают СОСЕДНИЕ
//     стадии, `CheckNamedVerbs` и `ExportRoleRules` (`namedverbs.go`). Единица
//     у каждой своя: здесь — пара (ресурс, класс), там — названное вхождение и
//     покрытое действие. Сложение находок разных проверок дало бы величину,
//     которую нечем перемерить.
//
//     ЗДЕСЬ СТОЯЛО «ПОИМЁННОЙ ФОРМЫ ПРАВА У РОЛИ НЕ СУЩЕСТВУЕТ», и это
//     утверждение ПЕРЕЖИЛО СВОЙ ПРЕДМЕТ. Ключ `verbs` был снят пред-разборной
//     проверкой, и снятие было ПОРЯДКОМ, а не запретом: §10 п. 2 приёмки
//     `classes-form-of-role-right.md`, его снимавшей, говорит дословно, что
//     форма возвращается ВМЕСТЕ с проверкой полноты и что ключ возвращает
//     задача #1844. Она его вернула — вместе с проверкой, — и обе стадии
//     получили вход.
//
//     Довод, ради которого форма снималась, остаётся в силе и держится теперь
//     кодом, а не отсутствием ключа: принять перечень ИМЁН, не умея проверить
//     его полноту по классу, значит свести его к классу МОЛЧА и выдать право
//     ШИРЕ просимого. Полнота считается по ПЕРЕСЕЧЕНИЮ «помечено этим классом
//     разделом `resources`» и «правило с этим классом удовлетворяет гейт» —
//     тому же определению, которым живёт стадия 1.
//
//     ЧТО ОСТАЛОСЬ ВЕРНЫМ из прежней редакции: производителя, пишущего раздел
//     `resources` в `services/*/manifest.yaml`, в дереве нет (`authzmapgen`
//     пишет `tables_gen.go`, то есть в обратную сторону). Связывающим это
//     препятствие не было и тогда: соединение «имя действия манифеста ↔ запись
//     каталога» построено `Attribute` (`attribution.go`, единственное
//     объявление правила в дереве) и провязано в `make -C services/iam
//     module-manifest-check` — по шести манифестам действий раздела 101,
//     записей каталога 228, без записи каталога 0, без счёта 0.
//
//     ЧЕМ ДЕРЖИТСЯ ЗАПРЕТ теперь, когда отсрочки нет: гейтом дерева
//     `internal/repohygiene` `TestNamedVerbFormReturnsOnlyWithItsCompletenessCheck`.
//     Он судит ПАРУ — отвергает ли форму прод-код манифеста И есть ли в дереве
//     пробы шести сценариев — и падает ровно на том сочетании, которое приёмка
//     запрещает: форма принята, полнота не проверяется. Сегодня он молчит по
//     второй законной причине (форма вернулась вместе со своей проверкой), а не
//     по первой.

var (
	// ErrClassCoversNoSuitableAction — право пусто: класс не покрывает ни
	// одного пригодного действия названного ресурса.
	ErrClassCoversNoSuitableAction = errors.New(
		"roleexport: класс не покрывает ни одного пригодного действия ресурса")
	// ErrRuleResourceUnknownToCatalog — правило называет ресурс, которому
	// каталог прав не приписывает ни одного действия. Отдельный отказ, а не
	// «класс пуст»: чинится он другим — именем ресурса, а не именем класса.
	ErrRuleResourceUnknownToCatalog = errors.New(
		"roleexport: каталог прав не знает у модуля такого ресурса")
)

// Finding — находка о правиле роли.
//
// Несёт координаты отдельными полями, а не только текстом: вызывающий вправе
// пересчитать находки по роли, по ресурсу и по классу, не разбирая прозу.
type Finding struct {
	// Kind — вид находки; сравнивается через errors.Is.
	Kind error
	// Role — идентификатор роли манифеста.
	Role string
	// Module — модуль, названный правилом (не обязательно модуль манифеста:
	// модуль вправе выдать своей группе роль чужого домена).
	Module string
	// Resource — ресурс, названный правилом.
	Resource string
	// Class — класс (глагол правила), оказавшийся пустым. Пуст у находок,
	// единица которых — ресурс.
	Class string
	// Detail — отказ целиком: что пусто, почему пусто и чем чинится.
	Detail string
}

func (f Finding) Error() string { return f.Detail }

// Unwrap отдаёт вид находки, чтобы errors.Is отвечал по сентинелу.
func (f Finding) Unwrap() error { return f.Kind }

// Census — объём осмотренного.
//
// Печатается ВСЕГДА: молчание проверки, не прочитавшей ни одной роли,
// неотличимо от молчания проверившей все.
type Census struct {
	// ActionsAttributed — действий, привязанных к ресурсам модулей.
	ActionsAttributed int
	// RolesRead — ролей манифеста осмотрено.
	RolesRead int
	// RulesRead — правил осмотрено.
	RulesRead int
	// PairsJudged — пар (ресурс, класс), по которым вынесен вердикт.
	PairsJudged int
	// FindingsFound — находок.
	FindingsFound int
}

// Summary — перепись строкой.
func (c Census) Summary() string {
	return fmt.Sprintf(
		"действий каталога %d · ролей %d · правил %d · пар (ресурс, класс) %d · находок %d",
		c.ActionsAttributed, c.RolesRead, c.RulesRead, c.PairsJudged, c.FindingsFound)
}

// CheckRoleRules судит правила ролей манифеста против каталога действий.
//
// Находки собираются ВСЕ: названная первая заставила бы автора манифеста чинить
// их по одной, по прогону на каждую, и скрыла бы, сколько их всего.
func CheckRoleRules(facts VerbFacts, m *manifest.Manifest, actions []Action) ([]error, Census) {
	census := Census{ActionsAttributed: len(actions)}
	if m == nil {
		return nil, census
	}

	byResource := map[string][]Action{}
	for _, a := range actions {
		byResource[a.Module+"."+a.Resource] = append(byResource[a.Module+"."+a.Resource], a)
	}

	var faults []error
	for i := range m.Roles {
		role := &m.Roles[i]
		census.RolesRead++
		for _, rule := range role.Rules {
			census.RulesRead++
			for _, resource := range rule.Resources {
				found, judged := judgeResource(facts, m, role.ID, rule, resource, byResource)
				faults = append(faults, found...)
				census.PairsJudged += judged
			}
		}
	}
	census.FindingsFound = len(faults)
	return faults, census
}

// judgeResource — вердикт по одному ресурсу правила; вторым значением — сколько
// пар (ресурс, класс) осмотрено.
func judgeResource(facts VerbFacts, m *manifest.Manifest, roleID string, rule manifest.Rule,
	resource string,
	byResource map[string][]Action) ([]error, int) {

	own := byResource[rule.Module+"."+resource]
	if len(own) == 0 {
		return []error{Finding{
			Kind:     ErrRuleResourceUnknownToCatalog,
			Role:     roleID,
			Module:   rule.Module,
			Resource: resource,
			Detail: fmt.Sprintf(
				"роль %q: правило называет ресурс %q модуля %q, а каталог прав не приписывает "+
					"этому ресурсу ни одного действия. Право по нему пусто при любом классе; "+
					"проверь написание ресурса — оно ДОСЛОВНО то же, каким ресурс назван "+
					"ключом закрытой таблицы типов (числа у написания нет: `securityGroup` "+
					"у vpc, `targetGroups` у балансировщика)",
				roleID, resource, rule.Module),
		}}, 0
	}

	fgaType, _ := authzmap.ObjectType(rule.Module, resource)
	var faults []error
	judged := 0
	for _, verb := range rule.Classes {
		class := classOf(m, verb)
		judged++
		if len(Covers(facts, own, fgaType, class)) > 0 {
			continue
		}
		faults = append(faults, Finding{
			Kind:     ErrClassCoversNoSuitableAction,
			Role:     roleID,
			Module:   rule.Module,
			Resource: resource,
			Class:    class,
			Detail:   emptyClassDetail(facts, roleID, rule.Module, resource, verb, class, fgaType, own),
		})
	}
	return faults, judged
}

// classOf — класс, которым правило распоряжается на самом деле.
//
// Снятый глагол остаётся ДЕЙСТВИЕМ: манифест объявляет, во что он разрешается
// на чтении, и правило, назвавшее его, распоряжается тем же классом. Иначе ярус
// чтения, воспроизводимый дословно (`read` · `list` · `get`), получил бы отказ
// на первом же своём глаголе.
func classOf(m *manifest.Manifest, verb string) string {
	if dep, ok := m.DeprecatedVerbs[verb]; ok && dep.Class != "" {
		return dep.Class
	}
	return verb
}

// emptyClassDetail — отказ целиком.
//
// Три вещи обязательны, и каждая закрывает свой промах: ЧТО пусто · ПОЧЕМУ
// пусто (пара «отношение + объект», которую спрашивает гейт) · ЧЕМ чинится
// (пригодные классы этого ресурса и годный способ выдать то, что классом не
// выдаётся). Без причины автор прочтёт отказ как «в манифесте опечатка» и пойдёт
// искать её у себя.
func emptyClassDetail(facts VerbFacts, roleID, module, resource, verb, class, fgaType string,
	own []Action) string {
	var b strings.Builder
	fmt.Fprintf(&b, "роль %q: класс %q на ресурсе %q модуля %q не покрывает ни одного "+
		"пригодного действия", roleID, class, resource, module)
	if class != verb {
		fmt.Fprintf(&b, " (глагол %q объявлен снятым и разрешается в класс %q)", verb, class)
	}
	b.WriteString(". ")

	if fgaType == "" {
		fmt.Fprintf(&b, "У пары (%q, %q) нет типа объекта в закрытой таблице модели прав — "+
			"пообъектного указателя на такой ресурс не пишет никто, поэтому правило роли "+
			"не производит на нём ни одного кортежа ни при каком классе. ",
			module, resource)
	}

	exempt, pairs := gateSummary(own)
	switch {
	case len(pairs) == 0 && exempt > 0:
		fmt.Fprintf(&b, "Все %d действий ресурса освобождены от гейта: их получает всякий "+
			"аутентифицированный, а не участник роли, — правом они не выдаются вовсе. ", exempt)
	case len(pairs) == 0:
		b.WriteString("Действий с гейтом у ресурса не найдено ни одного. ")
	default:
		b.WriteString("Гейты его действий спрашивают: ")
		b.WriteString(strings.Join(pairs, ", "))
		b.WriteString(". ")
	}

	if suitable := suitableClasses(facts, own, fgaType); len(suitable) > 0 {
		fmt.Fprintf(&b, "Пригодные классы этого ресурса: %s. ", strings.Join(suitable, ", "))
	} else {
		b.WriteString("Пригодных классов у этого ресурса НЕТ НИ ОДНОГО — ролью модуля он " +
			"не выдаётся целиком, а не частично. ")
	}
	b.WriteString(wayOut(own, fgaType))
	return b.String()
}

// gateSummary — сколько действий ресурса освобождено и какие пары «отношение +
// объект» спрашивают остальные.
//
// Пары ОТСОРТИРОВАНЫ: отказ, зависящий от обхода карты, читался бы по-разному от
// прогона к прогону.
func gateSummary(own []Action) (exempt int, pairs []string) {
	seen := map[string]bool{}
	for _, a := range own {
		if a.Exempt() {
			exempt++
			continue
		}
		seen[a.Relation+"@"+a.Object] = true
	}
	for p := range seen {
		pairs = append(pairs, p)
	}
	sort.Strings(pairs)
	return exempt, pairs
}

// suitableClasses — классы, покрывающие хотя бы одно пригодное действие ресурса.
//
// Словарь-кандидат — набор глаголов ТИПА плюс закрытый набор классов действия:
// первый несёт глаголы, объявленные именно этим типом (`addTargets` и подобные),
// второй — `create`, у которого пообъектного отношения нет вовсе и который
// покрывает действие ярусом. Ни один из двух здесь не переобъявляется.
func suitableClasses(facts VerbFacts, own []Action, fgaType string) []string {
	seen := map[string]bool{}
	var candidates []string
	for _, c := range append(facts.VerbsOfType(fgaType), manifest.CanonicalVerbs()...) {
		if !seen[c] {
			seen[c] = true
			candidates = append(candidates, c)
		}
	}
	var out []string
	for _, c := range candidates {
		if len(Covers(facts, own, fgaType, c)) > 0 {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// wayOut — годный способ выдать то, что правилом роли модуля не выдаётся.
//
// Способ РАЗНЫЙ у яруса области и у прямого userset'а кластера, и отказ обязан
// их различать: половина отказов иначе отправляет автора не туда.
func wayOut(own []Action, fgaType string) string {
	scope, cluster := false, false
	for _, a := range own {
		if a.Exempt() || a.Object == fgaType {
			continue
		}
		if authzmap.IsHierarchyScopeType(a.Object) {
			scope = true
			continue
		}
		cluster = true
	}
	var parts []string
	if scope {
		parts = append(parts, "право, чей гейт спрашивает ярус на области (`editor`/`viewer` "+
			"на проекте либо аккаунте), правилом роли МОДУЛЯ не выдаётся ни при каком "+
			"написании: этот кортеж пишет только ярусная роль платформы (`admin`/`edit`/`view`) "+
			"на самой области, и получателем там может быть группа")
	}
	if cluster {
		parts = append(parts, "право, чей гейт спрашивает отношение на кластере, выдаётся "+
			"привязкой ОТНОШЕНИЯ, а не ролью; формы выдачи отношением в манифесте сегодня НЕТ "+
			"(`seed.accessBindings[]` несёт только `roleId`) — это задача-преемник, и вместе с "+
			"формой она обязана назвать допустимый тип получателя: модель ограничивает субъект "+
			"отношением, и группу принимает не всякое")
	}
	if len(parts) == 0 {
		return "Годный способ: назови класс, покрывающий действие этого ресурса."
	}
	return "Годный способ: " + strings.Join(parts, "; ") + "."
}
