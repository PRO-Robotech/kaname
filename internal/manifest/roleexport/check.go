// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package roleexport

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// check.go — целостность правил роли: покрывает ли каждый названный класс хотя
// бы одно ПРИГОДНОЕ действие названного ресурса (приёмка §4.1, MOD-RL-05).
//
// Ветвей у вердикта ДВЕ. Ресурс с действиями в каталоге прав судится ими —
// это общий случай. Ресурс, объявленный без собственной службы
// (`authzmap.CatalogResourcesWithoutOwnService`), действий в каталоге не имеет
// by construction, и правило в форме `classes` над ним судится глаголами
// модели его типа (`judgeByModelVerbs`, kaname#872). Поимённая форма над таким
// ресурсом получает прежний отказ: сводить имена к классу не по чему.
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
//     задача kacho#1844. Она его вернула — вместе с проверкой, — и обе стадии
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
//     объявление правила в дереве) и провязано в `make //     module-manifest-check` — по шести манифестам действий раздела 101,
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
	// ErrClassIsNotAModelVerbOfType — право пусто: ресурс объявлен без
	// собственной службы, и класс правила не даёт ни одного глагола модели его
	// типа. Отдельный отказ, а не «класс не покрывает действия»: действий у
	// такого ресурса в каталоге нет by construction, и судит его модель.
	ErrClassIsNotAModelVerbOfType = errors.New(
		"roleexport: класс не даёт ни одного глагола модели типа ресурса без собственной службы")
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
	// PairsJudgedByModelVerbs — из них пар над ресурсом без собственной службы,
	// судимых глаголами модели его типа, а не действиями каталога. Отдельным
	// числом: иначе «находок 0» по такой паре неотличимо от «судилась каталогом».
	PairsJudgedByModelVerbs int
	// FindingsFound — находок.
	FindingsFound int
}

// Summary — перепись строкой.
func (c Census) Summary() string {
	return fmt.Sprintf(
		"действий каталога %d · ролей %d · правил %d · пар (ресурс, класс) %d · "+
			"из них по глаголам модели %d · находок %d",
		c.ActionsAttributed, c.RolesRead, c.RulesRead, c.PairsJudged,
		c.PairsJudgedByModelVerbs, c.FindingsFound)
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
			// Вложенные правила (kaname#874) судятся наравне с правилом верхнего
			// уровня — с модулем владельца: право, которое они дают, то же право.
			// Над ресурсом без своей службы вложенное правило в форме `classes`
			// судится глаголами модели его типа (kaname#872) так же, как верхнее.
			for _, r := range withChildren(rule) {
				census.RulesRead++
				for _, resource := range r.Resources {
					found, judged, byModel := judgeResource(facts, m, role.ID, r, resource, byResource)
					faults = append(faults, found...)
					census.PairsJudged += judged
					if byModel {
						census.PairsJudgedByModelVerbs += judged
					}
				}
			}
		}
	}
	census.FindingsFound = len(faults)
	return faults, census
}

// judgeResource — вердикт по одному ресурсу правила.
//
// `judged` — сколько пар (ресурс, класс) осмотрено; `byModel` — судились ли они
// глаголами модели типа, а не действиями каталога.
func judgeResource(facts VerbFacts, m *manifest.Manifest, roleID string, rule manifest.Rule,
	resource string,
	byResource map[string][]Action) (faults []error, judged int, byModel bool) {

	own := byResource[rule.Module+"."+resource]
	if len(own) == 0 {
		_, without := authzmap.CatalogResourcesWithoutOwnService()[rule.Module+"."+resource]
		_, named := rule.Right()
		if without && !named {
			faults, judged = judgeByModelVerbs(facts, m, roleID, rule, resource)
			return faults, judged, true
		}
		// Поимённая форма над ресурсом без своей службы — тот же отказ, что у
		// ресурса, которого каталог не знает: имена действий сводятся к классу
		// по действиям каталога (MOD-RL-18), а их у такого ресурса нет. Молчать
		// с нулём пар значило бы принять перечень, полноту которого никто не
		// считал.
		detail := fmt.Sprintf(
			"роль %q: правило называет ресурс %q модуля %q, а каталог прав не приписывает "+
				"этому ресурсу ни одного действия. Право по нему пусто при любом классе; "+
				"проверь написание ресурса — оно ДОСЛОВНО то же, каким ресурс назван "+
				"ключом закрытой таблицы типов (числа у написания нет: `securityGroup` "+
				"у vpc, `targetGroups` у балансировщика)",
			roleID, resource, rule.Module)
		if without {
			detail += ". Ресурс объявлен без собственной службы: правило в форме `classes` " +
				"над ним судится глаголами модели его типа, а поимённую форму `verbs` " +
				"свести к классу не по чему — назови право классами"
		}
		return []error{Finding{
			Kind:     ErrRuleResourceUnknownToCatalog,
			Role:     roleID,
			Module:   rule.Module,
			Resource: resource,
			Detail:   detail,
		}}, 0, false
	}

	fgaType, _ := authzmap.ObjectType(rule.Module, resource)
	policy := rolePolicy(m.Module)
	for _, verb := range rule.Classes {
		class := classOf(m, verb)
		judged++
		if len(Covers(facts, policy, own, fgaType, class)) > 0 {
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
	return faults, judged, false
}

// judgeByModelVerbs — вердикт по ресурсу, объявленному без собственной службы
// (`authzmap.CatalogResourcesWithoutOwnService`).
//
// # Почему судит модель, а не каталог
//
// Действий у такого ресурса в каталоге нет by construction: службы нет, и
// привязке записей не из чего вывести его написание. Гейт его объекта задаёт
// обработчик чужой службы, спрашивая пообъектное отношение `v_<глагол>` на типе
// ресурса, — то есть ровно те кортежи, которые пишет правило роли. Поэтому
// единственный вопрос, на который здесь есть ответ: даёт ли класс правила хотя
// бы один глагол модели этого типа. Пустое множество действий каталога для
// такого ресурса не означает «право пусто»; пустое множество ГЛАГОЛОВ — означает.
//
// # Чем это не ослабление
//
// Ответ даёт тот же предикат, которым эмиттер кортежей строит набор глаголов
// (`GrantedVerbs` с набором типа), поэтому «покрыт» здесь значит «правило
// действительно пишет на объекте этого типа хотя бы одно глагольное отношение».
// Запасного словаря у этой ветви нет: тип без собственного набора глаголов не
// покрывается ни одним классом — fail-closed. Тип есть у каждой записи перечня:
// это предусловие держит проба `TestResourcesWithoutOwnServiceAreClosedTableKeys`,
// поэтому ветви «пара вне закрытой таблицы» здесь нет.
// Ярус в покрытие не входит: без действий каталога неизвестно, спрашивает ли
// его хоть один гейт, и вывод «покрыто ярусом» был бы предположением.
//
// Решение о доступе это не меняет: правится только проверка формы при сборке.
func judgeByModelVerbs(facts VerbFacts, m *manifest.Manifest, roleID string, rule manifest.Rule,
	resource string) ([]error, int) {

	fgaType, _ := authzmap.ObjectType(rule.Module, resource)
	typeVerbs := facts.VerbsOfType(fgaType)
	policy := rolePolicy(m.Module)
	var faults []error
	judged := 0
	for _, verb := range rule.Classes {
		class := classOf(m, verb)
		judged++
		// Отдельной охраны «набор типа пуст» здесь нет намеренно: `GrantedVerbs`
		// сверяет каждый глагол с набором типа, и на пустом наборе отдаёт пусто
		// на любом пути. Охрана
		// была бы эквивалентным мутантом, а исход «тип без глаголов — находка»
		// держит проба (TestRuleOnResourceWithoutOwnServiceRefusesATypeWithoutModelVerbs).
		if len(facts.GrantedVerbs(fgaType, []string{class}, typeVerbs, policy)) > 0 {
			continue
		}
		faults = append(faults, Finding{
			Kind:     ErrClassIsNotAModelVerbOfType,
			Role:     roleID,
			Module:   rule.Module,
			Resource: resource,
			Class:    class,
			Detail:   modelVerbsDetail(roleID, rule.Module, resource, verb, class, fgaType, typeVerbs),
		})
	}
	return faults, judged
}

// modelVerbsDetail — отказ целиком: ЧТО пусто · ПОЧЕМУ судит модель · ЧЕМ
// чинится (глаголы модели типа, которые класс вправе назвать).
func modelVerbsDetail(roleID, module, resource, verb, class, fgaType string, typeVerbs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "роль %q: класс %q на ресурсе %q модуля %q не даёт ни одного глагола "+
		"модели его типа", roleID, class, resource, module)
	if class != verb {
		fmt.Fprintf(&b, " (глагол %q объявлен снятым и разрешается в класс %q)", verb, class)
	}
	b.WriteString(". Ресурс объявлен без собственной службы, действий в каталоге прав у " +
		"него нет by construction, поэтому право по нему судится глаголами модели типа, " +
		"которые правило роли пишет на объекте. ")
	switch {
	case len(typeVerbs) == 0:
		fmt.Fprintf(&b, "Тип %q не объявляет в модели ни одного глагола — ролью модуля "+
			"ресурс не выдаётся ни при каком классе.", fgaType)
	default:
		sorted := append([]string(nil), typeVerbs...)
		sort.Strings(sorted)
		fmt.Fprintf(&b, "Глаголы модели типа %q: %s. Годный способ: назови класс из этого "+
			"перечня.", fgaType, strings.Join(sorted, ", "))
	}
	return b.String()
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
	policy := rolePolicy(module)
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

	if skipped := SkippedByPlane(facts, policy, own, fgaType, class); len(skipped) > 0 {
		fmt.Fprintf(&b, "Действий этого ресурса, которые класс покрыл бы, но которые живут на "+
			"ПЛОСКОСТИ ИСПОЛНЕНИЯ, — %d: %s. Арендатору они недоступны by construction "+
			"(внутренний слушатель), поэтому ролью арендатора не выдаются ни при каком классе; "+
			"это запрет, а не пропуск. ", len(skipped), strings.Join(fqnsOf(skipped), ", "))
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

	if suitable := suitableClasses(facts, policy, own, fgaType); len(suitable) > 0 {
		fmt.Fprintf(&b, "Пригодные классы этого ресурса: %s. ", strings.Join(suitable, ", "))
	} else {
		b.WriteString("Пригодных классов у этого ресурса НЕТ НИ ОДНОГО — ролью модуля он " +
			"не выдаётся целиком, а не частично. ")
	}
	b.WriteString(wayOut(own, fgaType))
	return b.String()
}

// fqnsOf — записи каталога названных действий, В ПОРЯДКЕ ДОКУМЕНТА.
//
// Порядок не от обхода карты: перечень, зависящий от него, читался бы по-разному
// от прогона к прогону, и отказ нельзя было бы сверить с прошлым.
func fqnsOf(actions []Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, a.FQN)
	}
	sort.Strings(out)
	return out
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
func suitableClasses(facts VerbFacts, policy domain.RulePolicy, own []Action, fgaType string) []string {
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
		if len(Covers(facts, policy, own, fgaType, c)) > 0 {
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

// withChildren — правило и его вложенные правила (с модулем владельца) одним
// перечнем.
func withChildren(rule manifest.Rule) []manifest.Rule {
	out := []manifest.Rule{rule}
	for _, c := range rule.Children {
		out = append(out, manifest.Rule{
			Module: rule.Module, Resources: c.Resources, Classes: c.Classes, Verbs: c.Verbs,
			ResourceNames: c.ResourceNames, MatchLabels: c.MatchLabels,
		})
	}
	return out
}
