// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// role_effective_verbs.go — честное превью глаголов роли, которое отдаёт
// служба ролей (redesign-2026 F6): по букве правил и фактически. `authoredVerbs`
// — объединение глаголов правил роли по СЕГМЕНТАМ, которые роль сегодня держит,
// без повторов и в каноническом порядке; `*` разворачивается набором только тех
// ресурсов правила, чей якорь держится; правило без адресуемых ресурсов даёт
// свои глаголы как прежде; глагол ЯРУСНОЙ ПАРЫ судится живой строкой каталога
// этой пары (kaname#76, приёмка `catalog-consequence-reaches-role-readers.md`
// §2.3). `effectiveVerbs` добавляет квалификатор редактора `delete*`: роль,
// дающая `update` без `delete` и без `*`, — редактор, и редактор вправе удалять
// листовые объекты своей области (доматериализуется), но НЕ сам аккаунт или
// проект; заметка говорит это дословно, чтобы превью наименьших прав не
// обещало меньше выданного.
//
// XC-3 S1Ф2 — что здесь изменилось и почему это не косметика. Превью держало
// СОБСТВЕННЫЙ список глаголов, в который разворачивалась подстановка. Список ни с
// чем не сверялся: правка словаря материализации его не задевала, и сверяющего у
// него не было ни одного во всём дереве. Превью — ПУБЛИЧНЫЙ контракт («честный
// показ того, что роль на самом деле даёт»), поэтому отставший список означал роль,
// чьё обещание и чья материализация разошлись. Теперь набор приходит от вызывающего
// ТЕМ ЖЕ путём, что и на эмиссии.

// verbDisplayPrecedence — порядок ПОКАЗА глаголов в превью; глаголы вне этого
// списка сортируются после, стабильно.
//
// Это НЕ словарь глаголов и не утверждение об их составе: список не обязан
// перечислять всё, что бывает, поэтому глагол расширенного типа здесь не
// «отсутствует», а попадает в детерминированный хвост. Прежняя редакция была
// ОДНОВРЕМЕННО и словарём разворота подстановки — из-за чего расходилась с
// материализацией; разворот отсюда убран, осталось только старшинство вывода.
var verbDisplayPrecedence = []string{"get", "list", "create", "update", "delete"}

// EditorDeleteVerb — квалификатор, добавляемый к фактическим глаголам
// роли-редактора: удаление листовых объектов области, но не якоря.
const EditorDeleteVerb = "delete*"

// EditorDeleteNote — дословное пояснение квалификатора редактора. Текст наружу,
// контракт ответа: его не переводят.
const EditorDeleteNote = "co-materialized on in-scope leaf objects, NOT on the account/project anchor itself"

// TypeVerbLookup — набор глаголов, объявленный типом (module, resource);
// ok=false, когда пара не резолвится ни в один известный тип.
//
// Приходит ПАРАМЕТРОМ, а не импортом таблицы: владельцем таблицы остаётся authzmap,
// а домен — без внешних зависимостей (см. rule_verbs.go, «pure domain»).
type TypeVerbLookup func(module, resource string) (verbs []string, ok bool)

// WithCommonFallback оборачивает lookup так, что пара-ПОДСТАНОВКА получает
// словарь, ОБЩИЙ для всех ресурсов.
//
// Это решение ВЫЗЫВАЮЩЕГО, не домена: правило-подстановка (`*.*` роли-
// суперпользователя) своего набора не имеет by construction — перечислить
// ресурсы подстановки домену нечем, каталог ему не принадлежит, — а пустое
// превью читалось бы как «роль ничего не даёт».
//
// # Запасной словарь даётся ПОДСТАНОВКЕ, а не всякому промаху (kacho#1814)
//
// Прежде его получала ЛЮБАЯ нерезолвящаяся пара, и это переворачивало смысл
// снятия ресурса: правило, называющее снятый `compute.disk`, разворачивалось в
// глаголы ВСЕЙ платформы, то есть после снятия превью показывало не «меньше», а
// БОЛЬШЕ. Роль обещала арендатору то, чего материализация не даёт, и обещала
// тем громче, чем уже правило.
//
// Различает ФОРМА пары, а не исход резолва: подстановка называет «все» и потому
// законно берёт общий словарь; названный ресурс называет ОДИН тип, и если этого
// типа нет — давать нечего. Промах названной пары остаётся промахом
// (`ok=false`), и вызывающий разворачивает её ни во что.
func WithCommonFallback(lookup TypeVerbLookup, common []string) TypeVerbLookup {
	return func(module, resource string) ([]string, bool) {
		if lookup != nil {
			if verbs, ok := lookup(module, resource); ok {
				return verbs, true
			}
		}
		if module == wildcard || resource == wildcard {
			return common, true
		}
		return nil, false
	}
}

// ruleVerbSet — набор, в который разворачивается подстановка ЭТОГО правила:
// ОБЪЕДИНЕНИЕ наборов типов, которые правило адресует.
//
// Правило адресует Module × Resources, и обе оси допускают подстановку. Перечислить
// ресурсы модуля домен не может (каталог ему не принадлежит), поэтому такая пара
// уходит в lookup как есть и решение о ней принимает вызывающий.
func (r Rule) ruleVerbSet(lookup TypeVerbLookup) []string {
	return r.ruleVerbSetOf(lookup, r.Resources)
}

// ruleVerbSetOf — то же объединение по названным ресурсам правила.
func (r Rule) ruleVerbSetOf(lookup TypeVerbLookup, resources []string) []string {
	if lookup == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, res := range resources {
		verbs, ok := lookup(r.Module, res)
		if !ok {
			continue
		}
		for _, v := range verbs {
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// hasWildcardVerb — правило называет подстановку глагола. Такое правило
// объявляет на каждом своём ресурсе ОДИН сегмент — якорь ([RuleRefsOf]).
func (r Rule) hasWildcardVerb() bool {
	for _, v := range r.Verbs {
		if v == wildcard {
			return true
		}
	}
	return false
}

// addressable — ресурс правила объявляет сегменты: ни модуль, ни ресурс не
// подстановка. Тот же признак, которым [RuleRefsOf] решает, класть ли сегмент.
func (r Rule) addressable(res string) bool {
	return r.Module != wildcard && res != wildcard
}

// expandedVerbSet — множество глаголов превью роли по формуле §2.3 приёмки
// `catalog-consequence-reaches-role-readers.md` и признак «правило называет
// подстановку глагола».
//
// Ресурс правила судится ПОРОЗНЬ, и формула одна на каждый:
//
//   - ресурс НЕадресуемый (`*` в модуле либо в ресурсе) сегментов не объявляет,
//     признаку о нём сказать нечего — его явные глаголы и разворот подстановки
//     идут как прежде;
//   - адресуемый ресурс даёт явный глагол, если проекция выдач держит его
//     сегмент «тип + глагол» (у правила с подстановкой глагола сегмент один —
//     якорь), а подстановку — набором своего типа, если держится якорь;
//   - глагол ЯРУСНОЙ ПАРЫ выведен из суждения: класс ярусный, набор пары
//     резолвится, и глагола в нём нет — то есть строка каталога пары ярусная.
//     Пара, объявившая тот же класс пообъектно, и пара снятого ресурса ветви не
//     получают.
//
// Гранулярность — СЕГМЕНТ, а не правило: держащийся сегмент даёт свой глагол,
// а не все глаголы правила.
//
// Признак не прочитан — судить нечем, и превью считается по букве правил: отказ
// за такую роль несёт перевод в ответ (см. [PreviewHolding]).
func (r Role) expandedVerbSet(lookup TypeVerbLookup) (set map[string]bool, wildcardVerb bool) {
	set = map[string]bool{}
	add := func(verbs ...string) {
		for _, v := range verbs {
			set[NormalizeVerb(v)] = true
		}
	}
	for _, rule := range r.Rules {
		anchorOnly := rule.hasWildcardVerb()
		wildcardVerb = wildcardVerb || anchorOnly
		judged := r.Holding.Read()
		if !judged || len(rule.Resources) == 0 {
			for _, v := range rule.Verbs {
				if v == wildcard {
					add(rule.ruleVerbSet(lookup)...)
					continue
				}
				// Приведение ТОЙ ЖЕ точкой, что и на эмиссии: иначе одно слово в
				// двух написаниях дало бы в превью две записи, а материализация —
				// одну.
				add(v)
			}
			continue
		}
		for _, res := range rule.Resources {
			if !rule.addressable(res) {
				for _, v := range rule.Verbs {
					if v == wildcard {
						add(rule.ruleVerbSetOf(lookup, []string{res})...)
						continue
					}
					add(v)
				}
				continue
			}
			dotted := RoleRuleRef{Module: rule.Module, Resource: res}.Dotted()
			for _, v := range rule.Verbs {
				if v == wildcard {
					if r.Holding.holds(dotted, "") {
						add(rule.ruleVerbSetOf(lookup, []string{res})...)
					}
					continue
				}
				nv := NormalizeVerb(v)
				seg := nv
				if anchorOnly {
					seg = ""
				}
				if r.Holding.holds(dotted, seg) || r.Holding.tierPair(lookup, rule.Module, res, nv) {
					add(nv)
				}
			}
		}
	}
	return set, wildcardVerb
}

// orderVerbs — глаголы множества в каноническом порядке показа; глаголы вне
// старшинства идут после, в детерминированном (отсортированном) порядке.
func orderVerbs(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	seen := map[string]bool{}
	for _, c := range verbDisplayPrecedence {
		if set[c] {
			out = append(out, c)
			seen[c] = true
		}
	}
	// Детерминированный хвост: глаголы вне старшинства показа.
	extra := make([]string, 0)
	for v := range set {
		if !seen[v] {
			extra = append(extra, v)
		}
	}
	sortStrings(extra)
	return append(out, extra...)
}

// OrderVerbsForDisplay возвращает глаголы в КАНОНИЧЕСКОМ порядке показа: сперва
// старшинство (get/list/create/update/delete), затем всё остальное — стабильно, по
// алфавиту.
//
// Точка порядка ОДНА на всё превью и на публичное поле каталога. Порядок этих
// поверхностей — часть контракта: его читают существующие клиенты. Пока он жил
// внутри превью, поле каталога брало порядок из своего источника — и смена
// источника на пересечение наборов молча переставила бы значения по алфавиту.
func OrderVerbsForDisplay(verbs []string) []string {
	set := make(map[string]bool, len(verbs))
	for _, v := range verbs {
		set[NormalizeVerb(v)] = true
	}
	return orderVerbs(set)
}

// AuthoredVerbs — объединение глаголов правил роли по сегментам, которые роль
// держит, без повторов и в каноническом порядке (формула — [Role.expandedVerbSet]).
// Пусто у роли, выданной одними метками, и у роли без правил.
func (r Role) AuthoredVerbs(lookup TypeVerbLookup) []string {
	set, _ := r.expandedVerbSet(lookup)
	return orderVerbs(set)
}

// isEditorTier — роль-редактор: правку даёт, удаления и подстановки `*` не
// называет (администратор удаление уже несёт), и правка у неё ВЛЕЧЁТ удаление.
//
// Последнее условие — то же, что у материализации (`RulePolicy.UpdateImpliesDelete`,
// kaname#1006): роль модуля удаление к правке не получает, и превью, обещавшее
// ей `delete*`, разошлось бы с выданным.
//
// Выводится из СУЖЕННОГО множества: квалификатор уходит вместе со своим
// основанием, отдельного правила для него нет.
func (r Role) isEditorTier(lookup TypeVerbLookup) bool {
	if !PolicyOfRole(r.IsSystem, r.OwnerModule).UpdateImpliesDelete() {
		return false
	}
	set, wildcardVerb := r.expandedVerbSet(lookup)
	return !wildcardVerb && set["update"] && !set["delete"]
}

// EffectiveVerbs — [Role.AuthoredVerbs] плюс квалификатор редактора `delete*` у
// роли-редактора.
func (r Role) EffectiveVerbs(lookup TypeVerbLookup) []string {
	authored := r.AuthoredVerbs(lookup)
	if r.isEditorTier(lookup) {
		return append(authored, EditorDeleteVerb)
	}
	return authored
}

// VerbNotes — пояснения к производным глаголам фактического превью, ключ — сам
// глагол. Сегодня пояснение несёт только квалификатор редактора `delete*`.
func (r Role) VerbNotes(lookup TypeVerbLookup) map[string]string {
	if r.isEditorTier(lookup) {
		return map[string]string{EditorDeleteVerb: EditorDeleteNote}
	}
	return map[string]string{}
}

// sortStrings — малая сортировка по возрастанию на месте: ради одного вызова
// пакет сортировки не импортируется.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
