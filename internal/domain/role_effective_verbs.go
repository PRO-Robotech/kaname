// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_effective_verbs.go — redesign-2026 F6. The honest effective-verb preview
// surfaced by RoleService (authored vs effective). authoredVerbs is the deduped,
// canonically-ordered union of the verbs the role's rules grant (`*` expands to
// the verb set OF THE TYPE the rule addresses). effectiveVerbs adds the editor
// `delete*` qualifier: a role that grants `update` but not `delete`/`*` is
// editor-tier, and an editor MAY delete the in-scope leaf objects it edits
// (co-materialized), but NOT the account/project anchor — the verbNote states this
// verbatim so the least-privilege preview never under-promises.
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

// EditorDeleteVerb is the qualifier appended to an editor-tier role's effective
// verbs (delete of in-scope leaf objects, not the anchor).
const EditorDeleteVerb = "delete*"

// EditorDeleteNote is the verbatim explanation of the editor delete-qualifier.
const EditorDeleteNote = "co-materialized on in-scope leaf objects, NOT on the account/project anchor itself"

// TypeVerbLookup — набор глаголов, объявленный типом (module, resource);
// ok=false, когда пара не резолвится ни в один известный тип.
//
// Приходит ПАРАМЕТРОМ, а не импортом таблицы: владельцем таблицы остаётся authzmap,
// а домен — без внешних зависимостей (см. rule_verbs.go, «pure domain»).
type TypeVerbLookup func(module, resource string) (verbs []string, ok bool)

// WithCommonFallback оборачивает lookup так, что нерезолвящаяся пара получает
// словарь, ОБЩИЙ для всех ресурсов.
//
// Это решение ВЫЗЫВАЮЩЕГО, не домена: правило, не адресующее ни одного известного
// типа (в том числе `*`-форма), всё равно обязано дать превью — иначе роль
// показала бы пустой набор и выглядела бы ничего не дающей.
func WithCommonFallback(lookup TypeVerbLookup, common []string) TypeVerbLookup {
	return func(module, resource string) ([]string, bool) {
		if lookup != nil {
			if verbs, ok := lookup(module, resource); ok {
				return verbs, true
			}
		}
		return common, true
	}
}

// ruleVerbSet — набор, в который разворачивается подстановка ЭТОГО правила:
// ОБЪЕДИНЕНИЕ наборов типов, которые правило адресует.
//
// Правило адресует Module × Resources, и обе оси допускают подстановку. Перечислить
// ресурсы модуля домен не может (каталог ему не принадлежит), поэтому такая пара
// уходит в lookup как есть и решение о ней принимает вызывающий.
func (r Rule) ruleVerbSet(lookup TypeVerbLookup) []string {
	if lookup == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, res := range r.Resources {
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

// expandedVerbSet returns the deduped verb set the role grants, with `*` expanded
// to the verb set of the type(s) the producing rule addresses, plus whether any
// rule used the `*` wildcard.
func (r Role) expandedVerbSet(lookup TypeVerbLookup) (set map[string]bool, wildcard bool) {
	set = map[string]bool{}
	for _, rule := range r.Rules {
		for _, v := range rule.Verbs {
			if v == "*" {
				wildcard = true
				for _, c := range rule.ruleVerbSet(lookup) {
					set[c] = true
				}
				continue
			}
			set[v] = true
		}
	}
	return set, wildcard
}

// orderVerbs returns the verbs of set in canonical display order, verbs outside
// the precedence list appended in deterministic (sorted) order.
func orderVerbs(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	seen := map[string]bool{}
	for _, c := range verbDisplayPrecedence {
		if set[c] {
			out = append(out, c)
			seen[c] = true
		}
	}
	// deterministic tail for any verb outside the display precedence.
	extra := make([]string, 0)
	for v := range set {
		if !seen[v] {
			extra = append(extra, v)
		}
	}
	sortStrings(extra)
	return append(out, extra...)
}

// AuthoredVerbs is the deduped, canonically-ordered union of the role's rule verbs
// (`*` expands to the verb set of the addressed type). Empty for a label-only /
// rules-less role.
func (r Role) AuthoredVerbs(lookup TypeVerbLookup) []string {
	set, _ := r.expandedVerbSet(lookup)
	return orderVerbs(set)
}

// isEditorTier reports whether the role is editor-tier: it grants `update` but not
// `delete` and did not use the `*` wildcard (an admin/owner already carries delete).
func (r Role) isEditorTier(lookup TypeVerbLookup) bool {
	set, wildcard := r.expandedVerbSet(lookup)
	return !wildcard && set["update"] && !set["delete"]
}

// EffectiveVerbs is AuthoredVerbs plus the editor `delete*` qualifier for an
// editor-tier role.
func (r Role) EffectiveVerbs(lookup TypeVerbLookup) []string {
	authored := r.AuthoredVerbs(lookup)
	if r.isEditorTier(lookup) {
		return append(authored, EditorDeleteVerb)
	}
	return authored
}

// VerbNotes returns the per-verb clarifications for the effective preview. Only
// the editor `delete*` qualifier carries a note today.
func (r Role) VerbNotes(lookup TypeVerbLookup) map[string]string {
	if r.isEditorTier(lookup) {
		return map[string]string{EditorDeleteVerb: EditorDeleteNote}
	}
	return map[string]string{}
}

// sortStrings — tiny in-place ascending sort (avoids importing sort for one call).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
