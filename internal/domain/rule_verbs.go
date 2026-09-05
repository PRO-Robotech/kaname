// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_verbs.go — per-rule verb expansion + back-compat
// tier derivation. Pure domain (stdlib only) so BOTH the arm-emit path
// (access_binding.scope_grant_tuples) and the reconciler
// (reconcile.ruleObjectTuples) derive the SAME per-object verbs+tier from a rule.
// Both paths call THESE functions directly (no duplicated, drift-prone copies), so
// parity between them is guaranteed by the compiler, not a self-test.

import "strings"

// IsVerbOfType сообщает, объявляет ли ТИП этот глагол, то есть материализуется ли
// он как отношение `v_<глагол>` НА ЭТОМ типе.
//
// Заменила снятый глобальный словарь глаголов на путях эмиссии. Разница не косметическая: глобальный
// словарь отвечал одинаково для всех типов, поэтому «у этого типа такого глагола
// нет» было невыразимо — и правило, называющее соседний глагол, порождало кортеж с
// отношением, которого у типа не существует. Пустой набор не принадлежит никому
// (fail-closed): тип, не объявивший ничего, не получает ни одного `v_*`.
func IsVerbOfType(verb string, typeVerbs []string) bool {
	want := NormalizeVerb(verb)
	if want == "" {
		return false
	}
	for _, v := range typeVerbs {
		if NormalizeVerb(v) == want {
			return true
		}
	}
	return false
}

// NormalizeVerb — ЕДИНСТВЕННАЯ точка приведения имени глагола к канонической форме.
//
// Разрыв, который она закрывает, был двусторонним. Проверка принадлежности
// приводила ВХОД, а индекс словаря строился ДОСЛОВНО — словарная запись с заглавной
// буквой не нашлась бы никогда. И наоборот: имя отношения собиралось из АВТОРСКОГО
// написания, поэтому написание, отличающееся регистром, проходило проверку и
// адресовало отношение, которого в модели нет; владелец модели отвергает такую
// запись окончательно, а отказ считается постоянным — строка навсегда блокирует
// свою партицию очереди.
//
// Приведение ТОЖДЕСТВЕННО на всех существующих глаголах, поэтому ни одно отношение,
// ни один кортеж и ни одна запись каталога не меняются.
func NormalizeVerb(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// ResolveVerbsAndTier expands a rule's authored verbs (verb `*` → набор ТИПА) and
// derives the per-RULE back-compat tier (strongest verb-class among the rule's
// verbs), mapped the SAME way the consumer authz-gate resolves an action:
// get/list → viewer ; create/update (+ domain mutations) → editor ; delete → admin.
// Per-RULE, never whole-role (B-11). The tier tuple keeps tier-based Check
// call-sites working; the v_* tuples carry the precise per-verb enforcement.
// typeVerbs — набор глаголов, объявленный ТИПОМ, на который правило адресовано. Он
// приходит ПАРАМЕТРОМ от вызывающего, который тип уже знает: владельцем таблицы
// остаётся authzmap, а домен — без внешних зависимостей (см. объявление файла).
// Вызывающий, у которого типа нет (правило не резолвится ни в один известный),
// передаёт словарь, общий для всех ресурсов, — это его решение, не домена.
func ResolveVerbsAndTier(authored, typeVerbs []string) (verbs []string, tier string) {
	expanded := authored
	for _, v := range authored {
		if v == "*" {
			expanded = typeVerbs
			break
		}
	}
	hasEditor, hasAdmin := false, false
	for _, v := range expanded {
		switch verbBackCompatTier(v) {
		case "admin":
			hasAdmin = true
		case "editor":
			hasEditor = true
		}
	}
	switch {
	case hasAdmin:
		tier = "admin"
	case hasEditor:
		tier = "editor"
	default:
		tier = "viewer"
	}
	return expanded, tier
}

// ScopeSelfVerbs returns the UNION of authored verbs the role's rules grant on the
// binding's OWN scope resource-type — i.e. on the scope object itself
// (`account:<X>`/`project:<X>`/`cluster:<X>`). RBAC explicit-model 2026 P4 (D-7 /
// КФ-3 / C-01): a rules-role bound on a scope must materialize its tier (+ verb-
// bearing v_*) ON THE SCOPE ANCHOR ITSELF — the write-authz anchor / self-access
// that the removed binding-time scope_grant/anchor emit produced. The reconciler is
// now the SINGLE materialization path, so this projection feeds a scope-self
// desired member (reconcile.desiredRuleMembers), NOT a binding-time emit.
//
// A rule contributes its verbs when EITHER its (module,resource) is the FULL `*.*`
// wildcard (the system superuser shape — migration 0031: admin/edit/view) OR its
// (module,resource) is exactly ("iam", scopeResource) — e.g. an `iam.account` rule
// on an account-scoped binding. scopeResource is the scope's resource type:
// "account"|"project". (cluster has no per-resource iam rule; only the `*.*`
// superuser shape grants cluster-self — handled by the wildcard branch.)
//
// Returns nil when no rule applies to the scope self (a content-only role —
// e.g. `compute.instance` rules — grants nothing ON the account/project object,
// only on its content; the scope-self member is then absent, fail-closed).
func (rs Rules) ScopeSelfVerbs(scopeResource string, typeVerbs []string) []string {
	var collected []string
	matched := false
	for _, r := range rs {
		applies := false
		if r.Module == wildcard {
			// FULL `*.*` superuser shape; a half-wildcard (`*.concrete`/`concrete.*`)
			// is not a real seed shape and never grants scope-self (fail-closed).
			for _, res := range r.Resources {
				if res == wildcard {
					applies = true
					break
				}
			}
		} else if r.Module == "iam" && scopeResource != "" {
			for _, res := range r.Resources {
				if res == scopeResource {
					applies = true
					break
				}
			}
		}
		if !applies {
			continue
		}
		matched = true
		collected = append(collected, r.Verbs...)
	}
	if !matched {
		return nil
	}
	verbs, _ := ResolveVerbsAndTier(collected, typeVerbs)
	return verbs
}

// verbBackCompatTier maps a rule verb to the tier the consumer authz-gate resolves
// it to (resolveActionToRelation parity): get/list → viewer, delete → admin, else
// editor (create/update/domain mutations). ONLY for the back-compat tier tuple;
// the v_* tuples carry the precise per-verb enforcement. delete→admin (NOT editor)
// keeps Check(delete)→admin allowed for a rule granting delete.
//
// The read-style domain verbs getTargetStates / listOperations resolve to VIEWER —
// in lockstep with authzmap.verbClass and the consumer resolveActionToRelation map
// (authorize_service.go), which both classify them as read-tier. Keeping all three
// aligned is the tier-parity invariant (F-53): a rules-role must emit the SAME tier
// the legacy permissions did, never a stronger one (no escalation). Without this,
// the nlb loadbalancer.operator / target_manager roles would emit editor on
// listeners/targetGroups where legacy emitted viewer.
func verbBackCompatTier(verb string) string {
	switch NormalizeVerb(verb) {
	case "get", "list", "view", "watch", "describe", "read",
		"gettargetstates", "listoperations":
		return "viewer"
	case "delete":
		return "admin"
	default:
		return "editor"
	}
}

// RoleVerb — одна пара проекции «роль даёт этот глагол на этом типе».
//
// Тип — тип объекта модели прав (`vpc_network`), не точечное имя ресурса:
// вердикт спрашивает именно им. Глагол — в канонической форме и БЕЗ приставки
// отношения: приставку знает компилятор модели, и дублировать её здесь значило
// бы завести второе место, где она может смениться.
type RoleVerb struct {
	ObjectType string
	Verb       string
}

// RoleRuleRef — один ОБЪЯВЛЕННЫЙ сегмент правила роли: «эта роль называет вот
// этот (модуль, ресурс) и вот этот глагол».
//
// # Чем это НЕ является — и различие несущее
//
// Это НЕ `RoleVerb`. Та проекция отвечает на вопрос вердикта «разрешено ли
// действие» и содержит только то, что РЕЗОЛВИТСЯ: тип, которого не знает словарь
// модели, пар не даёт (`RoleVerbsFromSelectors`). Здесь наоборот — строка
// кладётся на КАЖДЫЙ объявленный сегмент, резолвится он или нет, потому что
// предмет этой таблицы есть ссылочная целостность: молчаливый пропуск и есть тот
// дефект, ради которого заводится ключ, и воспроизвести его в новом писателе
// значило бы завести ключ, которому нечего отвергать.
//
// # Пустой глагол — это ЯКОРЬ, а не «глагол не задан»
//
// Правило, не сузившее глаголы (`verbs: ["*"]`), даёт строку с пустым `Verb`,
// которая ложится в хранилище значением NULL. Ключ ресурса на ней проверяется,
// ключ глагола — пропускается `MATCH SIMPLE`, и это ПРАВИЛЬНО: ресурс уже
// проверен первым ключом. Ключей поэтому два, а не один: под одним составным
// ключом `MATCH SIMPLE` снял бы проверку целиком, и правило, называющее
// несуществующий ресурс, принималось бы успешно.
type RoleRuleRef struct {
	Module   string
	Resource string
	// Verb — пустая строка означает ЯКОРЬ (глаголы не сужены), а не отсутствие
	// значения: см. абзац выше.
	Verb string
}

// IsAnchor — правило не сузило глаголы.
func (r RoleRuleRef) IsAnchor() bool { return r.Verb == "" }

// Dotted — точечная форма имени типа (`vpc.network`), та самая, какой говорят
// `role_verb.object_type`, `role_rule_selectors.object_types` и колонка
// `catalog_resource.dotted` под своим CHECK.
//
// ЕДИНСТВЕННОЕ место, где эта склейка пишется в Go: второе написание разошлось
// бы с первым молча, а соединение по разным словарям не совпадает никогда — и
// отличить это от «права нет» было бы нечем.
func (r RoleRuleRef) Dotted() string { return r.Module + "." + r.Resource }

// RuleRefsOf — объявленные сегменты правил в форме строк проекции.
//
// Источник — АВТОРСКОЕ правило, а не селекторы: селекторы уже прошли через
// словарь модели и потеряли то, что он не знает, — то есть ровно те сегменты,
// ради которых ключ и заводится. Подстановка `*` в ресурсе и модуле сегментов не
// даёт: она называет не имя, а «все», и адресовать ею строку каталога нечего
// (системная роль с `*.*` материализуется коротким замыканием администратора
// кластера).
func RuleRefsOf(rules Rules) []RoleRuleRef {
	seen := make(map[RoleRuleRef]bool)
	out := make([]RoleRuleRef, 0, len(rules))
	for _, r := range rules {
		if r.Module == "*" {
			continue
		}
		for _, res := range r.Resources {
			if res == "*" {
				continue
			}
			for _, ref := range refsOfRule(r, res) {
				if seen[ref] {
					continue
				}
				seen[ref] = true
				out = append(out, ref)
			}
		}
	}
	return out
}

// refsOfRule — сегменты одного правила на одном ресурсе. Глагол `*` даёт ЯКОРЬ
// (одну строку с пустым глаголом), названный глагол — строку на каждый.
func refsOfRule(r Rule, res string) []RoleRuleRef {
	for _, v := range r.Verbs {
		if v == "*" {
			return []RoleRuleRef{{Module: r.Module, Resource: res}}
		}
	}
	out := make([]RoleRuleRef, 0, len(r.Verbs))
	for _, v := range r.Verbs {
		out = append(out, RoleRuleRef{Module: r.Module, Resource: res, Verb: NormalizeVerb(v)})
	}
	return out
}
