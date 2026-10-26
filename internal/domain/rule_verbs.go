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

// ResolveVerbsAndTier разворачивает авторские глаголы правила (`*` → набор ТИПА) и
// выводит ярус ПРАВИЛА — не роли целиком (B-11): сильнейший класс среди его
// глаголов, чтение → `viewer`, правка и прочие изменяющие → `editor`. Ярусный
// кортеж держит вопросы, которые спрашивают ярус; точное право по глаголу несут
// отношения `v_*`.
//
// # Удаление яруса не даёт
//
// Прежде `delete` давал `admin`, а `admin` на области — это право выдавать доступ и
// всё, что модель выводит из администратора: роль «только удалять» открывала
// держателю выдачу любых прав (kaname#1035, kaname#1039; приёмка
// role-rights-stay-within-what-is-named.md, Р1 и В1). Право удалять несёт
// отношение `v_delete`. Правило, все глаголы которого — `delete`, яруса не даёт
// вовсе: ответ — пустая строка, и ярусный кортеж не пишется. Удаление не даёт и
// `viewer` — глагол удаления не даёт чтения.
//
// # Подстановка `*` — единственный путь к `admin`
//
// Правило, назвавшее все глаголы типа подстановкой, выводит ярус по развёрнутому
// набору так же, как прежде: удаление в нём означает администратора. Роли с `*` и
// владелец аккаунта поэтому не меняются (Р1).
//
// typeVerbs — набор глаголов, объявленный ТИПОМ, на который правило адресовано. Он
// приходит ПАРАМЕТРОМ от вызывающего, который тип уже знает: владельцем таблицы
// остаётся authzmap, а домен — без внешних зависимостей (см. объявление файла).
// Вызывающий, у которого типа нет (правило не резолвится ни в один известный),
// передаёт словарь, общий для всех ресурсов, — это его решение, не домена.
func ResolveVerbsAndTier(authored, typeVerbs []string) (verbs []string, tier string) {
	for _, v := range authored {
		if v == "*" {
			return typeVerbs, wildcardTier(typeVerbs)
		}
	}
	hasViewer, hasEditor := false, false
	for _, v := range authored {
		switch verbTier(v) {
		case "editor":
			hasEditor = true
		case "viewer":
			hasViewer = true
		}
	}
	switch {
	case hasEditor:
		tier = "editor"
	case hasViewer:
		tier = "viewer"
	}
	return authored, tier
}

// wildcardTier — ярус подстановки `*` по развёрнутому набору типа: удаление в нём
// означает администратора, иначе — сильнейший класс прочих глаголов; набор без
// глаголов — наблюдатель. Вывод тот же, что до kaname#1035: роль с `*` не меняется.
func wildcardTier(expanded []string) string {
	hasEditor := false
	for _, v := range expanded {
		if NormalizeVerb(v) == verbDelete {
			return "admin"
		}
		if verbTier(v) == "editor" {
			hasEditor = true
		}
	}
	if hasEditor {
		return "editor"
	}
	return "viewer"
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
//
// # Подстановка сохраняется знаком `*` рядом с развёрнутым набором
//
// Подстановка `*` разворачивается в набор ТИПА якоря — из него пишутся отношения
// `v_*`. Сам знак `*` при этом остаётся в ответе: ярус выводится из него
// ([ResolveVerbsAndTier]), и только подстановка даёт ярус `admin` — правило,
// перечислившее те же глаголы поимённо, его не даёт (удаление яруса не даёт,
// kaname#1035). Без знака сборщик кортежей якоря видел бы развёрнутый набор, и
// владелец аккаунта (`*.*`) молча понизился бы до редактора. Знак отношением не
// становится: глаголом типа он не является ([IsVerbOfType]), и классу он не
// достаётся (класс получает только чтение, [IsClassReadVerb]).
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
	for _, v := range collected {
		if v == wildcard {
			return append(append([]string(nil), verbs...), wildcard)
		}
	}
	return verbs
}

// verbDelete — глагол удаления в канонической форме.
const verbDelete = "delete"

// verbTier — ярус одного глагола правила вне подстановки: чтение → `viewer`,
// удаление → пустая строка (яруса не даёт, Р1 kaname#1035), прочее (создание,
// правка, доменные изменения) → `editor`. Только для ярусного кортежа: точное право
// по глаголу несут отношения `v_*`.
//
// Доменные чтения getTargetStates и listOperations — наблюдательские, в лад с
// `authzmap.verbClass` и картой `resolveActionToRelation` (authorize_service.go):
// согласие трёх классификаторов — инвариант паритета ярусов (F-53), роль правил не
// получает яруса сильнее прежнего. Без этого роли nlb loadbalancer.operator и
// target_manager давали бы `editor` на слушателях и группах целей.
func verbTier(verb string) string {
	switch NormalizeVerb(verb) {
	case "get", "list", "view", "watch", "describe", "read",
		"gettargetstates", "listoperations":
		return "viewer"
	case verbDelete:
		return ""
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
	// Вложенные правила объявляют свои сегменты так же, как правила верхнего
	// уровня (kaname#874): «объявленных сегментов» роли не меньше, чем она даёт.
	for _, r := range withEffectiveChildren(rules) {
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

// withEffectiveChildren — правила роли и их вложенные правила одним перечнем, в
// порядке объявления (владелец, затем его вложенные), каждое вложенное — с
// модулем владельца. Для проекций, которым безразлично, откуда пришёл сегмент.
func withEffectiveChildren(rules Rules) Rules {
	if !rules.HasChildren() {
		return rules
	}
	out := make(Rules, 0, len(rules))
	for _, r := range rules {
		out = append(out, r)
		out = append(out, r.EffectiveChildren()...)
	}
	return out
}
