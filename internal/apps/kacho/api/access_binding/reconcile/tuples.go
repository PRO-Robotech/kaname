// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// tuples.go — per-object FGA tuple builder for materialized role.rules ARM_LABELS
// membership (RBAC rules-model 2026). For ONE label-matched object the
// per-object v_<verb> + back-compat tier tuples are derived from the producing
// RULE's verbs (domain.ResolveVerbsAndTier), so the reconciler can emit/eager-
// revoke the tuple of a single member on a diff.
//
// This is a use-case-layer concern (it owns the catalog-snapshot dependency),
// keeping the domain pure.

import (
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// ruleObjectTuples builds the per-object FGA tuple set for ONE label-matched
// object of an ARM_LABELS rule. It REUSES the per-object
// emit semantics (access_binding.emitNamesRule): the tier + closed per-verb v_*
// relations are derived from the RULE'S VERBS (domain.ResolveVerbsAndTier), NOT
// from the role's compiled permissions (ARM_LABELS rules are excluded from
// CompileRules). v_<verb> tuples are emitted ONLY when (a) ТИП объявляет
// непустой набор `v_*` AND (b) глагол входит в набор ИМЕННО ЭТОГО типа
// (domain.IsVerbOfType) — не в платформенный словарь: набор есть атрибут типа.
// Иначе доступ несёт ярусный кортеж. ok=false
// when the (objectType) has no FGA object type (a typo'd type never grants —
// fail-closed). The subject is the binding's subject (already FGA-formatted).
func ruleObjectTuples(cat *catalog.Facts, subject string, verbs []string, objectType, objectID string) ([]domain.MembershipTuple, bool) {
	fgaType, ok := cat.FGAObjectType(objectType)
	if !ok {
		return nil, false
	}
	return ruleObjectTuplesWithTypeVerbs(cat, subject, verbs, fgaType, objectID, typeVerbsOf(cat, fgaType))
}

// typeVerbsOf — набор глаголов, объявленный ТИПОМ; для неглагольного типа —
// словарь, ОБЩИЙ для всех ресурсов.
//
// Каталог приходит ПАРАМЕТРОМ, а не спрашивается у литерала (kacho#1816): ответ
// на «какие глаголы объявлены» может измениться в РАБОТАЮЩЕМ процессе — снятием
// строки, — и читатель на литерале продолжил бы считать снятый тип живым до
// следующего перезапуска. Отказ тогда приходит ЧУЖОЙ полосой: пара по снятому
// типу доезжает до внешнего ключа `role_verb_type_fk` и отвергается им.
//
// Запасной вариант нужен ради яруса, а не ради `v_*`: ярус выводится из
// РАЗВЁРНУТЫХ глаголов правила, поэтому подстановка `*` на типе без собственного
// набора обязана по-прежнему давать полный набор — иначе роль-суперпользователь
// молча понизилась бы с администратора до наблюдателя. Отношения `v_*` при этом не
// эмитятся всё равно: пустой набор не принадлежит никому (domain.IsVerbOfType).
func typeVerbsOf(cat *catalog.Facts, fgaType string) []string {
	if set := cat.VerbsOfType(fgaType); len(set) > 0 {
		return set
	}
	return cat.CommonVerbVocabulary()
}

// ruleObjectTuplesWithTypeVerbs — та же сборка при ЯВНО переданном наборе типа.
// Набор — параметр, чтобы отрицательные кейсы могли предъявить тип с УРЕЗАННЫМ
// набором: сегодня такого типа в таблице нет, а свойство обязано охраняться ДО
// появления первого пользователя.
func ruleObjectTuplesWithTypeVerbs(cat *catalog.Facts, subject string, verbs []string, fgaType, objectID string,
	typeVerbs []string) ([]domain.MembershipTuple, bool) {
	_, tier := domain.ResolveVerbsAndTier(verbs, typeVerbs)
	object := fmt.Sprintf("%s:%s", fgaType, objectID)
	// Набор глаголов считает ОДИН предикат — тот же, которым наполняется проекция
	// `role_verb`, читаемая формой E. Две реализации одного вопроса («что роль
	// разрешает на типе») по отдельности непротиворечивы и расходятся молча: ровно
	// так роль-администратор давала движку всё, а форме E — ничего (#496).
	granted := cat.GrantedVerbs(fgaType, verbs, typeVerbs)

	seen := map[domain.MembershipTuple]struct{}{}
	var out []domain.MembershipTuple
	add := func(relation string) {
		t := domain.MembershipTuple{User: subject, Relation: relation, Object: object}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	// Набор — включая развёрнутую подстановку, отсев чужого глагола и удаление,
	// которое влечёт правка на листе, — целиком принадлежит предикату выше. Разбор
	// каждого из трёх правил живёт рядом с ним; здесь остаётся только форма
	// отношения.
	for _, verb := range granted {
		add("v_" + verb)
	}
	// Back-compat tier tuple — carries domain-verb access + keeps tier-based Check
	// call-sites working.
	//
	// Условие у него есть, и прежняя редакция комментария его умалчивала: ярусный
	// кортеж эмитится, только если тип ВООБЩЕ резолвится (иначе вызывающий получил
	// ok=false выше и ни одного кортежа). Внутри же этой ветки — да, безусловно: он
	// не зависит от набора глаголов типа и остаётся носителем доступа для доменного
	// глагола, у которого отношения `v_*` нет по построению.
	add(tier)
	return out, true
}

// scopeSelfRuleFP — the sentinel rule_fp attributing the scope-self member (D-7).
// It is NOT a content rule's fingerprint; using a fixed, NUL-free sentinel gives the
// scope-self member its own access_binding_target_members row + emitted-tuple ledger
// lineage so the symmetric revoke / diff treats it independently of content members.
const scopeSelfRuleFP = "scope_self"

// scopeSelfMember builds the DesiredMember for the binding's scope anchor itself
// (D-7 / КФ-3 / C-01) from the role's scope-self verbs. The member object_type is
// the dotted iam scope key (iam.account / iam.project) so it round-trips through
// the catalog snapshot for the symmetric revoke; the FGA tuples target the bare scope
// object (account:<X>/project:<X>). ok=false when the role grants nothing on the
// scope self OR the scope type has no live catalog row (cluster — D-9 short-circuit
// owns cluster super-admin, not this per-object path).
func scopeSelfMember(cat *catalog.Facts, subject string, scopeType, scopeID string, verbs []string) (DesiredMember, bool) {
	dotted := "iam." + scopeType // iam.account / iam.project (cluster has no mapping)
	if _, ok := cat.FGAObjectType(dotted); !ok {
		return DesiredMember{}, false
	}
	tuples, ok := scopeSelfTuples(cat, subject, scopeType, scopeID, verbs)
	if !ok {
		return DesiredMember{}, false
	}
	return DesiredMember{
		RuleFP:     scopeSelfRuleFP,
		ObjectType: dotted,
		ObjectID:   scopeID,
		Status:     domain.VerificationActive,
		Tuples:     tuples,
	}, true
}

// scopeSelfTuples builds the FGA tuple set materialized ON THE BINDING'S OWN SCOPE
// OBJECT (`account:<X>`/`project:<X>`) from the role's scope-self verbs
// (RBAC explicit-model 2026 P4 / D-7 / КФ-3 / C-01). It is the unified-reconciler
// equivalent of the removed binding-time scope-anchor/scope_grant emit: the tier
// (back-compat) tuple is the write-authz anchor / no-access-loss anchor, plus the
// closed v_* set when the scope type is verb-bearing (account/project, #218).
//
// Only the verb-bearing hierarchy scopes account/project materialize a per-object
// scope-self member. cluster is DELIBERATELY excluded: cluster super-admin is served
// by the D-9 flat short-circuit (cluster:cluster_kacho_root#system_admin), NOT a
// per-object tuple — materializing per-object on cluster is the Q-2/D-9 anti-pattern.
// The sole caller (scopeSelfMember) already gates cluster out ("iam.cluster" has no
// catalog row at all — the hierarchy apex is not a resource), so this function never
// receives scopeType=="cluster"; the guard below is the explicit fail-closed fence
// (scope_self_cluster_guard_test.go pins the invariant against a future iam.cluster
// type re-enabling the dead path). ok=false when scopeType is not a per-object
// hierarchy scope or there are no verbs (a content-only role grants nothing on the
// anchor).
func scopeSelfTuples(cat *catalog.Facts, subject, scopeType, scopeID string, verbs []string) ([]domain.MembershipTuple, bool) {
	if scopeID == "" || len(verbs) == 0 {
		return nil, false
	}
	switch scopeType {
	case "account", "project":
		// per-object verb-bearing hierarchy scopes — materialized below.
	default:
		// cluster (D-9 short-circuit owns it) + any non-hierarchy scope → no member.
		return nil, false
	}
	return scopeSelfTuplesWithTypeVerbs(cat, subject, scopeType, scopeID, verbs, typeVerbsOf(cat, scopeType))
}

// scopeSelfTuplesWithTypeVerbs — та же сборка при ЯВНО переданном наборе типа
// (см. ruleObjectTuplesWithTypeVerbs про то, зачем набор параметром).
func scopeSelfTuplesWithTypeVerbs(cat *catalog.Facts, subject, scopeType, scopeID string,
	verbs, typeVerbs []string) ([]domain.MembershipTuple, bool) {
	_, tier := domain.ResolveVerbsAndTier(verbs, typeVerbs)
	object := scopeType + ":" + scopeID
	emitVerbs := len(typeVerbsDeclared(cat, scopeType)) > 0

	seen := map[domain.MembershipTuple]struct{}{}
	var out []domain.MembershipTuple
	add := func(relation string) {
		t := domain.MembershipTuple{User: subject, Relation: relation, Object: object}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if emitVerbs {
		for _, v := range verbs {
			if !domain.IsVerbOfType(v, typeVerbs) {
				continue
			}
			add("v_" + domain.NormalizeVerb(v))
		}
	}
	// Back-compat tier tuple — the write-authz / no-access-loss anchor (account/project).
	add(tier)
	return out, true
}

// ИМЯ ТИПА МОДЕЛИ СПРАШИВАЕТСЯ У ЖИВЫХ СТРОК (kacho#1967, kacho#1816)
//
// Здесь стоял собственный переходник реконсайлера — тонкая оболочка над
// `authzmap.FGAObjectType`, то есть над словарём, ПОРОЖДЁННЫМ СБОРКОЙ
// (`authzmap/tables_gen.go` из манифестов, #1092). Тип, которого сборка не
// знала, получал `ok=false`, и вызывающий пропускал его МОЛЧА: строки каталога
// записаны, членство модуля отвечает «да», роль создаётся без отказа — и ни одного
// кортежа не материализуется. Теперь имя читается из строки каталога
// (`catalog.Facts.FGAObjectType`), куда его положил манифест модуля, и тип, заведённый
// применением в РАБОТАЮЩЕМ процессе, раскрывается без пересборки.
//
// Переходников от этого НЕ СТАЛО ДВА: соответствие нигде не вычисляется, у
// него сменилось место хранения. Согласие строки с таблицей сборки — у стража
// старта (`seed.AssertCatalogParity`), и сверка идёт на КАЖДОМ старте с
// отказом в пуске при расхождении. Собственной оболочки пакет больше не держит:
// однострочный переадресатор к `catalog.Facts` не добавлял ничего, кроме второго
// имени у одного вопроса.

// typeVerbsDeclared — набор, ОБЪЯВЛЕННЫЙ типом, без запасного варианта. Именно он
// решает, эмитить ли `v_*` вообще: тип, ничего не объявивший, не получает ни
// одного отношения (fail-closed), даже когда подстановка правила развёрнута общим
// словарём ради вывода яруса.
func typeVerbsDeclared(cat *catalog.Facts, fgaType string) []string {
	return cat.VerbsOfType(fgaType)
}
