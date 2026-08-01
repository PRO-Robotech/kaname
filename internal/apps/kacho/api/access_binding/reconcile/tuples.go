// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// tuples.go — per-object FGA tuple builder for materialized role.rules ARM_LABELS
// membership (RBAC rules-model 2026). For ONE label-matched object the
// per-object v_<verb> + back-compat tier tuples are derived from the producing
// RULE's verbs (domain.ResolveVerbsAndTier), so the reconciler can emit/eager-
// revoke the tuple of a single member on a diff.
//
// This is a use-case-layer concern (it owns the authzmap dependency), keeping the
// domain pure.

import (
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ruleObjectTuples builds the per-object FGA tuple set for ONE label-matched
// object of an ARM_LABELS rule. It REUSES the per-object
// emit semantics (access_binding.emitNamesRule): the tier + closed per-verb v_*
// relations are derived from the RULE'S VERBS (domain.ResolveVerbsAndTier), NOT
// from the role's compiled permissions (ARM_LABELS rules are excluded from
// CompileRules). v_<verb> tuples are emitted ONLY when (a) the FGA type
// carries v_* relations (TypeHasVerbRelations) AND (b) the verb is in the closed
// CRUD set; otherwise access is carried by the back-compat tier tuple. ok=false
// when the (objectType) has no FGA object type (a typo'd type never grants —
// fail-closed). The subject is the binding's subject (already FGA-formatted).
func ruleObjectTuples(subject string, verbs []string, objectType, objectID string) ([]domain.MembershipTuple, bool) {
	fgaType, ok := fgaObjectType(objectType)
	if !ok {
		return nil, false
	}
	return ruleObjectTuplesWithTypeVerbs(subject, verbs, fgaType, objectID, typeVerbsOf(fgaType))
}

// typeVerbsOf — набор глаголов, объявленный ТИПОМ; для неглагольного типа —
// словарь, ОБЩИЙ для всех ресурсов.
//
// Запасной вариант нужен ради яруса, а не ради `v_*`: ярус выводится из
// РАЗВЁРНУТЫХ глаголов правила, поэтому подстановка `*` на типе без собственного
// набора обязана по-прежнему давать полный набор — иначе роль-суперпользователь
// молча понизилась бы с администратора до наблюдателя. Отношения `v_*` при этом не
// эмитятся всё равно: пустой набор не принадлежит никому (domain.IsVerbOfType).
func typeVerbsOf(fgaType string) []string {
	if set := authzmap.VerbsOfType(fgaType); len(set) > 0 {
		return set
	}
	return authzmap.CommonVerbVocabulary()
}

// ruleObjectTuplesWithTypeVerbs — та же сборка при ЯВНО переданном наборе типа.
// Набор — параметр, чтобы отрицательные кейсы могли предъявить тип с УРЕЗАННЫМ
// набором: сегодня такого типа в таблице нет, а свойство обязано охраняться ДО
// появления первого пользователя.
func ruleObjectTuplesWithTypeVerbs(subject string, verbs []string, fgaType, objectID string,
	typeVerbs []string) ([]domain.MembershipTuple, bool) {
	expanded, tier := domain.ResolveVerbsAndTier(verbs, typeVerbs)
	object := fmt.Sprintf("%s:%s", fgaType, objectID)
	emitVerbs := len(typeVerbsDeclared(fgaType)) > 0

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
		hasUpdate := false
		for _, v := range expanded {
			if !domain.IsVerbOfType(v, typeVerbs) {
				continue
			}
			if v == "update" {
				hasUpdate = true
			}
			add("v_" + v)
		}
		// v_update ⟹ v_delete co-materialization (create.go:435 invariant): under the
		// flat verb-bearing model a CRUD editor DELETES what it edits — an object-scoped
		// grant that carries v_update must also carry v_delete, else the resource creator
		// (edit@project → v_get/v_list/v_update but NOT v_delete) 403s "lacks v_delete" on
		// every cleanup of its OWN resource. Migration 0040 gave the edit roles the read
		// verbs but omitted delete; this closes the gap at the single materialization
		// path WITHOUT escalating the back-compat tier (stays editor) or over-granting a
		// stray delete verb into every role. It is fail-closed by construction: only a
		// grant that already updates the object gains delete.
		//
		// EXCLUDED — the hierarchy scopes account/project: deleting a scope object is an
		// owner/admin operation (ProjectService/AccountService.Delete gate v_delete on the
		// scope), NOT an editor one. An edit-tier grant on account/project (scope-self OR
		// as content of an account-owner binding) must NOT gain v_delete on the scope —
		// only a role that explicitly authored `delete` (owner/admin `*.*`) keeps it (the
		// loop above already emitted it, so this is purely additive for leaf types).
		//
		// XC-3 S1Ф2: у литерала теперь ТО ЖЕ условие, что у цикла выше. Он
		// дописывал отношение СТРОКОЙ, не проходя ни через сверку с набором, ни
		// через таблицу, — то есть тип, у которого `v_delete` не объявлен, получал
		// бы его, как только роль назовёт `update`. Пока набор был одинаков у всех
		// типов, это было безвредно; с набором У ТИПА это висячий кортеж.
		if hasUpdate && !isHierarchyScopeType(fgaType) && domain.IsVerbOfType("delete", typeVerbs) {
			add("v_delete")
		}
	}
	// Back-compat tier tuple — carries domain-verb access + keeps tier-based Check
	// call-sites working. Always emitted (parity with B emitNamesRule).
	add(tier)
	return out, true
}

// isHierarchyScopeType reports whether an FGA object_type is one of the tier-carrying
// hierarchy scope ancestors (account / project). These are the two verb-bearing types
// where a `delete` is a scope-destroying owner/admin operation, so the v_update⟹v_delete
// leaf-editor co-materialization is deliberately NOT applied to them (anti over-grant).
func isHierarchyScopeType(fgaType string) bool {
	return fgaType == "account" || fgaType == "project"
}

// scopeSelfRuleFP — the sentinel rule_fp attributing the scope-self member (D-7).
// It is NOT a content rule's fingerprint; using a fixed, NUL-free sentinel gives the
// scope-self member its own access_binding_target_members row + emitted-tuple ledger
// lineage so the symmetric revoke / diff treats it independently of content members.
const scopeSelfRuleFP = "scope_self"

// scopeSelfMember builds the DesiredMember for the binding's scope anchor itself
// (D-7 / КФ-3 / C-01) from the role's scope-self verbs. The member object_type is
// the dotted iam scope key (iam.account / iam.project) so it round-trips through
// fgaObjectType for the symmetric revoke; the FGA tuples target the bare scope
// object (account:<X>/project:<X>). ok=false when the role grants nothing on the
// scope self OR the scope type has no dotted iam mapping (cluster — D-9 short-circuit
// owns cluster super-admin, not this per-object path).
func scopeSelfMember(subject string, scopeType, scopeID string, verbs []string) (DesiredMember, bool) {
	dotted := "iam." + scopeType // iam.account / iam.project (cluster has no mapping)
	if _, ok := fgaObjectType(dotted); !ok {
		return DesiredMember{}, false
	}
	tuples, ok := scopeSelfTuples(subject, scopeType, scopeID, verbs)
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
// The sole caller (scopeSelfMember) already gates cluster out (fgaObjectType
// "iam.cluster" is absent from the objectTypes registry), so this function never
// receives scopeType=="cluster"; the guard below is the explicit fail-closed fence
// (scope_self_cluster_guard_test.go pins the invariant against a future iam.cluster
// type re-enabling the dead path). ok=false when scopeType is not a per-object
// hierarchy scope or there are no verbs (a content-only role grants nothing on the
// anchor).
func scopeSelfTuples(subject, scopeType, scopeID string, verbs []string) ([]domain.MembershipTuple, bool) {
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
	return scopeSelfTuplesWithTypeVerbs(subject, scopeType, scopeID, verbs, typeVerbsOf(scopeType))
}

// scopeSelfTuplesWithTypeVerbs — та же сборка при ЯВНО переданном наборе типа
// (см. ruleObjectTuplesWithTypeVerbs про то, зачем набор параметром).
func scopeSelfTuplesWithTypeVerbs(subject, scopeType, scopeID string,
	verbs, typeVerbs []string) ([]domain.MembershipTuple, bool) {
	_, tier := domain.ResolveVerbsAndTier(verbs, typeVerbs)
	object := scopeType + ":" + scopeID
	emitVerbs := len(typeVerbsDeclared(scopeType)) > 0

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
			add("v_" + v)
		}
	}
	// Back-compat tier tuple — the write-authz / no-access-loss anchor (account/project).
	add(tier)
	return out, true
}

// fgaObjectType resolves the FGA object_type for a dotted closed-table key
// (e.g. "compute.instance" → "compute_instance"). Thin alias over the canonical
// authzmap.FGAObjectType so the reconciler's tuple-object derivation and the
// verify-gate's ledger lookup (review #5) share ONE mapping and cannot drift.
func fgaObjectType(objectType string) (string, bool) {
	return authzmap.FGAObjectType(objectType)
}

// typeVerbsDeclared — набор, ОБЪЯВЛЕННЫЙ типом, без запасного варианта. Именно он
// решает, эмитить ли `v_*` вообще: тип, ничего не объявивший, не получает ни
// одного отношения (fail-closed), даже когда подстановка правила развёрнута общим
// словарём ради вывода яруса.
func typeVerbsDeclared(fgaType string) []string {
	return authzmap.VerbsOfType(fgaType)
}
