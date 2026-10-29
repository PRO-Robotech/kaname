// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_tuple_reconciler.go — role-permission tuple reconciler.
//
// RoleTupleReconciler реализует role.TupleReconciler — веер по разрешениям роли.
// Когда разрешения или правила роли меняются (Role.Update), он сверяет кортежи
// действующих выдач роли с новым ярусом через buildSubjectsBindingTuples —
// проекцию тонкой выдачи на якорь области, построенную на КАЖДОГО субъекта
// выдачи. Целей у выдачи нет (модель правил их сняла), поэтому эта проекция и
// есть весь сдвиг яруса внутри транзакции.
//
// The role.rules ARM_LABELS per-object MEMBERSHIP retiering is the complementary
// half handled by RoleMembershipFanout (rules_membership_fanout.go): a rule's verb
// change bumps its rule_fp, so the γ reconciler eager-revokes the old-fp members
// and re-materializes the new ones at the new tier. RoleTupleReconciler owns the
// binding-level (anchor/scope_grant) tuples; RoleMembershipFanout owns the
// per-member tuples.
//
// It lives in the access_binding package because that package owns the FGA
// tuple-builder (tuples.go) AND the persisted emitted-tuple ledger — so the role
// use-case stays free of FGA-tuple knowledge (clean-arch: role defines the port,
// access_binding implements it, the composition root wires it).

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// RoleTupleReconciler — the Role.Update reconcile fan-out.
type RoleTupleReconciler struct{}

// NewRoleTupleReconciler constructs the reconciler (stateless — all state lives
// in the writer-tx passed to ReconcileRoleTuples).
func NewRoleTupleReconciler() *RoleTupleReconciler { return &RoleTupleReconciler{} }

// ReconcileRoleTuples reconciles every ACTIVE binding of roleID from its stored
// emitted-set (old) to the tuples derived from newRole (new), inside the
// caller's writer-tx (the same tx as the role UPDATE — atomic, ban #10).
//
// Per binding:
//  1. newTuples = buildSubjectsBindingTuples(binding, subjects, newRole) —
//     проекция на якорь области для КАЖДОГО субъекта выдачи, тем же
//     построителем, что у создания (kaname#880),
//  2. read oldTuples = SelectEmittedTuples(binding),
//  3. diff: removed = old\new, added = new\old,
//  4. ReplaceEmittedTuples(binding, newTuples) — реестр ДО строк журнала
//     (kaname#919: иначе выдача держит снимаемый факт сама);
//  5. после веера — снятия и выдачи ВСЕХ выдач одним оператором журнала
//     (EmitRelationJournal, kaname#617).
//
// Bounded: the fan-out iterates only the ACTIVE bindings of the SINGLE mutated
// role (ListActiveByRole), not all bindings. Idempotent: an unchanged tier
// yields removed=added=∅ (no fga_outbox rows, the ledger replace is a no-op
// swap) — so a re-run / replayed Operation does not double-emit.
func (r *RoleTupleReconciler) ReconcileRoleTuples(ctx context.Context, w kanamerepo.Writer, roleID domain.RoleID, newRole domain.Role) error {
	bindings, err := w.AccessBindings().ListActiveByRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("list active bindings of role %s: %w", roleID, err)
	}
	// Субъекты — ОДНИМ обращением на весь веер: строка выдачи несёт лишь
	// проекцию первого субъекта, а создание выпустило кортежи каждому
	// (kaname#880). Выдача без строк перечня — заведённая до него; её субъект —
	// одиночная пара строки.
	ids := make([]domain.AccessBindingID, len(bindings))
	for i := range bindings {
		ids[i] = bindings[i].ID
	}
	subjects, err := w.AccessBindings().ListSubjectsForBindings(ctx, ids)
	if err != nil {
		return fmt.Errorf("list subjects of role %s bindings: %w", roleID, err)
	}
	var writes, deletes []abrepo.RelationTuple
	for i := range bindings {
		b := bindings[i]
		bs := subjects[b.ID]
		if len(bs) == 0 {
			bs = []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}
		}
		// Выдача тонкая (целей у выдачи нет): кортежи уровня выдачи — вся её
		// проекция, и строятся они на каждого субъекта тем же построителем, что у
		// создания. Перевод членов правил на новый ярус — вторая половина,
		// RoleMembershipFanout (смена глаголов правила меняет его отпечаток).
		newTuples := buildSubjectsBindingTuples(b, bs, newRole)
		// Read ONLY the binding-level subset (source='binding'). The ARM_LABELS
		// per-member tuples (source='member') are owned by RoleMembershipFanout — if
		// the diff saw them it would classify every member tuple as `removed` and
		// EmitRelationDelete would revoke live label-selected access (CRITICAL fix).
		oldTuples, serr := w.AccessBindings().SelectEmittedTuplesBySource(ctx, b.ID, "binding")
		if serr != nil {
			return fmt.Errorf("read emitted-set of binding %s: %w", b.ID, serr)
		}

		removed, added := diffTuples(oldTuples, newTuples)
		if len(removed) == 0 && len(added) == 0 {
			continue
		}
		// Реестр — ДО строк журнала. Строку снятия свёртка применяет, лишь когда
		// факт не держит ни одна действующая выдача (kaname#919); выдача ACTIVE, и
		// со старым реестром она держала бы снимаемый факт сама. Новый реестр уже
		// без снятых кортежей, а общий кортеж, который держит ДРУГАЯ выдача,
		// свёртка оставит — вычитать его здесь не нужно.
		if err := w.AccessBindingsW().ReplaceEmittedTuples(ctx, b.ID, newTuples); err != nil {
			return fmt.Errorf("replace emitted-set of binding %s: %w", b.ID, err)
		}
		writes = append(writes, added...)
		deletes = append(deletes, removed...)
	}
	// ЖУРНАЛ — ОДНИМ ОПЕРАТОРОМ НА ВЕСЬ ВЕЕР (kaname#617). Строки снятия и выдачи
	// по выдаче, оператором на каждую, брали замки строк факта порядком выдач веера:
	// две встречные смены ролей, чьи выдачи стоят на одних объектах одного субъекта
	// в разном порядке, сходились в кольцо (40P01, проба
	// `TestRoleUpdatesOfOneSubjectCommitWhenTheirFanoutsMeetCrosswise`). Один оператор
	// берёт их в общем порядке (объект, субъект, отношение).
	//
	// Реестры всех выдач заменены ДО оператора, поэтому свёртка каждой строки
	// снятия видит конечный реестр веера: кортеж, который одна выдача снимает, а
	// другая выдача того же веера выпускает, — не снятие (его держит её новый
	// реестр), и в журнал он идёт лишь выдачей; иначе вызов отверг бы кортеж,
	// названный дважды.
	deletes = withoutTuples(deletes, writes)
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	if err := w.AccessBindingsW().EmitRelationJournal(ctx, writes, deletes); err != nil {
		return fmt.Errorf("emit relation journal for role %s: %w", roleID, err)
	}
	return nil
}

// withoutTuples — кортежи from, которых нет в drop, в прежнем порядке.
func withoutTuples(from, drop []abrepo.RelationTuple) []abrepo.RelationTuple {
	if len(from) == 0 || len(drop) == 0 {
		return from
	}
	dropped := make(map[abrepo.RelationTuple]struct{}, len(drop))
	for _, t := range drop {
		dropped[t] = struct{}{}
	}
	out := from[:0:0]
	for _, t := range from {
		if _, ok := dropped[t]; !ok {
			out = append(out, t)
		}
	}
	return out
}

// diffTuples computes (removed = old\new, added = new\old) on set semantics over
// the (User, Relation, Object) natural key. Used by the reconcile fan-out to emit
// the minimal FGA delta and keep the drainer churn-free (idempotent).
func diffTuples(oldT, newT []abrepo.RelationTuple) (removed, added []abrepo.RelationTuple) {
	oldSet := make(map[abrepo.RelationTuple]struct{}, len(oldT))
	for _, t := range oldT {
		oldSet[t] = struct{}{}
	}
	newSet := make(map[abrepo.RelationTuple]struct{}, len(newT))
	for _, t := range newT {
		newSet[t] = struct{}{}
	}
	for _, t := range oldT {
		if _, ok := newSet[t]; !ok {
			removed = append(removed, t)
		}
	}
	for _, t := range newT {
		if _, ok := oldSet[t]; !ok {
			added = append(added, t)
		}
	}
	return removed, added
}
