// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"reflect"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// StagedBindingReconciler отделяет snapshot discovery от atomic apply.
// kaname#1034: completion не объявляется до commit всего diff.
type StagedBindingReconciler interface {
	ReconcileStagedBinding(context.Context, domain.AccessBindingID, bool, SizeRecorder) error
}

func (r *Reconciler) WithStagedBindingReconciler(staged StagedBindingReconciler) error {
	if r == nil || staged == nil {
		return errors.New("binding stage is absent")
	}
	v := reflect.ValueOf(staged)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return errors.New("binding stage is absent")
	}
	if r.stagedBindings != nil {
		return errors.New("binding stage is already installed")
	}
	r.stagedBindings = staged
	return nil
}

// BindingCommand — закрытый diff, полученный тем же applyDiff. Это не разрешение
// mutation: adapter применяет его лишь после полного защищённого epoch recheck.
// Delete tuple отложен до конца: другие координаты успевают сохранить claims.
type BindingCommand struct {
	Kind    string
	Binding domain.AccessBindingID
	Members []domain.TargetMember
	Refs    []EmittedTupleRef
	Rows    []LedgerRow
	Tuples  []domain.MembershipTuple
	Member  MemberCoord
	RuleFP  string
	Scope   domain.ScopeAnchor
}

func (c BindingCommand) Apply(ctx context.Context, s ReconcileStore) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch c.Kind {
	case "members":
		return s.UpsertMembers(ctx, c.Members)
	case "record":
		return s.RecordEmittedTuplesBatch(ctx, c.Refs)
	case "forget":
		return s.ForgetEmittedTuples(ctx, c.Binding, c.Rows)
	case "write":
		return s.EmitTupleWrite(ctx, c.Tuples)
	case "delete":
		return s.EmitTupleDelete(ctx, c.Tuples)
	case "member_delete":
		return s.DeleteMember(ctx, c.Binding, c.RuleFP, c.Member.ObjectType, c.Member.ObjectID)
	case "audit":
		return s.EmitContainmentAudit(ctx, c.Binding, c.Member.ObjectType, c.Member.ObjectID, c.Scope)
	default:
		return errors.New("unknown staged binding command")
	}
}

// StageBindingCoordinate читает лишь одну полную координату. Все rule_fp одной
// координаты остаются вместе: они могут делить ledger tuple. Исходный diff и
// creator/nested/public-reader semantics используются без второго compiler.
func (r *Reconciler) StageBindingCoordinate(ctx context.Context, s ReconcileStore, bs BindingScope, coord MemberCoord, obj domain.MirrorObject, present bool, ancestors []domain.MirrorObject, converge bool, emit func(BindingCommand) error, size SizeRecorder) error {
	if emit == nil {
		return errors.New("binding stage sink is absent")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var desired []DesiredMember
	if present && len(bs.Selectors) > 0 {
		// Creator-specific discovery предварительно сужен областью. Anchor
		// допускает надмножество: общий diff сохраняет REJECTED и containment audit.
		selected := bs
		selected.Selectors = nil
		for _, sel := range bs.Selectors {
			if sel.Container == nil && !obj.IsContainedIn(bs.Scope) && (sel.CreatedBySubject) {
				continue
			}
			selected.Selectors = append(selected.Selectors, sel)
		}
		desired = desiredMembersForObject(r.cat.Facts(), selected, obj, ancestors)
	}
	if size != nil {
		objects, tuples := 0, 0
		if len(desired) > 0 {
			objects = 1
		}
		for _, member := range desired {
			tuples += len(member.Tuples)
		}
		size.ObserveBindingMaterialization(objects, tuples)
	}
	current, err := s.CurrentMembersForObject(ctx, bs.BindingID, coord.ObjectType, coord.ObjectID)
	if err != nil {
		return err
	}
	recorder := &bindingRecorder{ReconcileStore: s, emit: emit}
	view := objectEmitted(s, bs.BindingID, coord.ObjectType, coord.ObjectID)
	view.converge = converge
	col := &syncFGACollector{}
	if err = r.applyDiff(ctx, recorder, bs, desired, current, view, col); err != nil {
		return err
	}
	return r.flushDeletes(ctx, recorder, col)
}

type bindingRecorder struct {
	ReconcileStore
	emit func(BindingCommand) error
}

func (s *bindingRecorder) UpsertMember(_ context.Context, m domain.TargetMember) error {
	return s.emit(BindingCommand{Kind: "members", Members: []domain.TargetMember{m}})
}
func (s *bindingRecorder) UpsertMembers(_ context.Context, m []domain.TargetMember) error {
	return s.emit(BindingCommand{Kind: "members", Members: m})
}
func (s *bindingRecorder) RecordEmittedTuples(_ context.Context, b domain.AccessBindingID, m MemberCoord, ts []domain.MembershipTuple) error {
	refs := make([]EmittedTupleRef, len(ts))
	for i, t := range ts {
		refs[i] = EmittedTupleRef{BindingID: b, Member: m, Tuple: t}
	}
	return s.emit(BindingCommand{Kind: "record", Refs: refs})
}
func (s *bindingRecorder) RecordEmittedTuplesBatch(_ context.Context, refs []EmittedTupleRef) error {
	return s.emit(BindingCommand{Kind: "record", Refs: refs})
}
func (s *bindingRecorder) ForgetEmittedTuples(_ context.Context, b domain.AccessBindingID, rows []LedgerRow) error {
	return s.emit(BindingCommand{Kind: "forget", Binding: b, Rows: rows})
}
func (s *bindingRecorder) EmitTupleWrite(_ context.Context, ts []domain.MembershipTuple) error {
	return s.emit(BindingCommand{Kind: "write", Tuples: ts})
}
func (s *bindingRecorder) EmitTupleDelete(_ context.Context, ts []domain.MembershipTuple) error {
	return s.emit(BindingCommand{Kind: "delete", Tuples: ts})
}
func (s *bindingRecorder) DeleteMember(_ context.Context, b domain.AccessBindingID, fp, t, id string) error {
	return s.emit(BindingCommand{Kind: "member_delete", Binding: b, RuleFP: fp, Member: MemberCoord{ObjectType: t, ObjectID: id}})
}
func (s *bindingRecorder) EmitContainmentAudit(_ context.Context, b domain.AccessBindingID, t, id string, scope domain.ScopeAnchor) error {
	return s.emit(BindingCommand{Kind: "audit", Binding: b, Member: MemberCoord{ObjectType: t, ObjectID: id}, Scope: scope})
}
