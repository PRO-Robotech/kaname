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
// CaptureStagedBindingCoordinate сохраняет прежний выбор desired для полного
// binding, включая creator/containment исключение. Результат ещё не proof:
// owner verifier обязан проверить canonical sources до резерва sequence keys.
func (r *Reconciler) CaptureStagedBindingCoordinate(ctx context.Context, s ReconcileStore, bs BindingScope, coord MemberCoord, obj domain.MirrorObject, present bool, ancestors []domain.MirrorObject) (CapturedObjectDiff, error) {
	var empty CapturedObjectDiff
	if err := ctx.Err(); err != nil {
		return empty, err
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
		var err error
		desired, err = desiredMembersForObject(r.cat.Facts(), selected, obj, ancestors)
		if err != nil {
			return empty, err
		}
	}

	current, err := s.CurrentMembersForObject(ctx, bs.BindingID, coord.ObjectType, coord.ObjectID)
	if err != nil {
		return empty, err
	}
	tuples, err := s.LedgerTuplesForMember(ctx, bs.BindingID, coord)
	if err != nil {
		return empty, err
	}
	ledger := make([]LedgerRow, 0, len(tuples))
	for _, tuple := range tuples {
		ledger = append(ledger, LedgerRow{Member: coord, Tuple: tuple})
	}
	return CapturedObjectDiff{Binding: bs, Desired: desired, Current: current, Ledger: ledger,
		Live: map[MemberCoord]bool{coord: present}}, nil
}

func (r *Reconciler) StageBindingCoordinate(ctx context.Context, s ReconcileStore, bs BindingScope, coord MemberCoord, obj domain.MirrorObject, present bool, ancestors []domain.MirrorObject, converge bool, emit func(BindingCommand) error, size SizeRecorder) error {
	if emit == nil {
		return errors.New("binding stage sink is absent")
	}
	input, err := r.CaptureStagedBindingCoordinate(ctx, s, bs, coord, obj, present, ancestors)
	if err != nil {
		return err
	}
	if size != nil {
		objects, tuples := 0, 0
		if len(input.Desired) > 0 {
			objects = 1
		}
		for _, member := range input.Desired {
			tuples += len(member.Tuples)
		}
		size.ObserveBindingMaterialization(objects, tuples)
	}
	commands, err := CompileCapturedBindingCoordinate(ctx, input, coord, converge)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err = emit(command); err != nil {
			return err
		}
	}
	return nil
}

// Один collector на coordinate и objectEmitted(converge) — исходная семантика
// StageBindingCoordinate. Whole-binding collector здесь намеренно не заменяет
// повторные эффекты одинаковых tuples от разных coordinates.
func CompileCapturedBindingCoordinate(ctx context.Context, input CapturedObjectDiff, coord MemberCoord, converge bool) ([]BindingCommand, error) {
	if input.Additive || input.Binding.BindingID == "" || coord.ObjectType == "" || coord.ObjectID == "" || len(input.Live) != 1 {
		return nil, ErrIncompleteObjectDiff
	}
	if _, ok := input.Live[coord]; !ok {
		return nil, ErrIncompleteObjectDiff
	}
	for _, member := range input.Current {
		if member.ObjectType != coord.ObjectType || member.ObjectID != coord.ObjectID {
			return nil, ErrIncompleteObjectDiff
		}
	}
	for _, member := range input.Desired {
		if member.ObjectType != coord.ObjectType || member.ObjectID != coord.ObjectID {
			return nil, ErrIncompleteObjectDiff
		}
	}
	for _, row := range input.Ledger {
		if row.Member != coord {
			return nil, ErrIncompleteObjectDiff
		}
	}
	var commands []BindingCommand
	emit := func(command BindingCommand) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch command.Kind {
		case "members":
			if command.Members == nil {
				command.Members = []domain.TargetMember{}
			}
		case "record":
			if command.Refs == nil {
				command.Refs = []EmittedTupleRef{}
			}
		case "forget":
			if command.Rows == nil {
				command.Rows = []LedgerRow{}
			}
		case "write", "delete":
			if command.Tuples == nil {
				command.Tuples = []domain.MembershipTuple{}
			}
		}
		commands = append(commands, command)
		return nil
	}
	store, err := newCapturedDiffStore(input, emit)
	if err != nil {
		return nil, err
	}
	view := objectEmitted(store, input.Binding.BindingID, coord.ObjectType, coord.ObjectID)
	view.converge = converge
	collector := &syncFGACollector{}
	reconciler := &Reconciler{}
	if err = reconciler.applyDiff(ctx, store, input.Binding, input.Desired, input.Current, view, collector); err != nil {
		return nil, err
	}
	if err = reconciler.flushDeletes(ctx, store, collector); err != nil {
		return nil, err
	}
	return commands, nil
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
