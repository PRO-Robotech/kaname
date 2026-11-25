// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Вход чистой компиляции diff. Он не удостоверяет полноту SQL census, guards
// или разрешение записи. Runner обязан захватить и затем защитить все строки.
// Ledger содержит полные координаты текущего прохода, включая пустые наборы;
// Live содержит явное наблюдение каждой mirror-координаты, которую он пишет.
type CapturedObjectDiff struct {
	Binding  BindingScope
	Desired  []DesiredMember
	Current  []domain.TargetMember
	Ledger   []LedgerRow
	Live     map[MemberCoord]bool
	Additive bool
	// Converge требует сверить сохранённый журнал и для неизменившегося
	// ACTIVE-члена с одним субъектом.
	Converge bool
}

var ErrIncompleteObjectDiff = errors.New("incomplete captured object diff")

// CompileCapturedObjectDiff применяет существующий applyDiff только к памяти.
// Один collector сохраняет вычитание удалений после всех выдач, как live fanout.
// Внешний код получает команды, а не callback или доступный DB writer.
func CompileCapturedObjectDiff(ctx context.Context, inputs []CapturedObjectDiff) ([]BindingCommand, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var commands []BindingCommand
	emit := func(c BindingCommand) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.Members = slices.Clone(c.Members)
		c.Refs = slices.Clone(c.Refs)
		c.Rows = slices.Clone(c.Rows)
		c.Tuples = slices.Clone(c.Tuples)
		// Закрытый payload команды всегда сериализуется массивом. Пустой
		// additive flush остаётся теми же тремя командами, а не JSON null:
		// SQL проверяет их форму и полноту независимо от числа элементов.
		switch c.Kind {
		case "members":
			if c.Members == nil {
				c.Members = []domain.TargetMember{}
			}
		case "record":
			if c.Refs == nil {
				c.Refs = []EmittedTupleRef{}
			}
		case "forget":
			if c.Rows == nil {
				c.Rows = []LedgerRow{}
			}
		case "write", "delete":
			if c.Tuples == nil {
				c.Tuples = []domain.MembershipTuple{}
			}
		}
		commands = append(commands, c)
		return nil
	}
	reconciler := &Reconciler{}
	collector := &syncFGACollector{}
	seen := make(map[domain.AccessBindingID]bool, len(inputs))
	var tail ReconcileStore
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if input.Binding.BindingID == "" || seen[input.Binding.BindingID] {
			return nil, ErrIncompleteObjectDiff
		}
		seen[input.Binding.BindingID] = true
		if !input.Binding.Active {
			continue
		}
		store, err := newCapturedDiffStore(input, emit)
		if err != nil {
			return nil, err
		}
		tail = store
		if input.Additive {
			var writes forwardWriteSet
			for _, desired := range input.Desired {
				if desired.Status != domain.VerificationActive {
					continue
				}
				if mirrorFed(desired.ObjectType) {
					live, known := input.Live[desiredCoord(desired)]
					if !known {
						return nil, ErrIncompleteObjectDiff
					}
					if !live {
						continue
					}
				}
				if err = reconciler.materializeForwardMember(ctx, store, input.Binding, desired, collector, &writes); err != nil {
					return nil, err
				}
			}
			if err = writes.writeLive(ctx, store); err != nil {
				return nil, err
			}
		} else {
			view := bindingEmitted(store, input.Binding.BindingID, input.Converge)
			if err = reconciler.applyDiff(ctx, store, input.Binding, input.Desired, input.Current, view, collector); err != nil {
				return nil, err
			}
		}
	}
	if tail != nil {
		if err := reconciler.flushDeletes(ctx, tail, collector); err != nil {
			return nil, err
		}
	}
	return commands, nil
}

type capturedDiffStore struct {
	*bindingRecorder
	binding domain.AccessBindingID
	ledger  []LedgerRow
	live    map[MemberCoord]bool
}

func newCapturedDiffStore(input CapturedObjectDiff, emit func(BindingCommand) error) (*capturedDiffStore, error) {
	s := &capturedDiffStore{binding: input.Binding.BindingID, ledger: slices.Clone(input.Ledger), live: input.Live}
	s.bindingRecorder = &bindingRecorder{emit: emit}
	// Все вызываемые applyDiff read/lock порты ниже замкнуты на captured данные.
	// Recorder перехватывает каждую запись; DB store здесь отсутствует.
	seen := map[string]bool{}
	for _, m := range input.Current {
		key := memberRuleKey(m.RuleFP, m.ObjectType, m.ObjectID)
		if m.BindingID != s.binding || m.RuleFP == "" || m.ObjectType == "" || m.ObjectID == "" || seen[key] {
			return nil, ErrIncompleteObjectDiff
		}
		seen[key] = true
	}
	for _, m := range input.Desired {
		if m.RuleFP == "" || m.ObjectType == "" || m.ObjectID == "" {
			return nil, ErrIncompleteObjectDiff
		}
	}
	return s, nil
}
func (s *capturedDiffStore) LockMirrorObjects(ctx context.Context, coords []MemberCoord) (map[MemberCoord]struct{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make(map[MemberCoord]struct{})
	for _, coord := range coords {
		live, known := s.live[coord]
		if !known {
			return nil, ErrIncompleteObjectDiff
		}
		if live {
			out[coord] = struct{}{}
		}
	}
	return out, nil
}
func (s *capturedDiffStore) LedgerTuples(ctx context.Context, id domain.AccessBindingID) ([]LedgerRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id != s.binding {
		return nil, ErrIncompleteObjectDiff
	}
	return slices.Clone(s.ledger), nil
}
func (s *capturedDiffStore) LedgerTuplesForMember(ctx context.Context, id domain.AccessBindingID, coord MemberCoord) ([]domain.MembershipTuple, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id != s.binding {
		return nil, ErrIncompleteObjectDiff
	}
	var out []domain.MembershipTuple
	for _, row := range s.ledger {
		if row.Member == coord {
			out = append(out, row.Tuple)
		}
	}
	return out, nil
}
func (s *capturedDiffStore) ForgetEmittedTuples(ctx context.Context, id domain.AccessBindingID, rows []LedgerRow) error {
	if id != s.binding {
		return ErrIncompleteObjectDiff
	}
	if err := s.bindingRecorder.ForgetEmittedTuples(ctx, id, rows); err != nil {
		return err
	}
	remove := make(map[LedgerRow]bool, len(rows))
	for _, row := range rows {
		remove[row] = true
	}
	next := s.ledger[:0:0]
	for _, row := range s.ledger {
		if !remove[row] {
			next = append(next, row)
		}
	}
	s.ledger = next
	return nil
}
func (s *capturedDiffStore) RecordEmittedTuples(ctx context.Context, id domain.AccessBindingID, coord MemberCoord, tuples []domain.MembershipTuple) error {
	if id != s.binding {
		return ErrIncompleteObjectDiff
	}
	if err := s.bindingRecorder.RecordEmittedTuples(ctx, id, coord, tuples); err != nil {
		return err
	}
	for _, tuple := range tuples {
		row := LedgerRow{Member: coord, Tuple: tuple}
		if !slices.Contains(s.ledger, row) {
			s.ledger = append(s.ledger, row)
		}
	}
	return nil
}
