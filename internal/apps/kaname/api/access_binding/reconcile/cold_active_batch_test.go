// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

type coldBatchStore struct {
	*fakeStore
	batches               [][]domain.TargetMember
	refs                  [][]EmittedTupleRef
	singles               int
	writeCalls            int
	failStage             string
	failure               error
	locksBeforeFirstWrite []MemberCoord
	mirrorCalls           int
}

func (s *coldBatchStore) LockMirrorObjects(ctx context.Context, coords []MemberCoord) (map[MemberCoord]struct{}, error) {
	s.mirrorCalls++
	return s.fakeStore.LockMirrorObjects(ctx, coords)
}

func (s *coldBatchStore) UpsertMember(ctx context.Context, m domain.TargetMember) error {
	s.singles++
	return s.fakeStore.UpsertMember(ctx, m)
}
func (s *coldBatchStore) UpsertMembers(ctx context.Context, ms []domain.TargetMember) error {
	if len(s.batches) == 0 {
		s.locksBeforeFirstWrite = append([]MemberCoord(nil), s.mirrorLocks...)
	}
	s.batches = append(s.batches, append([]domain.TargetMember(nil), ms...))
	if s.failStage == "members" && len(s.batches) == 2 {
		return s.failure
	}
	return s.fakeStore.UpsertMembers(ctx, ms)
}
func (s *coldBatchStore) EmitTupleWrite(ctx context.Context, ts []domain.MembershipTuple) error {
	s.writeCalls++
	if s.failStage == "queue" && s.writeCalls == 2 {
		return s.failure
	}
	return s.fakeStore.EmitTupleWrite(ctx, ts)
}
func (s *coldBatchStore) RecordEmittedTuplesBatch(ctx context.Context, refs []EmittedTupleRef) error {
	s.refs = append(s.refs, append([]EmittedTupleRef(nil), refs...))
	if s.failStage == "ledger" && len(s.refs) == 2 {
		return s.failure
	}
	return s.fakeStore.RecordEmittedTuplesBatch(ctx, refs)
}

func coldDesired(n int) ([]DesiredMember, *coldBatchStore) {
	desired := make([]DesiredMember, 0, n)
	f := &fakeStore{mirror: map[string][]domain.MirrorObject{}}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("i-%05d", i)
		f.mirror["compute.instance"] = append(f.mirror["compute.instance"], domain.MirrorObject{ObjectType: "compute.instance", ObjectID: id})
		desired = append(desired, DesiredMember{RuleFP: "rule", ObjectType: "compute.instance", ObjectID: id, Status: domain.VerificationActive, Tuples: []domain.MembershipTuple{{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:" + id}}})
	}
	return desired, &coldBatchStore{fakeStore: f}
}

func coldScope() BindingScope {
	return BindingScope{BindingID: "acb-1", RoleID: "role-1", Scope: domain.ScopeAnchor{Type: "project", ID: "prj-1"}}
}

func TestApplyDiff_ColdActiveMatchesOriginalDiffAcrossChunks(t *testing.T) {
	ctx := context.Background()
	desired, fast := coldDesired(4097)
	_, original := coldDesired(4097)
	update := desired[0]
	update.Tuples = append(append([]domain.MembershipTuple(nil), update.Tuples...), domain.MembershipTuple{User: "user:usr-1", Relation: "v_update", Object: "compute_instance:i-00000"})
	otherRule := desired[0]
	otherRule.RuleFP = "other-rule"
	desired = append(desired, update, otherRule, desired[0])
	bs := coldScope()
	r := New(fakeRunner{s: fast}, nil, catalogfixture.Source())
	require.NoError(t, r.applyDiff(ctx, fast, bs, desired, nil, nil, &syncFGACollector{}))
	// Несвязанный PENDING-член принуждает исходный full diff без добавления revoke.
	old := []domain.TargetMember{{BindingID: bs.BindingID, RuleFP: "sentinel", ObjectType: "compute.instance", ObjectID: "absent", VerificationStatus: domain.VerificationPending}}
	require.NoError(t, r.applyDiff(ctx, original, bs, desired, old, nil, &syncFGACollector{}))
	require.Equal(t, original.upserts, fast.upserts)
	require.Equal(t, allWrites(original.fakeStore), allWrites(fast.fakeStore), "порядок первых tuple writes не зависит от границы партии")
	require.ElementsMatch(t, original.ledgerNow(), fast.ledgerNow())
	require.Len(t, fast.ledgerNow(), 4098, "одна координата двух правил делит строку, новый глагол остаётся")
	require.Equal(t, []string{memberKey("compute.instance", "absent")}, original.deletes)
	require.Empty(t, fast.deletes)
	require.Empty(t, fast.audits)
	require.Zero(t, fast.singles)
	require.Len(t, fast.batches, 2)
	require.Len(t, fast.batches[0], 4096)
	require.Len(t, fast.batches[1], 4)
	require.Empty(t, original.batches)
	expectedLocks := make([]MemberCoord, 0, 4097)
	for i := 0; i < 4097; i++ {
		expectedLocks = append(expectedLocks, MemberCoord{ObjectType: "compute.instance", ObjectID: fmt.Sprintf("i-%05d", i)})
	}
	require.Equal(t, 1, fast.mirrorCalls, "исходный полный mirror census единожды до записи")
	require.ElementsMatch(t, expectedLocks, fast.mirrorLocks, "multiset сохраняет также число повторений каждой координаты")
	require.ElementsMatch(t, expectedLocks, fast.locksBeforeFirstWrite)
	require.Empty(t, fast.mirrorLocksAfterFirstWrite, "member-triggered batches не запрашивают mirror после записи")
	for _, batch := range fast.batches {
		for _, member := range batch {
			require.Equal(t, bs.BindingID, member.BindingID)
			require.Equal(t, domain.RoleID(bs.RoleID), member.RoleID)
		}
	}
	for _, batch := range fast.refs {
		for _, ref := range batch {
			require.Equal(t, bs.BindingID, ref.BindingID)
			require.Equal(t, "compute.instance", ref.Member.ObjectType)
			require.Equal(t, "compute_instance:"+ref.Member.ObjectID, ref.Tuple.Object)
		}
	}
}

func TestApplyDiff_ColdActiveKeepsGlobalCollectorAndBindingLedger(t *testing.T) {
	desired, store := coldDesired(1)
	r := New(fakeRunner{s: store}, nil, catalogfixture.Source())
	collector := &syncFGACollector{}
	for _, id := range []domain.AccessBindingID{"acb-first", "acb-second"} {
		bs := coldScope()
		bs.BindingID = id
		require.NoError(t, r.applyDiff(context.Background(), store, bs, desired, nil, nil, collector))
	}
	require.Len(t, allWrites(store.fakeStore), 1, "один общий collector на обе выдачи")
	require.Len(t, store.refs, 2)
	require.Equal(t, domain.AccessBindingID("acb-first"), store.refs[0][0].BindingID)
	require.Equal(t, domain.AccessBindingID("acb-second"), store.refs[1][0].BindingID)
}

func TestApplyDiff_ColdActiveFiltersBeforeTupleValidation(t *testing.T) {
	desired, store := coldDesired(2)
	store.vanished = map[MemberCoord]bool{desiredCoord(desired[1]): true}
	desired[1].Tuples = nil
	r := New(fakeRunner{s: store}, nil, catalogfixture.Source())
	require.NoError(t, r.applyDiff(context.Background(), store, coldScope(), desired, nil, nil, &syncFGACollector{}))
	require.Len(t, store.upserts, 1)
	require.Equal(t, desired[0].ObjectID, store.upserts[0].ObjectID)
	require.Len(t, store.refs[0], 1)
}

func TestApplyDiff_ColdActiveErrorsStopWithoutSuccess(t *testing.T) {
	for _, stage := range []string{"members", "queue", "ledger", "tuple"} {
		t.Run(stage, func(t *testing.T) {
			desired, store := coldDesired(8193)
			store.failStage = stage
			store.failure = errors.New("second batch failure")
			if stage == "tuple" {
				desired[4096].Tuples = nil
			}
			r := New(fakeRunner{s: store}, nil, catalogfixture.Source())
			err := r.applyDiff(context.Background(), store, coldScope(), desired, nil, nil, &syncFGACollector{})
			if stage == "tuple" {
				require.ErrorContains(t, err, "membership tuple inconsistent")
				require.Len(t, store.batches, 1)
			} else {
				require.ErrorIs(t, err, store.failure)
				require.Len(t, store.batches, 2)
			}
			require.Zero(t, store.singles)
			require.LessOrEqual(t, len(store.refs), 2, "после ошибки третья партия недопустима")
		})
	}
}

func TestApplyDiff_ColdActiveFallbackTransitionsCompletionAndRevoke(t *testing.T) {
	for _, scenario := range []string{"empty", "pending", "rejected", "mixed", "pending-active", "active-pending", "active-rejected", "completion", "revoke"} {
		t.Run(scenario, func(t *testing.T) {
			desired, store := coldDesired(1)
			bs := coldScope()
			var current []domain.TargetMember
			if scenario == "empty" {
				desired = nil
			} else if scenario == "pending" || scenario == "rejected" {
				desired[0].Tuples = nil
				desired[0].Status = domain.VerificationPending
				if scenario == "rejected" {
					desired[0].Status = domain.VerificationRejected
				}
			} else if scenario == "mixed" {
				desired = append(desired, DesiredMember{RuleFP: "pending-rule", ObjectType: "compute.instance", ObjectID: "other", Status: domain.VerificationPending})
			} else {
				current = []domain.TargetMember{{BindingID: bs.BindingID, RoleID: domain.RoleID(bs.RoleID), RuleFP: desired[0].RuleFP, ObjectType: desired[0].ObjectType, ObjectID: desired[0].ObjectID, VerificationStatus: domain.VerificationActive}}
				if scenario == "pending-active" {
					current[0].VerificationStatus = domain.VerificationPending
				}
				if scenario == "active-pending" {
					desired[0].Status = domain.VerificationPending
					desired[0].Tuples = nil
				}
				if scenario == "active-rejected" {
					desired[0].Status = domain.VerificationRejected
					desired[0].Tuples = nil
				}
				if scenario != "completion" {
					store.ledger = memberLedger("compute.instance", domain.MembershipTuple{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:i-00000"})
				}
				if scenario == "revoke" {
					desired = nil
				}
			}
			r := New(fakeRunner{s: store}, nil, catalogfixture.Source())
			collector := &syncFGACollector{}
			require.NoError(t, r.applyDiff(context.Background(), store, bs, desired, current, bindingEmitted(store, bs.BindingID, true), collector))
			require.NoError(t, r.flushDeletes(context.Background(), store, collector))
			require.Empty(t, store.batches, "existing/status/revoke/completion не используют cold bulk")
			if scenario == "empty" {
				require.Zero(t, store.singles)
				require.Empty(t, store.writes)
			}
			if scenario == "pending" || scenario == "rejected" || scenario == "pending-active" || scenario == "active-pending" || scenario == "active-rejected" {
				require.Equal(t, 1, store.singles)
			}
			if scenario == "mixed" {
				require.Equal(t, 2, store.singles)
			}
			if scenario == "rejected" || scenario == "active-rejected" {
				require.Len(t, store.audits, 1)
			}
			if scenario == "completion" {
				require.Zero(t, store.singles)
				require.Len(t, allWrites(store.fakeStore), 1)
				require.Len(t, store.recorded, 1)
			}
			if scenario == "revoke" || scenario == "active-pending" || scenario == "active-rejected" {
				require.Len(t, store.forgotten, 1)
				require.Len(t, store.tdeletes, 1)
			}
			if scenario == "revoke" {
				require.Len(t, store.deletes, 1)
			}
		})
	}
}

// Два допустимых verb tuples каждому из 32 субъектов: tuple budget наступает
// после 64 членов, существенно раньше member budget4096.
func coldFanoutDesired(n int) ([]DesiredMember, *coldBatchStore, BindingScope) {
	desired, store := coldDesired(n)
	bs := coldScope()
	for subject := 0; subject < 32; subject++ {
		bs.Subjects = append(bs.Subjects, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(fmt.Sprintf("usr-%02d", subject))})
	}
	for i := range desired {
		desired[i].Tuples = nil
		for _, subject := range bs.Subjects {
			for _, relation := range []string{"v_get", "v_update"} {
				desired[i].Tuples = append(desired[i].Tuples, domain.MembershipTuple{User: "user:" + string(subject.ID), Relation: relation, Object: "compute_instance:" + desired[i].ObjectID})
			}
		}
	}
	return desired, store, bs
}

func TestApplyDiff_ColdActiveTupleBudgetMultiSubjectMatchesOriginal(t *testing.T) {
	desired, fast, bs := coldFanoutDesired(129)
	_, original, _ := coldFanoutDesired(129)
	require.LessOrEqual(t, len(bs.Subjects), domain.MaxSubjectsPerBinding)
	// Первый член второй партии разделяет tuples и координату с первой партией,
	// но имеет другой RuleFP: ledger и общий collector имеют разные полные ключи.
	desired[64] = desired[0]
	desired[64].RuleFP = "shared-other-rule"
	r := New(fakeRunner{s: fast}, nil, catalogfixture.Source())
	require.NoError(t, r.applyDiff(context.Background(), fast, bs, desired, nil, nil, &syncFGACollector{}))
	current := []domain.TargetMember{{BindingID: bs.BindingID, RuleFP: "sentinel", ObjectType: "compute.instance", ObjectID: "absent", VerificationStatus: domain.VerificationPending}}
	require.NoError(t, r.applyDiff(context.Background(), original, bs, desired, current, nil, &syncFGACollector{}))
	require.Equal(t, original.upserts, fast.upserts)
	require.Equal(t, allWrites(original.fakeStore), allWrites(fast.fakeStore))
	require.ElementsMatch(t, original.ledgerNow(), fast.ledgerNow())
	require.Len(t, allWrites(fast.fakeStore), 128*64)
	require.Len(t, fast.ledgerNow(), 128*64)
	require.Len(t, fast.batches, 3)
	require.Len(t, fast.batches[0], 64)
	require.Len(t, fast.batches[1], 64)
	require.Len(t, fast.batches[2], 1)
	var expectedLocks []MemberCoord
	for i := 0; i < 129; i++ {
		if i == 64 {
			continue // Эта координата заменена вторым правилом уже учтённого i-00000.
		}
		expectedLocks = append(expectedLocks, MemberCoord{ObjectType: "compute.instance", ObjectID: fmt.Sprintf("i-%05d", i)})
	}
	require.Equal(t, 1, fast.mirrorCalls)
	require.ElementsMatch(t, expectedLocks, fast.mirrorLocks, "tuple-triggered batches сохраняют исходный exact multiset")
	require.ElementsMatch(t, expectedLocks, fast.locksBeforeFirstWrite)
	require.Empty(t, fast.mirrorLocksAfterFirstWrite)
	require.Zero(t, fast.singles)
	require.Empty(t, original.batches)
	require.Len(t, fast.writes, len(fast.refs))
	for i, refs := range fast.refs {
		require.LessOrEqual(t, len(refs), 4096)
		require.LessOrEqual(t, len(fast.writes[i]), 4096)
		require.LessOrEqual(t, len(fast.writes[i]), len(refs), "fresh — подмножество ledger своей партии")
		ledgerTuples := map[domain.MembershipTuple]bool{}
		for _, ref := range refs {
			require.Equal(t, bs.BindingID, ref.BindingID)
			require.Equal(t, "compute.instance", ref.Member.ObjectType)
			require.Equal(t, "compute_instance:"+ref.Member.ObjectID, ref.Tuple.Object)
			ledgerTuples[ref.Tuple] = true
		}
		for _, tuple := range fast.writes[i] {
			require.True(t, ledgerTuples[tuple], "fresh tuple обязан иметь ledger ref в этой партии")
		}
	}
}

func TestApplyDiff_ColdActiveSingleLargeMemberRemainsWholeAndIsolated(t *testing.T) {
	desired, fast, bs := coldFanoutDesired(3)
	_, original, _ := coldFanoutDesired(3)
	base := desired[1].Tuples
	// Повтор допустимых tuples не расширяет subjects/verbs. Такой member прежняя
	// memberTuples принимает целиком; новый batching не вправе отказать/усечь его.
	desired[1].Tuples = nil
	for i := 0; i < 65; i++ {
		desired[1].Tuples = append(desired[1].Tuples, base...)
	}
	r := New(fakeRunner{s: fast}, nil, catalogfixture.Source())
	require.NoError(t, r.applyDiff(context.Background(), fast, bs, desired, nil, nil, &syncFGACollector{}))
	current := []domain.TargetMember{{BindingID: bs.BindingID, RuleFP: "sentinel", ObjectType: "compute.instance", ObjectID: "absent", VerificationStatus: domain.VerificationPending}}
	require.NoError(t, r.applyDiff(context.Background(), original, bs, desired, current, nil, &syncFGACollector{}))
	require.Equal(t, original.upserts, fast.upserts)
	require.Equal(t, allWrites(original.fakeStore), allWrites(fast.fakeStore))
	require.ElementsMatch(t, original.ledgerNow(), fast.ledgerNow())
	require.Len(t, fast.batches, 3)
	for _, batch := range fast.batches {
		require.Len(t, batch, 1)
	}
	require.Len(t, fast.refs[0], 64)
	require.Len(t, fast.refs[1], 4160, "большой member сохранён целиком и не смешан с соседями")
	require.Len(t, fast.refs[2], 64)
	require.Len(t, fast.writes[1], 64, "общий collector сохраняет прежнюю дедупликацию")
	require.Len(t, fast.ledgerNow(), 192)
}

func TestApplyDiff_ColdActiveTupleTriggeredSecondBatchFailure(t *testing.T) {
	for _, stage := range []string{"members", "queue", "ledger"} {
		t.Run(stage, func(t *testing.T) {
			desired, store, bs := coldFanoutDesired(129)
			store.failStage = stage
			store.failure = errors.New("tuple-triggered second batch failed")
			r := New(fakeRunner{s: store}, nil, catalogfixture.Source())
			err := r.applyDiff(context.Background(), store, bs, desired, nil, nil, &syncFGACollector{})
			require.ErrorIs(t, err, store.failure)
			require.Len(t, store.batches, 2, "ошибка останавливает третью партию")
			require.Len(t, store.batches[0], 64)
			require.Len(t, store.batches[1], 64)
			require.Zero(t, store.singles)
			for _, refs := range store.refs {
				require.LessOrEqual(t, len(refs), 4096)
			}
		})
	}
}
