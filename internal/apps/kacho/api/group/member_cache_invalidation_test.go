// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// member_cache_invalidation_test.go — membership change must invalidate the
// member's cached verdicts, not only rewrite the relation store.
//
// A GROUP-subject AccessBinding grants through the `group:<gid>#member` userset.
// Removing a member therefore takes access away — but the only thing the
// use-case emitted was the FGA tuple intent, which travels to the relation store
// and reaches NO verdict cache. Verdict caches are dropped by the `subject_change`
// journal: строка пишется ЗДЕСЬ, а гасит кэш её ЧИТАТЕЛЬ — край, открывающий
// чтение сам (задача #1024 развернула направление; прежде строку толкал дренаж
// владельца прав). With no row emitted, the sole way a removed member stops
// passing is the cache entry ageing out — i.e. the revocation window, and only
// that.
//
// `subject_change_op_check` has admitted `group_member_change` since the initial
// schema; nothing ever produced it.
package group

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// fakeABWriter records subject-change emits; every other method of the wide
// WriterIface stays nil-embedded and panics if the use-case path widens.
type fakeABWriter struct {
	abrepo.WriterIface
	w *fakeMemberWriter

	events []abrepo.SubjectChangeEvent
}

func (a *fakeABWriter) EmitSubjectChangeEvent(_ context.Context, e abrepo.SubjectChangeEvent) error {
	a.events = append(a.events, e)
	a.w.seq = append(a.w.seq, "emit_subject_change")
	return nil
}

func (w *fakeMemberWriter) AccessBindingsW() abrepo.WriterIface { return w.abw }

const (
	testGroupID  = domain.GroupID("grp0000000000000abcd")
	testMemberID = domain.SubjectID("usr0000000000000aaaa")
)

// TestRemoveMember_InvalidatesTheMembersVerdictCache — the observable one.
//
// Removing a member must emit the `group_member_change` subject-change event for
// THE MEMBER (not the group): the edge keys cached verdicts by the subject that
// presented the token, and the member is who loses access.
func TestRemoveMember_InvalidatesTheMembersVerdictCache(t *testing.T) {
	repo, w := newFakeMemberRepo()
	uc := NewRemoveMemberUseCase(repo, nil)

	_, err := uc.doRemove(context.Background(), RemoveMemberInput{
		GroupID:    testGroupID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   testMemberID,
	})
	require.NoError(t, err)

	require.Len(t, w.abw.events, 1,
		"removing a member must emit exactly one subject-change event; without it no "+
			"verdict cache is dropped and the only thing that ends the member's access "+
			"is the revocation window expiring")
	ev := w.abw.events[0]
	assert.Equal(t, string(testMemberID), ev.SubjectID,
		"the subject is the MEMBER — that is whose cached verdicts must go")
	assert.Equal(t, "group_member_change", ev.EventType,
		"canonical event tag admitted by subject_change_op_check since the initial schema")
	assert.Equal(t, "group_member_change", ev.Op,
		"legacy op alias must satisfy the DB CHECK, or the INSERT is rejected outright")
}

// TestAddMember_InvalidatesTheMembersVerdictCache — the paired POSITIVE side.
//
// Adding is not symmetric with removing: only POSITIVE verdicts are cached
// (pkg/authz.RevocationWindowPolicy), so a fresh grant is visible immediately and
// needs no invalidation. It is emitted anyway because a cached DENY is possible
// at the edge in principle and because a producer that fires on one half of a
// mutation pair is the harder thing to reason about later.
func TestAddMember_InvalidatesTheMembersVerdictCache(t *testing.T) {
	repo, w := newFakeMemberRepo()
	uc := NewAddMemberUseCase(repo, nil)

	_, err := uc.doAdd(context.Background(), AddMemberInput{
		GroupID:    testGroupID,
		MemberType: domain.SubjectTypeServiceAccount,
		MemberID:   domain.SubjectID("sva0000000000000bbbb"),
	})
	require.NoError(t, err)

	require.Len(t, w.abw.events, 1)
	assert.Equal(t, "sva0000000000000bbbb", w.abw.events[0].SubjectID)
	assert.Equal(t, "group_member_change", w.abw.events[0].EventType)
}

// TestMemberChangeEventIsEmittedInsideTheWriterTx — ban #10: the row is written
// in the SAME transaction as the membership DML, never after the commit.
//
// Proven by ORDER, not by a comment: a rolled-back membership change must not
// leave an outbox row promising an invalidation that never had a cause.
func TestMemberChangeEventIsEmittedInsideTheWriterTx(t *testing.T) {
	repo, w := newFakeMemberRepo()
	uc := NewRemoveMemberUseCase(repo, nil)

	_, err := uc.doRemove(context.Background(), RemoveMemberInput{
		GroupID:    testGroupID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   testMemberID,
	})
	require.NoError(t, err)

	require.Contains(t, w.seq, "emit_subject_change")
	require.Contains(t, w.seq, "commit")
	assert.Less(t, indexOf(w.seq, "emit_subject_change"), indexOf(w.seq, "commit"),
		"emit must precede commit — an emit after the commit is a dual write, and a "+
			"rollback would leave the membership intact while announcing its removal")
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}
