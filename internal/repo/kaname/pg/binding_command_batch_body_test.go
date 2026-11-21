// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Только запись SQL плана прежнего body, не замена admission/runtime proof.
type bindingBodyCapture struct {
	pgx.Tx
	statement string
	args      []any
	calls     int
}

func (c *bindingBodyCapture) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.calls++
	c.statement, c.args = sql, args
	return pgconn.CommandTag{}, nil
}

func TestBindingCommandBatchBodyMatchesOriginalStores(t *testing.T) {
	m := domain.TargetMember{BindingID: "ab", RoleID: "role", RuleFP: "rule", ObjectType: "iam.group", ObjectID: "group", VerificationStatus: domain.VerificationActive}
	duplicate, otherRule, otherRole := m, m, m
	duplicate.VerificationStatus = domain.VerificationRejected
	otherRule.RuleFP = "other-rule"
	otherRole.RoleID = "other-role"
	ref := reconcile.EmittedTupleRef{BindingID: "ab", Member: reconcile.MemberCoord{ObjectType: "iam.group", ObjectID: "group"}, Tuple: domain.MembershipTuple{User: "user:one", Relation: "viewer", Object: "iam_group:group"}}
	otherMember, otherBinding := ref, ref
	otherMember.Member.ObjectID = "other-group"
	otherBinding.BindingID = "other-ab"
	for _, command := range []reconcile.BindingCommand{
		{Kind: "members", Members: []domain.TargetMember{m, duplicate, otherRule, otherRole}},
		{Kind: "record", Refs: []reconcile.EmittedTupleRef{ref, ref, otherMember, otherBinding}},
	} {
		t.Run(command.Kind, func(t *testing.T) {
			capture := &bindingBodyCapture{}
			store := &reconcileStore{tx: capture}
			var err error
			if command.Kind == "members" {
				err = store.UpsertMembers(context.Background(), command.Members)
			} else {
				err = store.RecordEmittedTuplesBatch(context.Background(), command.Refs)
			}
			require.NoError(t, err)
			require.Equal(t, 1, capture.calls)
			sql, args, _, supported, err := bindingCommandBatchBody(command)
			require.NoError(t, err)
			require.True(t, supported)
			require.Equal(t, capture.statement, sql, "исходный SQL, включая conflict clause")
			require.Equal(t, capture.args, args, "исходный порядок, полные ключи и first wins")
			require.Len(t, args[0], 3)
			if command.Kind == "members" {
				require.Equal(t, "ACTIVE", args[5].([]string)[0])
			}
		})
	}
}

func TestBindingCommandBatchBodyKeepsWholeCommandBoundary(t *testing.T) {
	for _, kind := range []string{"members", "record"} {
		for _, size := range []int{0, 1, 4096, 4097} {
			command := reconcile.BindingCommand{Kind: kind}
			if kind == "members" {
				command.Members = make([]domain.TargetMember, size)
			} else {
				command.Refs = make([]reconcile.EmittedTupleRef, size)
				for i := range command.Refs {
					command.Refs[i].Tuple = domain.MembershipTuple{User: "user:one", Relation: "viewer", Object: "iam_group:one"}
				}
			}
			_, _, _, supported, err := bindingCommandBatchBody(command)
			require.NoError(t, err)
			require.Equal(t, size > 0 && size <= 4096, supported, "%s/%d", kind, size)
		}
	}
	for _, kind := range []string{"write", "delete", "forget", "member_delete", "audit", "unknown"} {
		_, _, _, supported, err := bindingCommandBatchBody(reconcile.BindingCommand{Kind: kind})
		require.NoError(t, err)
		require.False(t, supported, kind)
	}
	_, _, _, supported, err := bindingCommandBatchBody(reconcile.BindingCommand{Kind: "record", Refs: []reconcile.EmittedTupleRef{{}}})
	require.NoError(t, err)
	require.False(t, supported, "malformed record сохраняет прежний Begin перед ошибкой body")
}
