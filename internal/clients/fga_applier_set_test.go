// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// fga_applier_set_test.go — a row that names a subject's relation SET must reach
// OpenFGA as ONE call.
//
// The row is the drainer's unit of work, so it is also the unit of atomicity: what a
// row does not carry together cannot arrive together. These cases pin the row → call
// shape, which is where the property is either kept or lost; the end-to-end version,
// against the real table and the store's observable state, lives in
// services/iam/internal/repo/kacho/pg/fga_outbox/set_atomicity_integration_test.go.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

func TestDecodeFGAOutboxEvent_RelationSet(t *testing.T) {
	e, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","object":"vpc_address:vaddr1","relation":"v_get","relations":["v_get","v_list","v_update","v_delete"]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"v_get", "v_list", "v_update", "v_delete"}, e.Relations)
}

// TestDecodeFGAOutboxEvent_EchoOutsideTheSetIsPermanent — the compatibility echo
// (`relation` written alongside a set so a reader predating the set form can still
// decode the row) must name a MEMBER of the set. An echo pointing outside it would
// mean two readers of the same row apply different things, which is the one outcome
// neither shape may produce; and it can only be a producer bug, so retrying it is
// futile — hence permanent, not transient.
func TestDecodeFGAOutboxEvent_EchoOutsideTheSetIsPermanent(t *testing.T) {
	_, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","object":"vpc_address:vaddr1","relation":"owner","relations":["v_get","v_list"]}`))
	require.Error(t, err)
	assert.ErrorIs(t, err, drainer.ErrPermanent)
}

func TestDecodeFGAOutboxEvent_EmptyRelationInSetIsPermanent(t *testing.T) {
	_, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","object":"vpc_address:vaddr1","relations":["v_get",""]}`))
	require.Error(t, err)
	assert.ErrorIs(t, err, drainer.ErrPermanent)
}

func TestDecodeFGAOutboxEvent_NoRelationAtAllIsPermanent(t *testing.T) {
	_, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","object":"vpc_address:vaddr1"}`))
	require.Error(t, err)
	assert.ErrorIs(t, err, drainer.ErrPermanent)
}

// TestFGAApplier_RelationSet_AppliedInOneCall — grant direction.
func TestFGAApplier_RelationSet_AppliedInOneCall(t *testing.T) {
	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)

	ev, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","object":"vpc_address:vaddr1","relation":"v_get","relations":["v_get","v_list","v_update","v_delete"]}`))
	require.NoError(t, err)
	require.NoError(t, apply(context.Background(), clients.FGAEventTypeWrite, ev))

	require.Len(t, mock.writeCalls, 1,
		"the row's whole set must reach the store in ONE call — split across calls it is "+
			"observable half present, which is a subject that may read its own fresh object "+
			"and may not change it")
	assert.Equal(t, []clients.RelationTuple{
		{User: "user:usr01", Relation: "v_get", Object: "vpc_address:vaddr1"},
		{User: "user:usr01", Relation: "v_list", Object: "vpc_address:vaddr1"},
		{User: "user:usr01", Relation: "v_update", Object: "vpc_address:vaddr1"},
		{User: "user:usr01", Relation: "v_delete", Object: "vpc_address:vaddr1"},
	}, mock.writeCalls[0])
	assert.Empty(t, mock.deleteCalls)
}

// TestFGAApplier_RelationSet_RevokedInOneCall — revoke direction. It is the quieter
// half and therefore the one worth pinning explicitly: a grant that lands late is a
// caller retrying, while a revoke that lands in pieces is access outliving its own
// removal, and from outside "works" and "not revoked yet" look identical.
func TestFGAApplier_RelationSet_RevokedInOneCall(t *testing.T) {
	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)

	ev, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","object":"vpc_address:vaddr1","relation":"v_get","relations":["v_get","v_delete"]}`))
	require.NoError(t, err)
	require.NoError(t, apply(context.Background(), clients.FGAEventTypeDelete, ev))

	require.Len(t, mock.deleteCalls, 1)
	assert.Equal(t, []clients.RelationTuple{
		{User: "user:usr01", Relation: "v_get", Object: "vpc_address:vaddr1"},
		{User: "user:usr01", Relation: "v_delete", Object: "vpc_address:vaddr1"},
	}, mock.deleteCalls[0])
	assert.Empty(t, mock.writeCalls)
}

// TestFGAApplier_SingleRelationRow_Unchanged — the positive control. Most producers
// (bootstrap, JIT, break-glass, the register proxy) name one relation at a time, and
// their rows must keep the historical shape and the historical one-tuple call. Without
// this the set cases above would stay green on an applier that had quietly changed what
// every other producer sends.
func TestFGAApplier_SingleRelationRow_Unchanged(t *testing.T) {
	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)

	ev, err := clients.DecodeFGAOutboxEvent([]byte(
		`{"user":"user:usr01","relation":"system_admin","object":"cluster:default"}`))
	require.NoError(t, err)
	require.NoError(t, apply(context.Background(), clients.FGAEventTypeWrite, ev))

	require.Len(t, mock.writeCalls, 1)
	assert.Equal(t, []clients.RelationTuple{
		{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"},
	}, mock.writeCalls[0])
}
