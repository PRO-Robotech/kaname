// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// access_binding_materialized_test.go — the materialization instant must reach the
// wire.
//
// Kachō is eventually-consistent: `Operation.done` means the binding row is
// DURABLE, never that the FGA tuples carrying the access are visible (gating
// `done` on downstream visibility is forbidden — ban #9). During that window the
// grantee gets a 403 that is byte-identical to a genuine denial, so the
// administrator who just granted cannot distinguish "still propagating" from
// "granted the wrong thing", and has nothing to poll.
//
// `materialized_at` is that signal WITHOUT a server-side barrier: it is a plain
// output-only field on the resource, so the client polls it with the very same
// bounded retry it already runs against the transient 403.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func TestAccessBindingToPb_MaterializedAtProjected(t *testing.T) {
	at := time.Date(2026, 7, 25, 10, 30, 45, 987_654_321, time.UTC)

	pb, err := abObj{}.toPb(domain.AccessBinding{
		ID:             domain.AccessBindingID("acb00000000000000mat"),
		Status:         domain.AccessBindingStatusActive,
		MaterializedAt: at,
	})
	require.NoError(t, err)
	require.NotNil(t, pb.GetMaterializedAt(),
		"a materialized binding must expose WHEN its access became live")
	assert.Equal(t, at.Truncate(time.Second).Unix(), pb.GetMaterializedAt().GetSeconds())
	assert.Zero(t, pb.GetMaterializedAt().GetNanos(),
		"timestamps are truncated to seconds on the wire (api-conventions)")
}

// Unset means "no ACTIVE per-object member yet" — still propagating, or a binding
// that materializes nothing per-object (cluster scope / legacy permissions-only
// role). It must be absent, not a zero epoch that reads as "materialized in 1970".
func TestAccessBindingToPb_MaterializedAtUnsetWhenNotMaterialized(t *testing.T) {
	pb, err := abObj{}.toPb(domain.AccessBinding{
		ID:     domain.AccessBindingID("acb00000000000000unm"),
		Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	assert.Nil(t, pb.GetMaterializedAt(),
		"a not-yet-materialized binding must leave the field unset, never epoch-zero")
}
