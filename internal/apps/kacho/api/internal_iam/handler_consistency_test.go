// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// handler_consistency_test.go — the InternalIAMService.Check handler must forward
// CheckRequest.consistency to CheckRelation so the owner-tuple confirm-gate probe
// reaches OpenFGA with HIGHER_CONSISTENCY (Koren-1 tail fix). The enforcement gate
// (unset consistency) must keep the default (HigherConsistency=false).

func TestInternalIAM_Check_ForwardsHigherConsistency(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{Allowed: true}}
	h := newCheckHandler(authz)

	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId:   "user:usr_owner",
		Relation:    "v_update",
		Object:      "vpc_network:enp_new",
		Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY,
	})
	require.NoError(t, err)
	assert.True(t, authz.gotReq.HigherConsistency,
		"HIGHER_CONSISTENCY on the wire must set CheckRelationRequest.HigherConsistency")
}

func TestInternalIAM_Check_DefaultConsistency_NotForced(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{Allowed: true}}
	h := newCheckHandler(authz)

	// Enforcement gate: consistency unset → default (cache-eligible) read.
	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_reader",
		Relation:  "viewer",
		Object:    "vpc_network:enp_x",
	})
	require.NoError(t, err)
	assert.False(t, authz.gotReq.HigherConsistency,
		"unset consistency must NOT force HIGHER_CONSISTENCY (enforcement gate stays low-latency)")

	// Explicit MINIMIZE_LATENCY behaves identically to unset.
	_, err = h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId:   "user:usr_reader",
		Relation:    "viewer",
		Object:      "vpc_network:enp_x",
		Consistency: iamv1.CheckRequest_MINIMIZE_LATENCY,
	})
	require.NoError(t, err)
	assert.False(t, authz.gotReq.HigherConsistency)
}
