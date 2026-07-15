// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// verify_gate_relation_test.go — Design-B (flat-authz verb-bearing complete)
// acceptance VBC-19/VBC-20 (verify-gate relation-satisfies-action, F-11/F-12).
//
// The pre-Design-B verify-gate only proved "materialization-happened" (the ledger
// is non-empty) — the blind spot that let the Design-A class-of-bug through
// (a tuple was materialized, but the relation it resolved did NOT satisfy the
// enforcement-relation the catalog gates on). The extended gate runs, for every
// active binding's required-relation check, a REAL FGA Check(subject,
// required_relation, object) and gates the cutover ONLY when 100% are ALLOW.
//
// This unit test drives the gate through a fake RelationChecker + store; the
// real-OpenFGA proof is in the pg integration test.
//
// RED until VerifyGate.VerifyRelationSatisfiesAction exists.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// relCheckStore — a VerifyStore double exposing ONLY the relation-check list; all
// other VerifyStore methods panic (not exercised on this path).
type relCheckStore struct {
	stubVerifyStore
	checks []BindingRelationCheck
	err    error
}

func (s relCheckStore) ListActiveBindingRelationChecks(context.Context) ([]BindingRelationCheck, error) {
	return s.checks, s.err
}

// fakeRelChecker — records (subject, relation, object) and returns a programmed
// verdict per object.
type fakeRelChecker struct {
	allow map[string]bool // object → allowed
	calls int
}

func (c *fakeRelChecker) Check(_ context.Context, _ /*subject*/, _ /*relation*/, object string) (bool, error) {
	c.calls++
	return c.allow[object], nil
}

func TestVerifyGate_VBC19_RelationSatisfiesAction_AllAllow(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_1", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
		{BindingID: "acb_2", Subject: "user:usr_b", Relation: "v_list", Object: "vpc_network:vpcn_y"},
	}}
	chk := &fakeRelChecker{allow: map[string]bool{
		"iam_user:usr_x":     true,
		"vpc_network:vpcn_y": true,
	}}

	gate := NewVerifyGate(panicEngine{}, store, nil).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	assert.True(t, report.NoAccessLoss,
		"VBC-19: 100% of active bindings satisfy required_relation → cutover permitted")
	assert.Equal(t, 2, report.BindingsChecked)
	assert.Empty(t, report.Failures)
	assert.Equal(t, 2, chk.calls, "VBC-19: gate must run a real FGA Check per active binding (not ledger-only)")
}

func TestVerifyGate_VBC20_CutoverBlockedUntilVGetBackfilled(t *testing.T) {
	// One active binding holds only a historical tier-tuple, so Check(v_get) DENIES
	// — the gate must FAIL (cutover blocked) until the reconciler backfills v_get.
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_ok", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
		{BindingID: "acb_bad", Subject: "user:usr_b", Relation: "v_get", Object: "iam_role:rol_y"},
	}}
	chk := &fakeRelChecker{allow: map[string]bool{
		"iam_user:usr_x": true,
		// iam_role:rol_y absent → DENY (tier-only historical ledger, no v_get).
	}}

	gate := NewVerifyGate(panicEngine{}, store, nil).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	assert.False(t, report.NoAccessLoss,
		"VBC-20: an active leaf-member with no v_get (Check DENY) → gate FAIL, cutover blocked (F-11)")
	require.Len(t, report.Failures, 1)
	assert.Equal(t, domain.AccessBindingID("acb_bad"), report.Failures[0].BindingID)
}

func TestVerifyGate_VBC19_NilChecker_SkipNonFatal(t *testing.T) {
	// An unwired RelationChecker (nil) makes the relation-satisfies gate a non-fatal
	// skip (ran=false) — the boot must not crash when the FGA checker is degraded.
	store := relCheckStore{}
	gate := NewVerifyGate(panicEngine{}, store, nil) // no WithRelationChecker
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	assert.True(t, report.NoAccessLoss, "nil checker → non-fatal skip (no assertion made)")
	assert.Equal(t, 0, report.BindingsChecked)
}
