// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// verify_gate_boot_smoke_test.go — review #14 unit coverage for the non-fatal skip
// branch of RunBootForwardSmoke (no Postgres): when the store reports NO owner-binding
// candidate (a brand-new cluster), the boot forward-smoke is a no-op (ran=false, no
// error) and never drives the reconcile engine — so boot does not crash on a
// best-effort gate. The positive (candidate-present) path is integration-tested in
// pg/verify_gate_boot_smoke_integration_test.go.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// stubVerifyStore — a VerifyStore double for the no-candidate skip path. Only
// SmokeOwnerBindingCandidate is exercised; any other call is a test-author error.
type stubVerifyStore struct {
	candidateOK  bool
	candidateErr error
}

func (s stubVerifyStore) ListActiveBindingMaterialization(context.Context) ([]BindingMaterialization, error) {
	panic("ListActiveBindingMaterialization not expected")
}
func (s stubVerifyStore) ListOwnerBindingsMissingMembers(context.Context) ([]domain.AccessBindingID, error) {
	panic("ListOwnerBindingsMissingMembers not expected")
}
func (s stubVerifyStore) SeedSmokeMirrorObject(context.Context, string, string, string, string, map[string]string) error {
	panic("SeedSmokeMirrorObject must NOT be called when there is no candidate")
}
func (s stubVerifyStore) RemoveSmokeMirrorObject(context.Context, string, string) error {
	panic("RemoveSmokeMirrorObject must NOT be called when there is no candidate")
}
func (s stubVerifyStore) LedgerHasObject(context.Context, domain.AccessBindingID, string) (bool, error) {
	panic("LedgerHasObject must NOT be called when there is no candidate")
}
func (s stubVerifyStore) SmokeOwnerBindingCandidate(context.Context) (domain.AccessBindingID, string, bool, error) {
	return "", "", s.candidateOK, s.candidateErr
}
func (s stubVerifyStore) ListActiveBindingRelationChecks(context.Context) ([]BindingRelationCheck, error) {
	panic("ListActiveBindingRelationChecks not expected on the boot-smoke skip path")
}

// panicEngine fails the test if the reconcile engine is driven on the skip path.
type panicEngine struct{}

func (panicEngine) ReconcileObject(context.Context, string, string) error {
	panic("ReconcileObject must NOT be called when there is no smoke candidate")
}

func TestRunBootForwardSmoke_NoCandidate_NonFatalSkip(t *testing.T) {
	gate := NewVerifyGate(panicEngine{}, stubVerifyStore{candidateOK: false}, nil)

	passed, ran, err := gate.RunBootForwardSmoke(context.Background())
	require.NoError(t, err, "no candidate is a non-fatal skip, not an error")
	assert.False(t, ran, "no owner-binding candidate → forward-smoke skipped")
	assert.False(t, passed)
}

func TestRunBootForwardSmoke_DiscoveryError_Wrapped(t *testing.T) {
	sentinel := errors.New("db down")
	gate := NewVerifyGate(panicEngine{}, stubVerifyStore{candidateErr: sentinel}, nil)

	passed, ran, err := gate.RunBootForwardSmoke(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel, "discovery error is wrapped (not swallowed)")
	assert.False(t, ran)
	assert.False(t, passed)
}
