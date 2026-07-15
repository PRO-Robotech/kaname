// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cache_invalidation_applier_test.go — unit tests for SubjectChangeApplier +
// DecodeSubjectChange.
//
// Applier scenarios:
//
//	single emit → applier RPC invoked (happy)
//	gateway NotFound (no cache entries) → ErrAlreadyApplied
//	gateway Unavailable → transient (propagated raw, drainer retries)
//	gateway InvalidArgument → ErrPermanent
//	FGA prefix mapping (usr_/sva_/grp_)
//
// Decoder scenarios:
//
//	payload IS NULL (race with backfill) → ErrPermanent
//	legacy row with op only → event_type derived
package clients_test

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	apigatewayv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/apigateway/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// ─────────────────────────────────────────────────────────────────────────────
// recordingAuthzCacheClient — captures InvalidateSubject calls + returns
// canned status/error. Thread-safe (drainer can apply concurrently in some
// integration tests).
// ─────────────────────────────────────────────────────────────────────────────

type recordingAuthzCacheClient struct {
	mu     sync.Mutex
	calls  []*apigatewayv1.InvalidateSubjectRequest
	errs   []error // per-call return; if shorter than calls, last value reused
	cursor int
}

func (c *recordingAuthzCacheClient) InvalidateSubject(
	_ context.Context, req *apigatewayv1.InvalidateSubjectRequest, _ ...grpc.CallOption,
) (*emptypb.Empty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, req)
	var e error
	switch {
	case len(c.errs) == 0:
		e = nil
	case c.cursor < len(c.errs):
		e = c.errs[c.cursor]
	default:
		e = c.errs[len(c.errs)-1]
	}
	c.cursor++
	if e != nil {
		return nil, e
	}
	return &emptypb.Empty{}, nil
}

func (c *recordingAuthzCacheClient) snapshot() []*apigatewayv1.InvalidateSubjectRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*apigatewayv1.InvalidateSubjectRequest, len(c.calls))
	copy(out, c.calls)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodeSubjectChange
// ─────────────────────────────────────────────────────────────────────────────

// Test_DecoderLegacyPayload — legacy rows pre-rollout may have
// `event_type` field absent in JSON (or be derived from `op` alias by the
// migration 0023 backfill). Decoder must default event_type to canonical
// alias of op (binding_delete→binding_revoke, binding_upsert→binding_grant).
func Test_DecoderLegacyPayload(t *testing.T) {
	payload := []byte(`{"subject_id":"usr_legacy","op":"binding_delete"}`)
	e, err := clients.DecodeSubjectChange(payload)
	require.NoError(t, err)
	assert.Equal(t, "usr_legacy", e.SubjectID)
	assert.Equal(t, "binding_revoke", e.EventType,
		"decoder must derive canonical event_type from legacy op alias")
	assert.Equal(t, "binding_delete", e.Op)
}

// Test_DecoderModernPayload — modern writers populate both
// op and event_type. Decoder returns the explicit event_type as-is.
func Test_DecoderModernPayload(t *testing.T) {
	payload := []byte(
		`{"subject_id":"usr_x","op":"jit_revoke","event_type":"jit_revoke",` +
			`"resource_type":"project","resource_id":"prj_a"}`)
	e, err := clients.DecodeSubjectChange(payload)
	require.NoError(t, err)
	assert.Equal(t, "usr_x", e.SubjectID)
	assert.Equal(t, "jit_revoke", e.EventType)
	assert.Equal(t, "project", e.ResourceType)
	assert.Equal(t, "prj_a", e.ResourceID)
}

// Test_DecoderEmptyPayloadIsPermanent — payload IS NULL after migration
// 0023 backfill should be impossible in steady state, but if a legacy
// writer commits an INSERT in the race window between ADD COLUMN and
// UPDATE-backfill, decoder must fail-permanent.
func Test_DecoderEmptyPayloadIsPermanent(t *testing.T) {
	_, err := clients.DecodeSubjectChange(nil)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"empty payload must wrap drainer.ErrPermanent (defensive — legacy row not backfilled)")
	assert.Contains(t, err.Error(), "payload",
		"error message must mention payload so operator can diagnose")
}

// Test_DecoderMalformedJSONIsPermanent — invalid JSON → permanent
// (poison the row; never retry malformed payload).
func Test_DecoderMalformedJSONIsPermanent(t *testing.T) {
	_, err := clients.DecodeSubjectChange([]byte(`{not-json`))
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent))
}

// Test_DecoderEmptySubjectIDIsPermanent — empty subject_id (e.g. forced
// INSERT with subject_id=”) → permanent (drainer poisons; would
// inevitably hit gateway InvalidArgument anyway).
func Test_DecoderEmptySubjectIDIsPermanent(t *testing.T) {
	_, err := clients.DecodeSubjectChange([]byte(`{"subject_id":"","op":"binding_delete"}`))
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent))
}

// ─────────────────────────────────────────────────────────────────────────────
// SubjectChangeApplier — happy path
// ─────────────────────────────────────────────────────────────────────────────

// Test_ApplierInvokesInvalidateSubject — happy path: decoded
// event → applier → InvalidateSubject called once with correct fields.
func Test_ApplierInvokesInvalidateSubject(t *testing.T) {
	mock := &recordingAuthzCacheClient{}
	apply := clients.NewSubjectChangeApplier(mock)

	ev := clients.SubjectChangeEvent{
		SubjectID:    "usr_alice",
		EventType:    "binding_revoke",
		Op:           "binding_delete",
		ResourceType: "project",
		ResourceID:   "prj_a",
	}
	err := apply(context.Background(), "binding_revoke", ev)
	require.NoError(t, err)

	calls := mock.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "user:usr_alice", calls[0].Subject,
		"applier must FGA-prefix usr_ subject ids with 'user:'")
	assert.Equal(t, "binding_revoke", calls[0].EventType)
	assert.Equal(t, "project", calls[0].ResourceType)
	assert.Equal(t, "prj_a", calls[0].ResourceId)
}

// ─────────────────────────────────────────────────────────────────────────────
// SubjectChangeApplier — error classification
// ─────────────────────────────────────────────────────────────────────────────

// Test_ApplierReturnsErrAlreadyAppliedOnNotFound — gateway-side
// 0-entries-dropped is reported as codes.NotFound; applier must translate
// to drainer.ErrAlreadyApplied so the drainer marks sent_at and never
// re-tries.
func Test_ApplierReturnsErrAlreadyAppliedOnNotFound(t *testing.T) {
	mock := &recordingAuthzCacheClient{
		errs: []error{status.Error(codes.NotFound, "no cache entries for subject")},
	}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke",
		clients.SubjectChangeEvent{SubjectID: "usr_z", EventType: "binding_revoke"})
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrAlreadyApplied),
		"gateway NotFound must map to drainer.ErrAlreadyApplied")
}

// Test_ApplierReturnsErrPermanentOnInvalidArgument — empty subject
// or malformed request → InvalidArgument → ErrPermanent.
func Test_ApplierReturnsErrPermanentOnInvalidArgument(t *testing.T) {
	mock := &recordingAuthzCacheClient{
		errs: []error{status.Error(codes.InvalidArgument, "subject required")},
	}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke",
		clients.SubjectChangeEvent{SubjectID: "usr_a", EventType: "binding_revoke"})
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"gateway InvalidArgument must map to drainer.ErrPermanent")
}

// Test_ApplierPropagatesTransientUnavailable — Unavailable is
// transient (gateway down/restarting) — drainer retries with exp backoff.
// Applier must propagate raw (NOT wrap in ErrPermanent or ErrAlreadyApplied).
func Test_ApplierPropagatesTransientUnavailable(t *testing.T) {
	transient := status.Error(codes.Unavailable, "connection refused")
	mock := &recordingAuthzCacheClient{errs: []error{transient}}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke",
		clients.SubjectChangeEvent{SubjectID: "usr_a", EventType: "binding_revoke"})
	require.Error(t, err)
	assert.False(t, stderrors.Is(err, drainer.ErrPermanent),
		"Unavailable must NOT be permanent — drainer must retry")
	assert.False(t, stderrors.Is(err, drainer.ErrAlreadyApplied),
		"Unavailable must NOT be ErrAlreadyApplied — drainer must retry")
}

// Test_ApplierPropagatesTransientDeadlineExceeded — DeadlineExceeded
// is transient (gateway slow/overloaded).
func Test_ApplierPropagatesTransientDeadlineExceeded(t *testing.T) {
	mock := &recordingAuthzCacheClient{
		errs: []error{status.Error(codes.DeadlineExceeded, "context deadline exceeded")},
	}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke",
		clients.SubjectChangeEvent{SubjectID: "usr_a", EventType: "binding_revoke"})
	require.Error(t, err)
	assert.False(t, stderrors.Is(err, drainer.ErrPermanent))
	assert.False(t, stderrors.Is(err, drainer.ErrAlreadyApplied))
}

// ─────────────────────────────────────────────────────────────────────────────
// FGA prefix mapping (usr_/sva_/grp_)
// ─────────────────────────────────────────────────────────────────────────────

// Test_FGAPrefixMapping_usr — usr_ → user:
// Test_FGAPrefixMapping_sva — sva_ → service_account:
// Test_FGAPrefixMapping_grp — grp_ → group:
// All three asserted in one table-driven test for compactness.
func Test_FGAPrefixMapping(t *testing.T) {
	mock := &recordingAuthzCacheClient{}
	apply := clients.NewSubjectChangeApplier(mock)

	cases := []struct {
		subjectID string
		wantFGA   string
	}{
		{"usr_alpha", "user:usr_alpha"},
		{"sva_beta", "service_account:sva_beta"},
		{"grp_gamma", "group:grp_gamma"},
	}

	for _, tc := range cases {
		err := apply(context.Background(), "binding_revoke",
			clients.SubjectChangeEvent{SubjectID: tc.subjectID, EventType: "binding_revoke"})
		require.NoError(t, err, "subject %q", tc.subjectID)
	}

	calls := mock.snapshot()
	require.Len(t, calls, len(cases))
	for i, tc := range cases {
		assert.Equal(t, tc.wantFGA, calls[i].Subject,
			"subject %q must FGA-prefix to %q", tc.subjectID, tc.wantFGA)
	}
}

// Test_FGAPrefixUnknownFallback — unrecognised prefix (e.g.
// future subject-type) falls through as-is. Documented contract:
// applier doesn't grow new prefixes; canonical mapping owned by
// fgaPrefixSwitch.
func Test_FGAPrefixUnknownFallback(t *testing.T) {
	mock := &recordingAuthzCacheClient{}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke",
		clients.SubjectChangeEvent{SubjectID: "xyz_unknown", EventType: "binding_revoke"})
	require.NoError(t, err)
	calls := mock.snapshot()
	require.Len(t, calls, 1)
	// Unknown prefix passed as-is — gateway will report NotFound (no cache
	// entries) → ErrAlreadyApplied → row marked sent_at. Safe default.
	assert.Equal(t, "xyz_unknown", calls[0].Subject)
}

// Test_ApplierUsesDrainerEventTypeOverPayload — drainer signature
// `Applier[T] = func(ctx, eventType string, payload T) error` — the eventType
// arg is the canonical value scanned from row's `event_type` column. Applier
// must prefer it over payload.EventType (defensive: payload is informational,
// row column is the source of truth).
func Test_ApplierUsesDrainerEventTypeOverPayload(t *testing.T) {
	mock := &recordingAuthzCacheClient{}
	apply := clients.NewSubjectChangeApplier(mock)

	// Payload says binding_grant, drainer (column-scanned) says binding_revoke.
	// Applier must use the drainer arg.
	err := apply(context.Background(), "binding_revoke",
		clients.SubjectChangeEvent{
			SubjectID: "usr_test",
			EventType: "binding_grant", // drift — drainer arg wins
			Op:        "binding_upsert",
		})
	require.NoError(t, err)
	calls := mock.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "binding_revoke", calls[0].EventType,
		"drainer eventType arg (column) must override payload.EventType")
}
