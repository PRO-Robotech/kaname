// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// evaluate_test.go — unit coverage for
// ConditionsService.Evaluate (handler + ConditionsCRUDService.Evaluate wrapper).
//
// The raw evaluator (BuiltinEvaluator) already has unit tests in
// internal/service/conditions_evaluator_test.go; what was untested is the
// SERVICE wrapper path the handler drives: request `Context` injection
// (default current_time), repo.Get lookup, builtin recognition through a stored
// expression, and the handler's mapErr → gRPC status mapping. These tests use a
// real service.BuiltinEvaluator + a tiny in-memory ConditionsRepoPort fake — no
// Postgres required for the use-case logic (DB round-trip is covered separately
// in evaluate_integration_test.go).
package conditions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/condition"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeConditionsRepo — minimal ConditionsRepoPort for Evaluate use-case tests.
// Only Get is exercised by Evaluate; the rest satisfy the interface and panic
// if a future change starts calling them (so the fake never silently hides a
// regression).
type fakeConditionsRepo struct {
	byID map[domain.ConditionID]domain.Condition
	// listRows — rows returned by List. Filtered by FolderID when the filter
	// carries one (mirrors the repo's folder-scope predicate) so the authz
	// tests can distinguish an empty-folder_id global scan from a scoped list.
	listRows []domain.Condition
}

func (f *fakeConditionsRepo) Get(_ context.Context, id domain.ConditionID) (domain.Condition, error) {
	c, ok := f.byID[id]
	if !ok {
		return domain.Condition{}, iamerr.Wrapf(iamerr.ErrNotFound, "Condition %s not found", id)
	}
	return c, nil
}

func (f *fakeConditionsRepo) List(_ context.Context, filter condition.ListFilter) ([]domain.Condition, string, error) {
	if filter.FolderID == "" {
		return f.listRows, "", nil
	}
	out := make([]domain.Condition, 0, len(f.listRows))
	for _, c := range f.listRows {
		if c.FolderID == filter.FolderID {
			out = append(out, c)
		}
	}
	return out, "", nil
}

func (f *fakeConditionsRepo) CountReferences(context.Context, domain.ConditionID) (int64, error) {
	panic("CountReferences not used by Evaluate")
}

func (f *fakeConditionsRepo) Insert(context.Context, domain.Condition) (domain.Condition, error) {
	panic("Insert not used by Evaluate")
}

func (f *fakeConditionsRepo) UpdateMutable(context.Context, domain.ConditionID, condition.UpdatePatch, int64) (domain.Condition, error) {
	panic("UpdateMutable not used by Evaluate")
}

func (f *fakeConditionsRepo) SetStatus(context.Context, domain.ConditionID, domain.ConditionStatus) error {
	panic("SetStatus not used by Evaluate")
}

func (f *fakeConditionsRepo) Delete(context.Context, domain.ConditionID) error {
	panic("Delete not used by Evaluate")
}

// tx-scoped mutations (audit-atomic path) — never used by the
// sync Evaluate read path; panic so a future change can't silently call them.

func (f *fakeConditionsRepo) InsertTx(context.Context, service.Tx, domain.Condition) (domain.Condition, error) {
	panic("InsertTx not used by Evaluate")
}

func (f *fakeConditionsRepo) UpdateMutableTx(context.Context, service.Tx, domain.ConditionID, condition.UpdatePatch, int64) (domain.Condition, error) {
	panic("UpdateMutableTx not used by Evaluate")
}

func (f *fakeConditionsRepo) SetStatusTx(context.Context, service.Tx, domain.ConditionID, domain.ConditionStatus) error {
	panic("SetStatusTx not used by Evaluate")
}

func (f *fakeConditionsRepo) DeleteTx(context.Context, service.Tx, domain.ConditionID) error {
	panic("DeleteTx not used by Evaluate")
}

func (f *fakeConditionsRepo) CountReferencesTx(context.Context, service.Tx, domain.ConditionID) (int64, error) {
	panic("CountReferencesTx not used by Evaluate")
}

func newEvaluateHandler(t *testing.T, conds ...domain.Condition) *Handler {
	t.Helper()
	repo := &fakeConditionsRepo{byID: make(map[domain.ConditionID]domain.Condition, len(conds))}
	for _, c := range conds {
		repo.byID[c.ID] = c
	}
	// ops is nil: Evaluate is a sync read-path RPC that never touches the
	// operations table.
	svc := service.NewConditionsCRUDService(repo, nil, service.NewBuiltinEvaluator())
	return NewHandler(svc)
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

// ── happy: builtin recognised, evaluates true ────────────────────────────

func TestEvaluate_SourceIPInRange_Allowed(t *testing.T) {
	// Given a stored source_ip_in_range condition.
	cond := domain.Condition{
		ID:         "cnd00000000000000aaa",
		FolderID:   "fld_eval",
		Name:       "ip-corp",
		Expression: "source_ip_in_range",
		Status:     domain.ConditionStatusActive,
	}
	h := newEvaluateHandler(t, cond)

	// When evaluated with a client_ip inside the supplied allowed_cidrs.
	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(cond.ID),
		Context:     mustStruct(t, map[string]any{"client_ip": "10.0.0.5"}),
		Params:      mustStruct(t, map[string]any{"allowed_cidrs": []any{"10.0.0.0/24"}}),
	})

	// Then allowed=true and a trace + evaluatedAt are returned.
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	assert.NotEmpty(t, resp.GetTrace())
	require.NotNil(t, resp.GetEvaluatedAt())
}

// ── builtin recognised, evaluates false (deny path is still NoError) ──────

func TestEvaluate_SourceIPInRange_Denied(t *testing.T) {
	cond := domain.Condition{
		ID:         "cnd00000000000000bbb",
		FolderID:   "fld_eval",
		Name:       "ip-corp",
		Expression: "source_ip_in_range",
		Status:     domain.ConditionStatusActive,
	}
	h := newEvaluateHandler(t, cond)

	// When the client_ip is outside the allowed range.
	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(cond.ID),
		Context:     mustStruct(t, map[string]any{"client_ip": "192.168.1.1"}),
		Params:      mustStruct(t, map[string]any{"allowed_cidrs": []any{"10.0.0.0/24"}}),
	})

	// Then allowed=false (a deny is a successful evaluation, not an error).
	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
}

// ── params path: condition params drive the verdict independently of context ─

func TestEvaluate_BusinessHours_ParamsDriveVerdict(t *testing.T) {
	cond := domain.Condition{
		ID:         "cnd00000000000000ccc",
		FolderID:   "fld_eval",
		Name:       "biz-hours",
		Expression: "business_hours",
		Status:     domain.ConditionStatusActive,
	}
	h := newEvaluateHandler(t, cond)

	// current_time fixed at 10:00 UTC. With params start_h=9,end_h=18 → inside.
	tenAMUTC := int64(1718530200) // 2024-06-16T10:10:00Z, hour=10
	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(cond.ID),
		Context:     mustStruct(t, map[string]any{"current_time": float64(tenAMUTC)}),
		Params:      mustStruct(t, map[string]any{"start_h": float64(9), "end_h": float64(18), "tz": "UTC"}),
	})
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed(), "hour 10 is within [9,18)")

	// Same context, but params narrow the window to [11,18) → outside.
	resp2, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(cond.ID),
		Context:     mustStruct(t, map[string]any{"current_time": float64(tenAMUTC)}),
		Params:      mustStruct(t, map[string]any{"start_h": float64(11), "end_h": float64(18), "tz": "UTC"}),
	})
	require.NoError(t, err)
	assert.False(t, resp2.GetAllowed(), "hour 10 is outside [11,18)")
}

// ── free-form expression: evaluator delegates to FGA → not allowed, trace set ─

func TestEvaluate_FreeFormExpression_NotAllowedWithTrace(t *testing.T) {
	cond := domain.Condition{
		ID:         "cnd00000000000000ddd",
		FolderID:   "fld_eval",
		Name:       "free-form",
		Expression: `request.auth.claims.dept == "eng"`,
		Status:     domain.ConditionStatusActive,
	}
	h := newEvaluateHandler(t, cond)

	// When evaluated, the local evaluator cannot resolve a free-form CEL and
	// reports it (delegated to FGA semantics) — surfaced as allowed=false +
	// an explanatory trace, NOT a gRPC error.
	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(cond.ID),
		Context:     mustStruct(t, map[string]any{}),
	})

	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
	assert.NotEmpty(t, resp.GetTrace())
}

// ── negative: unknown condition id → NotFound ────────────────────────────

func TestEvaluate_UnknownConditionID_NotFound(t *testing.T) {
	h := newEvaluateHandler(t) // empty repo

	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: "cnd00000000000000zzz",
		Context:     mustStruct(t, map[string]any{}),
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ── negative: missing context → InvalidArgument (handler guard) ──────────

func TestEvaluate_MissingContext_InvalidArgument(t *testing.T) {
	cond := domain.Condition{
		ID:         "cnd00000000000000eee",
		FolderID:   "fld_eval",
		Name:       "ip-corp",
		Expression: "source_ip_in_range",
		Status:     domain.ConditionStatusActive,
	}
	h := newEvaluateHandler(t, cond)

	// nil Context — the handler rejects before touching the service.
	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(cond.ID),
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── negative: malformed condition id → InvalidArgument (id.Validate) ──────

func TestEvaluate_MalformedConditionID_InvalidArgument(t *testing.T) {
	h := newEvaluateHandler(t)

	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: "NOT-A-CND-ID!!",
		Context:     mustStruct(t, map[string]any{}),
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
