// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// conditions_evaluate_service_integration_test.go — Wave Q test-debt
// (relates #122): testcontainers Postgres coverage for the
// ConditionsService.Evaluate path end-to-end through the SERVICE wrapper +
// gRPC handler.
//
// The raw evaluator (BuiltinEvaluator) and the ConditionsRepo SQL side are
// covered elsewhere; what was previously untested is the wired path:
//
//	handler.Evaluate → ConditionsCRUDService.Evaluate → real ConditionsRepo.Get
//	(Postgres) → BuiltinEvaluator → EvaluateConditionResponse.
//
// This is the request-time CEL evaluation admin RPC. Evaluate is a synchronous
// read-path RPC (no Operation), so no operations worker is needed.
//
// Coverage:
//   - happy: a stored source_ip_in_range condition evaluates true with an
//     in-range client_ip drawn from the live DB row's expression.
//   - happy(false): same condition denies an out-of-range client_ip.
//   - negative: well-formed-but-absent condition id → NotFound (repo.Get).
//   - negative: missing request context → InvalidArgument (handler guard).
//
// Run: `make test` or the targeted go test with Docker available. Skipped
// under `testing.Short()`.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	condhandler "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/conditions"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

func newEvaluateStructIE(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

// setupEvaluateHandler builds the real wiring (PG repo + BuiltinEvaluator)
// behind the ConditionsService gRPC handler and seeds one ACTIVE condition.
func setupEvaluateHandler(t *testing.T) (*condhandler.Handler, domain.ConditionID) {
	t.Helper()
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)
	id := domain.ConditionID(ids.NewID(domain.PrefixConditionResource))
	seeded, err := repo.Insert(ctx, domain.Condition{
		ID:         id,
		FolderID:   "fld_evalsvc",
		Name:       "ip-corp",
		Expression: "source_ip_in_range",
		Status:     domain.ConditionStatusCreating,
	})
	require.NoError(t, err)
	require.NoError(t, repo.SetStatus(ctx, seeded.ID, domain.ConditionStatusActive))

	// Evaluate never creates an Operation; ops repo is unused on this path.
	svc := service.NewConditionsCRUDService(repo, nil, service.NewBuiltinEvaluator())
	return condhandler.NewHandler(svc), seeded.ID
}

func TestEvaluateService_IamExt_SourceIPInRange_Allowed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	h, id := setupEvaluateHandler(t)

	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(id),
		Context:     newEvaluateStructIE(t, map[string]any{"client_ip": "10.0.0.5"}),
		Params:      newEvaluateStructIE(t, map[string]any{"allowed_cidrs": []any{"10.0.0.0/24"}}),
	})
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	require.NotNil(t, resp.GetEvaluatedAt())
	// api-conventions: evaluatedAt truncated to whole seconds.
	assert.Zero(t, resp.GetEvaluatedAt().AsTime().Nanosecond())
}

func TestEvaluateService_IamExt_SourceIPInRange_Denied(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h, id := setupEvaluateHandler(t)

	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(id),
		Context:     newEvaluateStructIE(t, map[string]any{"client_ip": "192.168.99.99"}),
		Params:      newEvaluateStructIE(t, map[string]any{"allowed_cidrs": []any{"10.0.0.0/24"}}),
	})
	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
}

func TestEvaluateService_IamExt_UnknownCondition_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h, _ := setupEvaluateHandler(t)

	// Well-formed but absent id → repo.Get tombstone/miss → NotFound.
	absent := domain.ConditionID(ids.NewID(domain.PrefixConditionResource))
	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(absent),
		Context:     newEvaluateStructIE(t, map[string]any{}),
	})
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestEvaluateService_IamExt_MissingContext_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h, id := setupEvaluateHandler(t)

	resp, err := h.Evaluate(context.Background(), &iamv1.EvaluateConditionRequest{
		ConditionId: string(id),
		// Context omitted.
	})
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
