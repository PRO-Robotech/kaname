// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_hydra_unavailable_test.go — a failed Hydra-admin CreateOAuthClient on
// the async SAKeyService.Issue worker path must be reported to the client as a
// fail-closed codes.Unavailable (peer unreachable), NOT the opaque generic
// codes.Internal "internal worker error" the operations worker assigns to any
// UNRECOGNIZED (non-status) error.
//
// Regression for the live-stand defect: a mis-set / absent
// KACHO_IAM_HYDRA_ADMIN_URL made iam derive the public `https://hydra-admin.<domain>`
// (unresolvable in-cluster) → CreateOAuthClient failed → the plain
// `fmt.Errorf("%w: hydra create-client: %w", iamerr.ErrUnavailable, err)` was NOT a
// gRPC status, so the worker degraded it to codes.Internal "internal worker error"
// with NO log line — the reason the outage was undiagnosable. This locks:
//   1. the op error carries codes.Unavailable (not Internal / Unknown),
//   2. the wire message is opaque (no dial/URL/host text leak), and
//   3. the raw cause is logged at ERROR (observability).
package sa_keys

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// unavailableHydra — CreateOAuthClient always fails (Hydra admin unreachable).
type unavailableHydra struct{ err error }

func (u unavailableHydra) CreateOAuthClient(context.Context, clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	return clients.HydraOAuthClient{}, u.err
}
func (u unavailableHydra) DeleteOAuthClient(context.Context, string) error { return nil }

func TestIssue_HydraCreateUnavailable_MapsToUnavailableAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	// A realistic transport failure — the exact class the live stand produced
	// (public hydra-admin host does not resolve in-cluster). Its text carries the
	// URL + dial detail that must NOT reach the wire.
	rawCause := errors.New(`Post "https://hydra-admin.api.kacho.cloud/admin/clients": dial tcp: lookup hydra-admin.api.kacho.cloud: no such host`)

	repo := &stubSAClientRepo{accountID: "acc00000000000000001"}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, unavailableHydra{err: rawCause}, ops)
	u.WithLogger(logger)

	// No TrustedSubjects → private_key_jwt path (the path the newman
	// AUTHZGCP-SAKEY-SECRET-NOT-LEAKED case exercises).
	in := IssueInput{ServiceAccountID: "sva_test", CreatedByUserID: "usr_admin"}
	_, err := u.Execute(context.Background(), in)
	require.NoError(t, err, "Execute returns the started Operation synchronously; the failure lands in the async op")

	waitForOp(t, ops)

	require.NotNil(t, ops.lastErr, "async worker must record a terminal error")
	require.Equal(t, codes.Unavailable, codes.Code(ops.lastErr.Code),
		"a Hydra-admin peer failure is fail-closed UNAVAILABLE, never the opaque INTERNAL 'internal worker error'")

	// Opaque wire message — infra topology (URL/host/dial) must not leak.
	require.NotContains(t, ops.lastErr.Message, "no such host")
	require.NotContains(t, ops.lastErr.Message, "hydra-admin.api.kacho.cloud")

	// Observability: the raw cause is logged (the gap that made the live outage
	// invisible — the worker never logged fn-errors).
	require.Contains(t, buf.String(), "hydra admin call failed")
	require.Contains(t, buf.String(), "no such host",
		"the raw cause must be logged so a hydra-admin outage is diagnosable")

	// The mapping row must NOT have been persisted on a Hydra failure.
	require.False(t, repo.insertOK, "no DB row on hydra create-client failure")
}
