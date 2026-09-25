// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_provider_unavailable_test.go — a failed provider-admin CreateOAuthClient on
// the async SAKeyService.Issue worker path must be reported to the client as a
// fail-closed codes.Unavailable (peer unreachable), NOT the opaque generic
// codes.Internal "internal worker error" the operations worker assigns to any
// UNRECOGNIZED (non-status) error.
//
// Regression for the live-stand defect: a mis-set / absent
// KANAME_HYDRA_ADMIN_URL made iam derive the public `https://<издатель>-admin.<domain>`
// (unresolvable in-cluster) → CreateOAuthClient failed → the plain
// `fmt.Errorf("%w: hydra create-client: %w", iamerr.ErrUnavailable, err)` was NOT a
// gRPC status, so the worker degraded it to codes.Internal "internal worker error"
// with NO log line — the reason the outage was undiagnosable. This locks:
//  1. the op error carries codes.Unavailable (not Internal / Unknown),
//  2. the wire message is opaque (no dial/URL/host text leak), and
//  3. the raw cause is logged at ERROR (observability).
package sa_keys

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/testsupport/logbuf"
)

// unavailableOAuthClientAdmin — CreateOAuthClient always fails (provider admin unreachable).
type unavailableOAuthClientAdmin struct{ err error }

func (u unavailableOAuthClientAdmin) CreateOAuthClient(context.Context, clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	return clients.HydraOAuthClient{}, u.err
}
func (u unavailableOAuthClientAdmin) DeleteOAuthClient(context.Context, string) error { return nil }

func TestIssue_ProviderCreateUnavailable_MapsToUnavailableAndLogs(t *testing.T) {
	// The cause is logged by the operation worker goroutine, and read here after
	// waitForOp. Ordering through the ops stub's mutex happens to cover that read
	// today (the log precedes MarkError); the synchronised buffer makes the probe
	// independent of that ordering instead of relying on it.
	buf := &logbuf.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelError}))

	// A realistic transport failure — the exact class the live stand produced
	// (public provider-admin host does not resolve in-cluster). Its text carries the
	// URL + dial detail that must NOT reach the wire.
	rawCause := errors.New(`Post "https://provider-admin.api.kacho.cloud/admin/clients": dial tcp: lookup provider-admin.api.kacho.cloud: no such host`)

	repo := &stubSAClientRepo{accountID: "acc00000000000000001"}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, unavailableOAuthClientAdmin{err: rawCause}, ops)
	u.WithLogger(logger)

	// No TrustedSubjects → private_key_jwt path (the path the newman
	// AUTHZGCP-SAKEY-SECRET-NOT-LEAKED case exercises).
	in := IssueInput{ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"}
	_, err := u.Execute(context.Background(), in)
	require.NoError(t, err, "Execute returns the started Operation synchronously; the failure lands in the async op")

	waitForOp(t, ops)

	require.NotNil(t, ops.lastErr, "async worker must record a terminal error")
	require.Equal(t, codes.Unavailable, codes.Code(ops.lastErr.Code),
		"a provider-admin peer failure is fail-closed UNAVAILABLE, never the opaque INTERNAL 'internal worker error'")

	// Opaque wire message — infra topology (URL/host/dial) must not leak.
	require.NotContains(t, ops.lastErr.Message, "no such host")
	require.NotContains(t, ops.lastErr.Message, "provider-admin.api.kacho.cloud")

	// Observability: the raw cause is logged (the gap that made the live outage
	// invisible — the worker never logged fn-errors).
	// Текст берётся у ПРОДУКТА дословно: его печатает
	// `IssueSAKeyUseCase.hydraUnavailable` в usecases.go. Имя поставщика уйдёт
	// отсюда тем же изменением, которым переименуется производственная строка,
	// и не раньше: проба обязана называть то, что печатает продукт.
	require.Contains(t, buf.String(), "hydra admin call failed")
	require.Contains(t, buf.String(), "no such host",
		"the raw cause must be logged so a provider-admin outage is diagnosable")

	// The mapping row must NOT have been persisted on a Hydra failure.
	require.False(t, repo.insertOK, "no DB row on a provider create-client failure")
}
