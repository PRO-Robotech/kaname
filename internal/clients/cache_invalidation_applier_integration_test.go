// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cache_invalidation_applier_integration_test.go — end-to-end tests for
// the subject-change push-drain pipeline (kacho-iam half):
//
//	INSERT subject_change_outbox row → LISTEN/NOTIFY → drainer claims →
//	  Decoder → Applier → bufconn fake InternalAuthzCacheServer
//
// Required schema (post-rollout) on subject_change_outbox:
//
//	event_type, payload, sent_at, attempt_count, last_error
//
// Coverage map:
//
//	TestIntegration_SingleEmit_EndToEnd            — single emit → applier RPC invoked end-to-end
//	TestIntegration_DrainerCatchUpOnRestart        — drainer restart picks up unsent rows
//	TestIntegration_LegacyRow_BackfilledAndDrained — legacy row backfilled by migration is drained
//	TestIntegration_AtomicRollback_NoLeak          — real-pg atomic emit + ROLLBACK → no outbox row leak
package clients_test

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	apigatewayv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/apigateway/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// ─────────────────────────────────────────────────────────────────────────────
// recordingAuthzCacheServer — bufconn-served fake InternalAuthzCacheService.
// Counts calls per subject; configurable canned reply per-call.
// ─────────────────────────────────────────────────────────────────────────────

type recordingAuthzCacheServer struct {
	apigatewayv1.UnimplementedInternalAuthzCacheServiceServer
	mu       sync.Mutex
	count    int64 // atomic — accessed from gRPC handler goroutines + test
	subjects []string
	replyErr error // nil → OK
}

func (s *recordingAuthzCacheServer) InvalidateSubject(
	_ context.Context, req *apigatewayv1.InvalidateSubjectRequest,
) (*emptypb.Empty, error) {
	atomic.AddInt64(&s.count, 1)
	s.mu.Lock()
	s.subjects = append(s.subjects, req.Subject)
	err := s.replyErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *recordingAuthzCacheServer) snapshotSubjects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.subjects))
	copy(out, s.subjects)
	return out
}

func (s *recordingAuthzCacheServer) callCount() int64 {
	return atomic.LoadInt64(&s.count)
}

// startBufconnServer — launches the recording server on an in-memory listener,
// returns a connected gRPC client + a stop func.
func startBufconnServer(t *testing.T, srv *recordingAuthzCacheServer) (apigatewayv1.InternalAuthzCacheServiceClient, func()) {
	t.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	gs := grpc.NewServer()
	apigatewayv1.RegisterInternalAuthzCacheServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.DialContext(context.Background(), "bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	return cli, func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// setupTestPGDrainer — boots Postgres-testcontainer + migrations + pool.
// Returns the pool (caller responsible for Close via t.Cleanup).
// ─────────────────────────────────────────────────────────────────────────────

func setupTestPGDrainer(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_iam_test"),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."),
		"goose Up must run — RED expectation: migration 0023 missing → goose error")

	// dsn already has ?sslmode=disable, so append search_path option with &.
	dsn += "&options=-c%20search_path%3Dkacho_iam%2Cpublic"
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// ─────────────────────────────────────────────────────────────────────────────
// single emit → applier RPC invoked end-to-end
// ─────────────────────────────────────────────────────────────────────────────

// TestIntegration_SingleEmit_EndToEnd — INSERT into
// subject_change_outbox triggers NOTIFY → drainer wakes → claims row →
// decodes payload → applies via fake gateway → row marked sent_at.
//
// End-to-end latency expectation: ≤ 1s (≥ 1 replica converges within < 1s of
// revoke commit).
func TestIntegration_SingleEmit_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := setupTestPGDrainer(t)

	fakeSrv := &recordingAuthzCacheServer{}
	cli, stop := startBufconnServer(t, fakeSrv)
	defer stop()

	d, err := drainer.New[clients.SubjectChangeEvent](
		pool,
		drainer.Config{
			Table:     "kacho_iam.subject_change_outbox",
			Channel:   "kacho_iam_subject_outbox_added",
			BatchSize: 16,
			// PollFallback well under the 1s delivery deadline so a NOTIFY that is
			// missed because the row was INSERTed before the drainer finished
			// installing its LISTEN is still drained by the periodic catch-up tick
			// within the assertion window — making delivery deterministic instead
			// of depending on a fixed "give drainer time to LISTEN" sleep.
			PollFallback: 250 * time.Millisecond,
			MaxAttempts:  5,
			BackoffMin:   100 * time.Millisecond,
			BackoffMax:   500 * time.Millisecond,
			ApplyTimeout: 2 * time.Second,
		},
		clients.DecodeSubjectChange,
		clients.NewSubjectChangeApplier(cli),
		nil,
	)
	require.NoError(t, err)

	drainerCtx, drainerCancel := context.WithCancel(ctx)
	defer drainerCancel()
	drainerDone := make(chan error, 1)
	go func() { drainerDone <- d.Run(drainerCtx) }()
	// No fixed "wait for LISTEN" sleep: the row is drained either by the NOTIFY
	// (if LISTEN is already installed), the drainer's startup catch-up scan, or
	// the sub-second PollFallback tick — the bounded delivery poll below is the
	// deterministic gate.

	// INSERT a post-rollout-shape row (payload populated).
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, event_type, payload)
		VALUES ('usr_w1_2_15', 'binding_delete', 'binding_revoke',
		        '{"subject_id":"usr_w1_2_15","op":"binding_delete","event_type":"binding_revoke","resource_type":"","resource_id":""}'::jsonb)`)
	require.NoError(t, err)

	// Wait up to 1s for drainer to deliver — the latency promise.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if fakeSrv.callCount() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.Equal(t, int64(1), fakeSrv.callCount(),
		"drainer must deliver row to gateway within 1s")
	subs := fakeSrv.snapshotSubjects()
	require.Len(t, subs, 1)
	assert.Equal(t, "user:usr_w1_2_15", subs[0])

	// Row marked sent_at.
	var sentAt *time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT sent_at FROM kacho_iam.subject_change_outbox WHERE subject_id='usr_w1_2_15'`).
		Scan(&sentAt))
	require.NotNil(t, sentAt, "row must be marked sent_at after successful apply")

	drainerCancel()
	select {
	case <-drainerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("drainer did not stop after cancel")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// legacy op-only row backfilled and drained
// ─────────────────────────────────────────────────────────────────────────────

// TestIntegration_LegacyRow_BackfilledAndDrained — legacy (op-only) row
// (op only) gets payload + event_type backfilled by migration 0023; drainer
// applies it correctly.
func TestIntegration_LegacyRow_BackfilledAndDrained(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := setupTestPGDrainer(t)

	// Migration 0023 has already run. Simulate a row that was inserted
	// the legacy (op-only) row by directly INSERTing then explicitly NULL'ing
	// the post-rollout-only columns; then run the migration's backfill UPDATE
	// over that subject_id. (We cannot literally insert pre-migration in
	// the same test process.)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.subject_change_outbox (subject_id, op)
		VALUES ('usr_w1_2_21_legacy', 'binding_delete')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE kacho_iam.subject_change_outbox
		   SET event_type = NULL, payload = NULL
		 WHERE subject_id='usr_w1_2_21_legacy'`)
	require.NoError(t, err)

	// Re-apply backfill (identical to migration 0023 SQL).
	_, err = pool.Exec(ctx, `
		UPDATE kacho_iam.subject_change_outbox
		   SET payload = jsonb_build_object(
		       'subject_id', subject_id,
		       'op',         op,
		       'event_type', COALESCE(event_type,
		                              CASE op
		                                  WHEN 'binding_delete' THEN 'binding_revoke'
		                                  WHEN 'binding_upsert' THEN 'binding_grant'
		                                  ELSE op
		                              END),
		       'resource_type', COALESCE(resource_type, ''),
		       'resource_id',   COALESCE(resource_id,   '')
		   ),
		   event_type = COALESCE(event_type, CASE op
		       WHEN 'binding_delete' THEN 'binding_revoke'
		       WHEN 'binding_upsert' THEN 'binding_grant'
		       ELSE op
		   END)
		 WHERE subject_id='usr_w1_2_21_legacy' AND payload IS NULL`)
	require.NoError(t, err)

	fakeSrv := &recordingAuthzCacheServer{}
	cli, stop := startBufconnServer(t, fakeSrv)
	defer stop()

	d, err := drainer.New[clients.SubjectChangeEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.subject_change_outbox",
			Channel:      "kacho_iam_subject_outbox_added",
			BatchSize:    16,
			PollFallback: 2 * time.Second, // tighter poll for legacy row catch-up
			MaxAttempts:  5,
			BackoffMin:   100 * time.Millisecond,
			BackoffMax:   500 * time.Millisecond,
			ApplyTimeout: 2 * time.Second,
		},
		clients.DecodeSubjectChange,
		clients.NewSubjectChangeApplier(cli),
		nil,
	)
	require.NoError(t, err)

	drainerCtx, drainerCancel := context.WithCancel(ctx)
	defer drainerCancel()
	go func() { _ = d.Run(drainerCtx) }()

	// Allow catch-up: NOTIFY may have missed this row (inserted before LISTEN),
	// but startup catch-up SELECT picks it up.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fakeSrv.callCount() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, int64(1), fakeSrv.callCount(),
		"drainer must catch up & deliver legacy row at startup")
	subs := fakeSrv.snapshotSubjects()
	assert.Equal(t, "user:usr_w1_2_21_legacy", subs[0])
}

// ─────────────────────────────────────────────────────────────────────────────
// real-pg atomic emit + ROLLBACK → outbox row NOT visible
// ─────────────────────────────────────────────────────────────────────────────

// TestIntegration_AtomicRollback_NoLeak — force a real ROLLBACK
// after an in-tx INSERT (mimicking the EmitSubjectChangeEvent code path
// that JIT.Deny / BG.Deny / their expirer workers will use). The outbox
// row MUST NOT be visible to drainer (atomicity per ban #10).
//
// Difference from the writer-level rollback test in
// subject_change_repo_w1_2_test.go: that one uses Writer.Rollback at the
// repo abstraction. THIS one uses raw pgx.Tx → tx.Rollback to prove
// DB-level atomicity (no special test seam).
func TestIntegration_AtomicRollback_NoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := setupTestPGDrainer(t)

	fakeSrv := &recordingAuthzCacheServer{}
	cli, stop := startBufconnServer(t, fakeSrv)
	defer stop()

	d, err := drainer.New[clients.SubjectChangeEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.subject_change_outbox",
			Channel:      "kacho_iam_subject_outbox_added",
			BatchSize:    16,
			PollFallback: 1 * time.Second,
			MaxAttempts:  3,
			BackoffMin:   100 * time.Millisecond,
			BackoffMax:   200 * time.Millisecond,
			ApplyTimeout: 1 * time.Second,
		},
		clients.DecodeSubjectChange,
		clients.NewSubjectChangeApplier(cli),
		nil,
	)
	require.NoError(t, err)

	drainerCtx, drainerCancel := context.WithCancel(ctx)
	defer drainerCancel()
	go func() { _ = d.Run(drainerCtx) }()
	// No fixed "wait for LISTEN" sleep: the post-rollback sentinel row below is a
	// committed barrier drained via NOTIFY / startup catch-up / the 1s
	// PollFallback tick, which deterministically proves a full drain cycle
	// elapsed past the rolled-back INSERT.

	// Open real pgx.Tx, INSERT, ROLLBACK.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, event_type, payload)
		VALUES ('usr_w1_2_22_rollback', 'jit_revoke', 'jit_revoke',
		        '{"subject_id":"usr_w1_2_22_rollback","op":"jit_revoke","event_type":"jit_revoke","resource_type":"","resource_id":""}'::jsonb)`)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx), "force rollback must succeed")

	// Deterministic barrier (replaces a fixed 1500ms sleep): AFTER the rollback,
	// COMMIT a sentinel outbox row and block until the drainer delivers it. That
	// the drainer processed a row committed AFTER the rollback proves at least one
	// full poll/notify cycle elapsed past the rolled-back INSERT — so if the
	// rolled-back row were ever going to be (incorrectly) visible, it would have
	// been delivered by now. The negative assertions below then fire on a proven
	// post-rollback cycle, not on wall-clock luck.
	// Use a deliverable (binding_delete/binding_revoke) shape for the sentinel so
	// the drainer applies it and calls the fake gateway — a positive completion
	// signal (the rolled-back row's op is irrelevant to the atomicity assertion).
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, event_type, payload)
		VALUES ('usr_w1_2_22_sentinel', 'binding_delete', 'binding_revoke',
		        '{"subject_id":"usr_w1_2_22_sentinel","op":"binding_delete","event_type":"binding_revoke","resource_type":"","resource_id":""}'::jsonb)`)
	require.NoError(t, err)

	// The applier delivers subjects prefixed as "user:<id>" (see the happy-path
	// assertion earlier in this file).
	require.Eventually(t, func() bool {
		for _, s := range fakeSrv.snapshotSubjects() {
			if s == "user:usr_w1_2_22_sentinel" {
				return true
			}
		}
		return false
	}, 10*time.Second, 20*time.Millisecond, "sentinel row must be delivered by the drainer")

	// The rolled-back subject must NEVER have been delivered (DB-level atomicity:
	// uncommitted rows are invisible to the drainer).
	for _, s := range fakeSrv.snapshotSubjects() {
		assert.NotEqual(t, "user:usr_w1_2_22_rollback", s,
			"rolled-back INSERT must not be visible to drainer (DB-level atomicity)")
	}

	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.subject_change_outbox
		  WHERE subject_id='usr_w1_2_22_rollback'`).Scan(&cnt))
	assert.Equal(t, 0, cnt, "row absent from table after rollback")
}
