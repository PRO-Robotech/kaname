// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_resource_failsafe_integration_test.go — SEC-C group A fail-safe
// (A-07, A-08). These are the SEC-C RPC-contract tests demanded by
// system-design review C1: they prove the *RegisterResource intent* survives an
// FGA backend outage and a drainer-replica restart, and that a poison row never
// wedges the drainer. The transitive drainer chain is already covered by
// internal/clients/fga_applier_integration_test.go; here we drive it through the
// RegisterResource use-case (the SEC-C entry point) end-to-end.
//
//	A-07 SEC-C-A-07-FGA-DOWN-INTENT-PERSISTS:
//	  FGA-stub returns 5xx → RegisterResource STILL returns OK (intent committed
//	  to kacho_iam.fga_outbox in the writer-tx, independent of FGA reachability);
//	  the outbox row stays sent_at IS NULL with a growing attempt_count;
//	  a drainer-replica restart in the apply window does NOT lose the row (state
//	  lives in the DB, survives restart-on-rotate); once the stub recovers (200) the
//	  fresh replica drains it → sent_at IS NOT NULL, FGA-Check ALLOW.
//
//	A-08 SEC-C-A-08-POISON-ROW:
//	  a bug-shaped intent (FGA rejects as a validation error) is force-poisoned
//	  (attempt_count = MaxAttempts, last_error LIKE '%validation%', sent_at NULL)
//	  and a subsequent normal Register row STILL applies — the drainer is not
//	  wedged on the poison row.
//
// Skipped under `go test -short`.
package internal_iam_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// failableFGAStub is an in-memory OpenFGA client whose write path can be
// toggled to fail, modelling an FGA outage (5xx / network drop) or a per-tuple
// validation rejection (poison). It satisfies clients.RelationStore and reuses
// the same error vocabulary the production fga_applier.go classifies on
// (transient = raw 5xx text; permanent = "status 400 … validation_error").
type failableFGAStub struct {
	mu    sync.Mutex
	store map[string]struct{}

	// down, when set, makes WriteTuples return a transient 5xx-shaped error for
	// every tuple (drainer retries → row stays pending).
	down atomic.Bool

	// poisonObject, when non-empty, makes WriteTuples reject any tuple whose
	// Object equals it with a 400 validation-shaped error (drainer poisons it).
	poisonObject string
}

func newFailableFGAStub() *failableFGAStub {
	return &failableFGAStub{store: make(map[string]struct{}, 16)}
}

func fgaKey(u, r, o string) string { return u + "|" + r + "|" + o }

func (s *failableFGAStub) Check(_ context.Context, subject, relation, object string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.store[fgaKey(subject, relation, object)]
	return ok, nil
}

func (s *failableFGAStub) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	if s.down.Load() {
		// Transient outage — propagated raw → drainer classifies as retryable.
		return fmt.Errorf("openfga write: status 503: backend unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tuples {
		if s.poisonObject != "" && t.Object == s.poisonObject {
			// 400 validation-shaped → fga_applier maps to drainer.ErrPermanent.
			return fmt.Errorf("openfga write: status 400: validation_error: object type is undefined in the authorization model")
		}
		s.store[fgaKey(t.User, t.Relation, t.Object)] = struct{}{}
	}
	return nil
}

func (s *failableFGAStub) DeleteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tuples {
		delete(s.store, fgaKey(t.User, t.Relation, t.Object))
	}
	return nil
}

var _ clients.RelationStore = (*failableFGAStub)(nil)

// startFGADrainer wires the corelib drainer over the failable stub against the
// given pool with test-fast timings and returns a stop func that blocks until
// the drainer goroutine has exited (modelling a clean replica shutdown).
func startFGADrainer(t *testing.T, pool *pgxpool.Pool, stub *failableFGAStub) (stop func()) {
	t.Helper()
	logger := observability.NewSlogger(drainerLogWriter{t})
	d, err := drainer.New[clients.FGAOutboxEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.fga_outbox",
			Channel:      "kacho_iam_fga_outbox",
			BatchSize:    32,
			PollFallback: 500 * time.Millisecond, // fast poll for test stability
			MaxAttempts:  5,
			BackoffMin:   20 * time.Millisecond,
			BackoffMax:   200 * time.Millisecond,
			ApplyTimeout: 2 * time.Second,
		},
		clients.DecodeFGAOutboxEvent,
		clients.NewFGAApplier(stub),
		logger,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = d.Run(ctx); close(done) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("drainer did not exit within 3s of cancel")
		}
	}
}

// scopedOutbox reads back the single test tuple's outbox row state (scoped by
// object, so the migration-seeded fga_writer relation-tuples are excluded).
func scopedOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, object string) (sentNull bool, attempt int, lastErr *string, exists bool) {
	t.Helper()
	err := pool.QueryRow(ctx,
		`SELECT sent_at IS NULL, attempt_count, last_error
		   FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = $1
		  ORDER BY id DESC LIMIT 1`, object).
		Scan(&sentNull, &attempt, &lastErr)
	if err != nil {
		return false, 0, nil, false
	}
	return sentNull, attempt, lastErr, true
}

func TestRegisterResource_A07_FGADownIntentPersistsAcrossRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, kachopg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	uc := internaliam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
	)

	const (
		subject  = "project:prj-1"
		relation = "parent"
		object   = "vpc_network:enp00000000000000003"
	)

	stub := newFailableFGAStub()
	stub.down.Store(true) // FGA is DOWN before the intent is registered.

	// Replica #1.
	stop1 := startFGADrainer(t, pool, stub)

	// RegisterResource must succeed even though FGA is unreachable: the intent
	// is committed to fga_outbox in the writer-tx, independent of FGA.
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: subject, Relation: relation, Object: object,
	}), "RegisterResource must return OK while FGA is down — intent is not lost")

	// The row stays pending (sent_at NULL) and attempt_count grows as the
	// drainer keeps retrying the 5xx-failing apply.
	require.Eventually(t, func() bool {
		sentNull, attempt, lastErr, ok := scopedOutbox(t, ctx, pool, object)
		return ok && sentNull && attempt >= 2 && lastErr != nil && strings.Contains(*lastErr, "503")
	}, 5*time.Second, 100*time.Millisecond,
		"intent must stay pending with a growing attempt_count + transient last_error while FGA is down")

	// Restart the replica IN THE APPLY WINDOW (restart-on-rotate). State is
	// in the DB, not memory: the row must survive the restart.
	stop1()
	sentNull, _, _, ok := scopedOutbox(t, ctx, pool, object)
	require.True(t, ok, "outbox row must survive the drainer-replica restart (state in DB)")
	require.True(t, sentNull, "row still unapplied after restart (FGA still down)")

	// Replica #2 takes over; FGA recovers → the fresh replica drains the row.
	stop2 := startFGADrainer(t, pool, stub)
	defer stop2()
	stub.down.Store(false) // FGA back up (200).

	require.Eventually(t, func() bool {
		sentNull, _, _, ok := scopedOutbox(t, ctx, pool, object)
		return ok && !sentNull
	}, 6*time.Second, 100*time.Millisecond,
		"after FGA recovery the new replica must apply the surviving intent (sent_at NOT NULL)")

	// FGA-Check now ALLOWs the owner-tuple (intent eventually applied; DENY
	// window finite and closed).
	allowed, cerr := stub.Check(ctx, subject, relation, object)
	require.NoError(t, cerr)
	require.True(t, allowed, "owner-tuple must be present in FGA after recovery")
}

func TestRegisterResource_A08_PoisonRowDoesNotWedgeDrainer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, kachopg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	uc := internaliam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
	)

	const (
		poisonObject = "undefined_type:bug00000000000000001"
		goodObject   = "vpc_network:enp00000000000000004"
	)

	stub := newFailableFGAStub()
	stub.poisonObject = poisonObject // FGA rejects this object as a validation error.

	stop := startFGADrainer(t, pool, stub)
	defer stop()

	// Force-poison: a bug-shaped intent that FGA will reject as a validation
	// error. A-08 models this via the RegisterResource use-case (the relay is
	// generic — a malformed owner-type slips past the FGA-string syntax check
	// but is rejected by the FGA authorization model).
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: poisonObject,
	}))

	// The poison row is force-poisoned: attempt_count == MaxAttempts (5),
	// last_error mentions the validation error, sent_at stays NULL — it is NOT
	// retried forever.
	require.Eventually(t, func() bool {
		sentNull, attempt, lastErr, ok := scopedOutbox(t, ctx, pool, poisonObject)
		return ok && sentNull && attempt >= 5 &&
			lastErr != nil && strings.Contains(strings.ToLower(*lastErr), "validation")
	}, 5*time.Second, 100*time.Millisecond,
		"poison row must be force-poisoned (attempt_count=MaxAttempts, validation last_error), not retried forever")

	// A subsequent NORMAL register still applies — the drainer is not wedged on
	// the poison row.
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: goodObject,
	}))
	require.Eventually(t, func() bool {
		sentNull, _, _, ok := scopedOutbox(t, ctx, pool, goodObject)
		return ok && !sentNull
	}, 5*time.Second, 100*time.Millisecond,
		"normal register after a poison row must still apply — drainer not wedged")

	allowed, cerr := stub.Check(ctx, "project:prj-1", "parent", goodObject)
	require.NoError(t, cerr)
	assert.True(t, allowed, "good owner-tuple applied past the poison row")
}

// drainerLogWriter adapts t.Log into io.Writer for observability.NewSlogger.
type drainerLogWriter struct{ t *testing.T }

func (w drainerLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
