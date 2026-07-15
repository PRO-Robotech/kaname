// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_test

// conditions_audit_outbox_integration_test.go — durable audit_outbox emit on
// ConditionsService CRUD (Create / Update / Delete), atomically with the
// conditions-row mutation (worker-tx, ban #10).
//
// ConditionsService is the CEL conditional-authz overlay — its mutations are
// security-relevant (they widen/narrow access grants) and so must leave a durable
// compliance trail, exactly like the other mutations (AccessBinding /
// Account / Project / SA / Group / Role / SAKey / cluster-admin / session).
//
// Drives the real ConditionsCRUDService against a testcontainers Postgres (so the
// audit row INSERT actually hits the audit_outbox CHECK constraints). The audit
// row is emitted inside the SAME worker-tx as the condition mutation.
//
// Acceptance scenarios:
//   - Create emits exactly one iam.condition.created row — actor=verified
//     principal, conditionId/binding_id/expression carried.
//   - Update emits exactly one iam.condition.updated row + changed_fields.
//   - Delete emits exactly one iam.condition.deleted row, atomic with hard-delete.
//   - rollback-no-orphan: a worker-tx that fails to commit (Insert conflict)
//     leaves neither the condition row nor the audit row.
//   - 22-char id regression-guard: id matches ^evt_…{20,30}$.
//   - no-secrets: the serialized payload contains no secret marker.
//   - anti-spoofing actor: actor is the verified principal, never a body value.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

var condEvtIDRe = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

// setupCondAuditDB spins up a Postgres 16 testcontainer, runs the IAM migrations
// and returns a DSN whose search_path defaults to kacho_iam.
func setupCondAuditDB(t testing.TB) string {
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
	require.NoError(t, goose.Up(db, "."))

	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "options=") || strings.Contains(dsn, "options%3D") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + optionsParam
}

// allowAllRelations — permissive authzguard.RelationChecker for the audit tests,
// which exercise the CRUD audit-emit path, not the authz gate (covered by the
// dedicated conditions/authz_test.go). Every Check allows, so the folder-scope
// authz gate passes and the mutation proceeds.
type allowAllRelations struct{}

func (allowAllRelations) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// buildCondSvc wires a real ConditionsCRUDService against the live pool with the
// durable audit emitter attached (mirrors SAKey buildIssueUC).
func buildCondSvc(pool *pgxpool.Pool) *service.ConditionsCRUDService {
	repo := kachopg.NewConditionsRepo(pool)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	eval := service.NewBuiltinEvaluator()
	svc := service.NewConditionsCRUDService(repo, opsRepo, eval)
	svc.WithRelationStore(allowAllRelations{})
	svc.WithAuditEmitter(kachopg.NewAuditOutboxEmitter(pool), kachopg.NewPoolTxBeginner(pool))
	return svc
}

type condAuditRow struct {
	id         string
	eventType  string
	status     string
	payload    map[string]any
	payloadRaw string
}

func condAuditRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, condID string) []condAuditRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT id, event_type, status, event_payload::text
		   FROM kacho_iam.audit_outbox
		  WHERE event_type = $1 AND event_payload->>'condition_id' = $2
		  ORDER BY created_at ASC`,
		eventType, condID)
	require.NoError(t, err)
	defer rows.Close()
	var out []condAuditRow
	for rows.Next() {
		var r condAuditRow
		require.NoError(t, rows.Scan(&r.id, &r.eventType, &r.status, &r.payloadRaw))
		require.NoError(t, json.Unmarshal([]byte(r.payloadRaw), &r.payload))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// awaitCondAudit polls audit_outbox until the row for (eventType, condID)
// appears — the ConditionsService CRUD is async (operations.Run worker).
func awaitCondAudit(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, condID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.audit_outbox
			  WHERE event_type = $1 AND event_payload->>'condition_id' = $2`,
			eventType, condID).Scan(&n))
		if n >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("audit row %s for condition %s never appeared", eventType, condID)
}

// awaitOpError polls the operations table until the given operation is Done and
// asserts it terminated in error (the expected duplicate-name rollback). This is
// the deterministic gate the rollback-no-orphan test needs — it replaces a fixed
// time.Sleep that could let the absence assertions run before the worker had even
// processed the operation (false GREEN).
func awaitOpError(ctx context.Context, t *testing.T, opsRepo operations.Repo, opID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		op, err := opsRepo.Get(ctx, opID)
		if err != nil || op == nil {
			return false
		}
		return op.Done
	}, 5*time.Second, 20*time.Millisecond, "operation %s never reached Done", opID)
	op, err := opsRepo.Get(ctx, opID)
	require.NoError(t, err)
	require.NotNil(t, op.Error,
		"duplicate-name Create must terminate the operation in error (23505 rollback), got success")
}

// awaitConditionStatus polls until the conditions row reaches the target status.
func awaitConditionStatus(ctx context.Context, t *testing.T, pool *pgxpool.Pool, condID, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var s string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM kacho_iam.conditions WHERE id = $1`, condID).Scan(&s); err != nil {
			return false
		}
		return s == want
	}, 5*time.Second, 20*time.Millisecond, "condition %s must reach status %s", condID, want)
}

func withCondPrincipal(ctx context.Context, userID string) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: userID})
}

func assertNoCondSecrets(t *testing.T, payloadRaw string) {
	t.Helper()
	for _, banned := range []string{
		"client_secret", "privateKey", "private_key", "BEGIN", "PRIVATE KEY",
		"access_token", "refresh_token", "password", "token",
	} {
		require.NotContains(t, payloadRaw, banned,
			"audit payload must not contain secret material (%q)", banned)
	}
}

// findCreatedCondID returns the id of the (single) ACTIVE/CREATING condition in
// the given folder — the Create RPC mints the id internally.
func findCreatedCondID(ctx context.Context, t *testing.T, pool *pgxpool.Pool, folderID string) string {
	t.Helper()
	var id string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.conditions WHERE folder_id = $1 AND status != 'DELETING' LIMIT 1`,
			folderID).Scan(&id) == nil
	}, 5*time.Second, 20*time.Millisecond, "created condition must persist")
	return id
}

// ── Create emits durable iam.condition.created ───────────────────────────────

func TestConditionsAudit_CreateEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	folderID := "prj_cond_create"
	svc := buildCondSvc(pool)

	op, err := svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		FolderID:   folderID,
		Name:       "ip-corp",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	condID := findCreatedCondID(ctx, t, pool, folderID)
	awaitCondAudit(ctx, t, pool, "iam.condition.created", condID)

	rows := condAuditRows(ctx, t, pool, "iam.condition.created", condID)
	require.Len(t, rows, 1, "Create must emit exactly one iam.condition.created row")
	r := rows[0]
	require.Equal(t, uid, r.payload["actor"], "actor is the verified principal")
	require.Equal(t, condID, r.payload["condition_id"])
	require.Equal(t, "non_expired", r.payload["expression_name"], "carries the CEL/builtin expression, not the resource name")
	require.Equal(t, "pending", r.status)
	require.Regexp(t, condEvtIDRe, r.id, "audit id must match the 22-char evt_ format (#126 guard)")
	assertNoCondSecrets(t, r.payloadRaw)
}

// ── Update emits durable iam.condition.updated + changed_fields ──────────────

func TestConditionsAudit_UpdateEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	folderID := "prj_cond_update"
	svc := buildCondSvc(pool)

	_, err = svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		FolderID:   folderID,
		Name:       "to-update",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	condID := findCreatedCondID(ctx, t, pool, folderID)
	awaitConditionStatus(ctx, t, pool, condID, "ACTIVE")

	newDesc := "patched description"
	_, err = svc.Update(withCondPrincipal(ctx, uid), service.UpdateConditionRequest{
		ID:          domain.ConditionID(condID),
		UpdateMask:  []string{"description"},
		Description: newDesc,
	})
	require.NoError(t, err)

	awaitCondAudit(ctx, t, pool, "iam.condition.updated", condID)
	rows := condAuditRows(ctx, t, pool, "iam.condition.updated", condID)
	require.Len(t, rows, 1, "Update must emit exactly one iam.condition.updated row")
	r := rows[0]
	require.Equal(t, uid, r.payload["actor"])
	require.Equal(t, condID, r.payload["condition_id"])
	cf, ok := r.payload["changed_fields"].([]any)
	require.True(t, ok, "changed_fields must be present")
	require.Contains(t, cf, "description")
	require.Regexp(t, condEvtIDRe, r.id)
	assertNoCondSecrets(t, r.payloadRaw)

	// commit-together: the description must actually be patched.
	var gotDesc string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT description FROM kacho_iam.conditions WHERE id = $1`, condID).Scan(&gotDesc))
	require.Equal(t, newDesc, gotDesc)
}

// ── Delete emits durable iam.condition.deleted, atomic with hard-delete ──────

func TestConditionsAudit_DeleteEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	folderID := "prj_cond_delete"
	svc := buildCondSvc(pool)

	_, err = svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		FolderID:   folderID,
		Name:       "to-delete",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	condID := findCreatedCondID(ctx, t, pool, folderID)
	awaitConditionStatus(ctx, t, pool, condID, "ACTIVE")

	_, err = svc.Delete(withCondPrincipal(ctx, uid), domain.ConditionID(condID))
	require.NoError(t, err)

	awaitCondAudit(ctx, t, pool, "iam.condition.deleted", condID)
	rows := condAuditRows(ctx, t, pool, "iam.condition.deleted", condID)
	require.Len(t, rows, 1, "Delete must emit exactly one iam.condition.deleted row")
	r := rows[0]
	require.Equal(t, uid, r.payload["actor"])
	require.Equal(t, condID, r.payload["condition_id"])
	require.Regexp(t, condEvtIDRe, r.id)
	assertNoCondSecrets(t, r.payloadRaw)

	// commit-together: the condition row must be gone alongside the committed
	// audit row (hard-delete).
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.conditions WHERE id = $1`, condID).Scan(&n))
	require.Equal(t, 0, n, "the deleted condition row must be gone (commit-together)")
}

// ── rollback-no-orphan: a Create whose Insert violates the folder+name unique
// index rolls back the whole worker-tx → neither condition nor audit row. ─────

func TestConditionsAudit_CreateRollbackNoOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	folderID := "prj_cond_rollback"
	svc := buildCondSvc(pool)

	// First Create succeeds.
	_, err = svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		FolderID:   folderID,
		Name:       "dup-name",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	firstID := findCreatedCondID(ctx, t, pool, folderID)
	awaitCondAudit(ctx, t, pool, "iam.condition.created", firstID)

	// Second Create with the SAME (folder, name) — the Insert hits
	// conditions_folder_name_uniq (23505) → the worker-tx rolls back. No second
	// condition row and no orphan audit row may exist.
	dupOp, err := svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		FolderID:   folderID,
		Name:       "dup-name",
		Expression: "non_expired",
	})
	require.NoError(t, err) // async — error surfaces on the Operation, not here
	require.NotNil(t, dupOp)

	// Deterministically gate on the SUBJECT operation reaching a terminal state
	// (Done) — the orphan-audit regression is produced DURING worker processing,
	// so asserting absence before the worker has processed the op would pass
	// vacuously. Poll the operation until Done and assert it terminated in error
	// (the 23505 duplicate), then run the absence assertions. No fixed sleep.
	awaitOpError(ctx, t, operations.NewRepo(pool, "kacho_iam"), dupOp.ID)

	var condCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.conditions WHERE folder_id = $1 AND name = 'dup-name' AND status != 'DELETING'`,
		folderID).Scan(&condCount))
	require.Equal(t, 1, condCount, "duplicate Create must not create a second condition row")

	var auditCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox WHERE event_type = 'iam.condition.created'`).Scan(&auditCount))
	require.Equal(t, 1, auditCount, "rolled-back Create must leave no orphan audit row (atomicity, запрет #10)")
}

// ── anti-spoofing: actor is the principal, never a body value ────────────────

func TestConditionsAudit_ActorFromPrincipal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	principal := ids.NewID(domain.PrefixUser)
	folderID := "prj_cond_actor"
	svc := buildCondSvc(pool)

	_, err = svc.Create(withCondPrincipal(ctx, principal), service.CreateConditionRequest{
		FolderID:   folderID,
		Name:       "actor-test",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	condID := findCreatedCondID(ctx, t, pool, folderID)
	awaitCondAudit(ctx, t, pool, "iam.condition.created", condID)

	rows := condAuditRows(ctx, t, pool, "iam.condition.created", condID)
	require.Len(t, rows, 1)
	require.Equal(t, principal, rows[0].payload["actor"],
		"actor must be the authenticated principal (PrincipalFromContext)")
}

// compile-time assertion that fmt is used (keeps import if helper edits shift).
var _ = fmt.Sprintf
