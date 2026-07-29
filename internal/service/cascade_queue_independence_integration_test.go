// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cascade_queue_independence_integration_test.go — the property the recorded
// three-tier super-access decision actually asks for.
//
// The decision (.claude/rules/security.md, "Три уровня супер-доступа") chose a
// cascade over per-object materialization on ONE argument: the emergency path.
// If the top tiers were materialized, then with a lagging or broken pipeline the
// person who has to repair the platform would himself be locked out — precisely
// when he is needed. The words are "resolves at request time and works ALWAYS,
// regardless of the state of the pipeline".
//
// Every existing lock on that cascade (authzmap/super_admin_cascade_test.go,
// authzmap/account_owner_structural_test.go) seeds the structural pointer as a
// STORED tuple and then asks whether the derivation fires. That proves the shape
// of the model. It cannot fail on the defect these tests exist for, because the
// pointer is exactly the thing the pipeline delivers: the model derives
// `super_admin` over `account`/`project`/`cluster` parent-pointers, and every one
// of those tuples reaches OpenFGA only through the at-least-once outbox
// (access_binding/tuples.go::hierarchyParentTuple → EmitRelationWrite →
// fga_outbox → drainer; same for the account/project/group/role/service_account
// create paths). So the cascade was as materialized as the flat index it was
// chosen over — just materialized one indirection further out.
//
// These tests therefore put the pipeline in the ONLY state that distinguishes
// the two designs: the rows are committed in iam's database and the drainer has
// delivered NOTHING for them. A cascade that is genuinely request-time resolves
// anyway. A cascade that is secretly materialized denies.
//
// Real OpenFGA (canonical fga_model.fga) + real Postgres. Skipped under -short.

package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

const ciClusterObject = "cluster:cluster_kacho_root"

// ciVerbs — the closed CRUD verb set every verb-bearing type declares.
var ciVerbs = []string{"v_get", "v_list", "v_create", "v_update", "v_delete"}

// ciWorld bundles the committed iam state with the authorization service under
// test. Ids are literal (not ids.NewID) so a failure message names the row it is
// about.
type ciWorld struct {
	pool    *pgxpool.Pool
	svc     *service.AuthorizeService
	harness *fgatest.Harness
}

// newCIWorld boots real OpenFGA + real Postgres and builds the AuthorizeService
// exactly as cmd/kacho-iam/wiring.go does, plus the structural-fact resolver.
func newCIWorld(t *testing.T) *ciWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA + real-Postgres integration test in -short mode")
	}
	h := fgatest.New(t)
	dsn := kachopg.NewTestPostgres(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kachopg.New(pool, nil)

	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           h.Client,
		ModelID:             h.Client.AuthorizationModel,
		ClusterAdminChecker: h.Client,
		StructuralFacts:     authzcascade.New(repo),
	})
	return &ciWorld{pool: pool, svc: svc, harness: h}
}

func (w *ciWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	_, err := w.pool.Exec(context.Background(), sql, args...)
	require.NoError(t, err, "seed: %s", sql)
}

// seedAccountWithOwner / seedUser / seedRole / seedBinding / seedProject write the
// COMMITTED rows and nothing else. No tuple is written for any of them — that is
// the whole point of these tests.
//
// users.account_id → accounts.id and accounts.owner_user_id → users.id are a
// mutual pair; only the latter is DEFERRABLE INITIALLY DEFERRED, so the founding
// account and its owner must land in ONE transaction (exactly as production's
// account-create does).
func (w *ciWorld) seedAccountWithOwner(t *testing.T, accountID, ownerUserID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`,
		accountID, ownerUserID)
	require.NoError(t, err, "seed account %s", accountID)
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	                       VALUES ($1, $1, $1 || '@example.test', $2)`, ownerUserID, accountID)
	require.NoError(t, err, "seed owner %s", ownerUserID)
	require.NoError(t, tx.Commit(ctx))
}

func (w *ciWorld) seedUser(t *testing.T, id, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	           VALUES ($1, $1, $1 || '@example.test', $2)`, id, accountID)
}

// seedRole — an account-scoped custom role. `name` must satisfy
// roles_custom_name_check (`^[a-z][a-z0-9_]{0,40}$`), so it is derived from the id
// rather than being the id.
func (w *ciWorld) seedRole(t *testing.T, id, accountID string) {
	t.Helper()
	name := strings.ReplaceAll(id, "-", "_")
	w.exec(t, `INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
	           VALUES ($1, $2, $3, '["vpc.network.all.get"]'::jsonb)`, id, accountID, name)
}

func (w *ciWorld) seedBinding(t *testing.T, id, subjectID, roleID, resourceType, resourceID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.access_bindings
	             (id, subject_type, subject_id, role_id, resource_type, resource_id)
	           VALUES ($1, 'user', $2, $3, $4, $5)`, id, subjectID, roleID, resourceType, resourceID)
}

func (w *ciWorld) seedProject(t *testing.T, id, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $1)`, id, accountID)
}

func (w *ciWorld) allowed(t *testing.T, subject, relation, object string) bool {
	t.Helper()
	res, err := w.svc.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject:  subject,
		Relation: relation,
		Object:   object,
	})
	require.NoError(t, err, "CheckRelation must not error (%s %s %s)", subject, relation, object)
	return res.Allowed
}

// TestAccountAdminRevokesForeignGrantWhileQueueHasNotDelivered — level 3, the
// exact shape of the 2026-07-26 incident: a colleague granted access and left,
// and the administrator must be able to revoke it.
//
// The binding row is committed. Its parent-pointer has NOT been delivered — the
// state every freshly created binding is in for the whole delivery window, and
// the state a wedged partition stays in indefinitely.
func TestAccountAdminRevokesForeignGrantWhileQueueHasNotDelivered(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc      = "acc-ciqueue1"
		owner    = "usr-ciqueueown1"
		accAdmin = "usr-ciqueueadm1"
		stranger = "usr-ciqueuestr1"
		grantee  = "usr-ciqueuegrantee1"
		role     = "rol-ciqueue1"
		binding  = "abn-ciqueue1"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, accAdmin, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, grantee, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "account", acc)

	// The ONLY tuple in the store: the account administrator's own delegation.
	// It is a GRANT, not a structural pointer — it was made long before the
	// emergency and is not what this test withholds.
	w.harness.Write(t, "user:"+accAdmin, "admin", "account:"+acc)

	// The binding's parent-pointer `account:<A> # account @ iam_access_binding:<B>`
	// is deliberately ABSENT: the drainer has not delivered it.
	for _, verb := range ciVerbs {
		require.True(t, w.allowed(t, "user:"+accAdmin, verb, "iam_access_binding:"+binding),
			"level 3 (account administrator) must hold %s on a binding in his own account "+
				"while the queue has not delivered the binding's parent-pointer", verb)
	}

	// Narrowing still works — the fix must not turn the cascade into a pass.
	for _, verb := range ciVerbs {
		require.False(t, w.allowed(t, "user:"+stranger, verb, "iam_access_binding:"+binding),
			"a member of the same account WITHOUT the admin delegation must stay denied on %s", verb)
	}
	require.False(t, w.allowed(t, "user:"+grantee, "v_delete", "iam_access_binding:"+binding),
		"the binding's own SUBJECT is not thereby its administrator")
}

// TestRevokedBindingStaysManageableAndGrantsNothing — the direction a reader is
// most likely to "fix" wrongly, asserted so that it can actually fail.
//
// A revoked binding keeps its row (only Delete removes it), and the projection is
// deliberately status-independent, so the account administrator still reaches the
// binding OBJECT: a revoked grant is a record that has to remain readable and
// deletable, and filtering it out here would take that away exactly when the queue is
// behind — the same lockout this branch exists to remove, in the other direction.
//
// What must NOT come back is the grant. To make that a real assertion rather than a
// tautology, this test first PUTS the grant in the store — the scope-object verb tuples
// the reconciler materializes, plus the delivered parent pointer — proves the grantee
// has access, then does what revoke does (delete the emitted set, keep the row) and
// proves the access is gone. Without the fixture being live first, "denied afterwards"
// would hold even if the resolver re-armed everything, because there would have been
// nothing to re-arm.
func TestRevokedBindingStaysManageableAndGrantsNothing(t *testing.T) {
	w := newCIWorld(t)
	ctx := context.Background()

	const (
		acc      = "acc-ciqueue6"
		owner    = "usr-ciqueueown6"
		accAdmin = "usr-ciqueueadm6"
		grantee  = "usr-ciqueuegrantee6"
		role     = "rol-ciqueue6"
		binding  = "abn-ciqueue6"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, accAdmin, acc)
	w.seedUser(t, grantee, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "account", acc)

	w.harness.Write(t, "user:"+accAdmin, "admin", "account:"+acc)

	// The queue has delivered everything this ACTIVE binding emits: the grantee's
	// per-object verbs on the scope, and the binding's parent pointer.
	emitted := make([]clients.RelationTuple, 0, len(ciVerbs)+1)
	for _, verb := range ciVerbs {
		w.harness.Write(t, "user:"+grantee, verb, "account:"+acc)
		emitted = append(emitted, clients.RelationTuple{
			User: "user:" + grantee, Relation: verb, Object: "account:" + acc})
	}
	w.harness.Write(t, "account:"+acc, "account", "iam_access_binding:"+binding)
	emitted = append(emitted, clients.RelationTuple{
		User: "account:" + acc, Relation: "account", Object: "iam_access_binding:" + binding})

	// Premise: the grant is live. If this fails the rest proves nothing.
	for _, verb := range ciVerbs {
		require.True(t, w.allowed(t, "user:"+grantee, verb, "account:"+acc),
			"premise: the ACTIVE binding's %s must be in force before revoking it", verb)
	}

	// Revoke, exactly as doRevoke does it: the row survives with status REVOKED and the
	// emitted set is removed from the store.
	w.exec(t, `UPDATE kacho_iam.access_bindings
	              SET status = 'REVOKED', revoked_at = now(), revoked_by_user_id = $2
	            WHERE id = $1`, binding, accAdmin)
	require.NoError(t, w.harness.Client.DeleteTuples(ctx, emitted))

	// The grant is gone and nothing supplied at request time may bring it back: what
	// the grantee held were tuples on the SCOPE object, and the resolver projects
	// parent pointers and the account owner, never a grant on a scope.
	for _, verb := range ciVerbs {
		require.False(t, w.allowed(t, "user:"+grantee, verb, "account:"+acc),
			"revocation must stay revoked: the grantee must hold no %s on the scope after "+
				"the emitted set is removed, even though the binding row survives", verb)
	}

	// The record itself stays manageable, over a pointer the store no longer has.
	require.True(t, w.allowed(t, "user:"+accAdmin, "v_delete", "iam_access_binding:"+binding),
		"a revoked binding must stay manageable by the account administrator — its parent "+
			"pointer was deleted with the emitted set, so this can only resolve from the row")
}

// TestForeignAccountAdminIsNotAdminHere — the injected structural fact is the
// account the row actually names, so an administrator of a DIFFERENT account
// gains nothing from it.
func TestForeignAccountAdminIsNotAdminHere(t *testing.T) {
	w := newCIWorld(t)

	const (
		accA     = "acc-ciqueue2a"
		accB     = "acc-ciqueue2b"
		ownerA   = "usr-ciqueueown2a"
		ownerB   = "usr-ciqueueown2b"
		admB     = "usr-ciqueueadm2b"
		grantee  = "usr-ciqueuegrantee2"
		roleA    = "rol-ciqueue2a"
		bindingA = "abn-ciqueue2a"
	)
	w.seedAccountWithOwner(t, accA, ownerA)
	w.seedAccountWithOwner(t, accB, ownerB)
	w.seedUser(t, admB, accB)
	w.seedUser(t, grantee, accA)
	w.seedRole(t, roleA, accA)
	w.seedBinding(t, bindingA, grantee, roleA, "account", accA)

	w.harness.Write(t, "user:"+admB, "admin", "account:"+accB)

	for _, verb := range ciVerbs {
		require.False(t, w.allowed(t, "user:"+admB, verb, "iam_access_binding:"+bindingA),
			"administrator of account B must not reach a binding scoped to account A (%s)", verb)
	}
}

// TestProjectScopedBindingReachesTheAccountAdminWhileQueueHasNotDelivered —
// a project-scoped binding cascades through TWO structural pointers
// (`super_admin from project` on the binding, then `admin from account` on the
// project). Both are queue-delivered, so both must be derivable from committed
// rows.
func TestProjectScopedBindingReachesTheAccountAdminWhileQueueHasNotDelivered(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc      = "acc-ciqueue3"
		owner    = "usr-ciqueueown3"
		accAdmin = "usr-ciqueueadm3"
		grantee  = "usr-ciqueuegrantee3"
		prj      = "prj-ciqueue3"
		role     = "rol-ciqueue3"
		binding  = "abn-ciqueue3"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, accAdmin, acc)
	w.seedUser(t, grantee, acc)
	w.seedProject(t, prj, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "project", prj)

	w.harness.Write(t, "user:"+accAdmin, "admin", "account:"+acc)

	require.True(t, w.allowed(t, "user:"+accAdmin, "v_delete", "iam_access_binding:"+binding),
		"level 3 must reach a PROJECT-scoped binding of his own account through both "+
			"undelivered pointers (binding→project and project→account)")
}

// TestAccountOwnerCanDeleteHisAccountWhileQueueHasNotDelivered — the owner
// refinement, verbatim: "an account is created by self-service, so tearing it
// down must be as reliable as creating it". The model reads `account.v_delete:
// … or owner`, and its comment states that right "holds the instant the account
// exists and never waits for the reconciler to materialize the owner binding".
//
// The `owner` tuple is itself queue-delivered (account/create.go ownerTuples →
// fga_outbox), so before this change the claim was false for exactly as long as
// the delivery window lasts.
func TestAccountOwnerCanDeleteHisAccountWhileQueueHasNotDelivered(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc      = "acc-ciqueue4"
		owner    = "usr-ciqueueown4"
		outsider = "usr-ciqueueout4"
		delegate = "usr-ciqueuedel4"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, outsider, acc)
	w.seedUser(t, delegate, acc)

	// Nothing at all is in the store. The account was just created.
	for _, verb := range ciVerbs {
		require.True(t, w.allowed(t, "user:"+owner, verb, "account:"+acc),
			"the account owner must hold %s on his own account the instant the row exists", verb)
	}
	for _, verb := range ciVerbs {
		require.False(t, w.allowed(t, "user:"+outsider, verb, "account:"+acc),
			"a non-owner must not reach the account object (%s)", verb)
	}

	// The boundary the levels are written with: the DELEGATED account administrator
	// cascades WITHIN the account and never onto the account itself — tearing down
	// the tenancy stays with its owner and with the cloud. Supplying the account's
	// structural facts at request time must not blur that: `account`'s verbs read
	// `owner` and `super_admin`, never the `admin` tier, and this holds it.
	w.harness.Write(t, "user:"+delegate, "admin", "account:"+acc)
	for _, verb := range ciVerbs {
		require.False(t, w.allowed(t, "user:"+delegate, verb, "account:"+acc),
			"the delegated account administrator must not reach the account object itself (%s)", verb)
	}
	// He is nevertheless an administrator INSIDE the account.
	w.seedRole(t, "rol-ciqueue4", acc)
	w.seedBinding(t, "abn-ciqueue4", outsider, "rol-ciqueue4", "account", acc)
	require.True(t, w.allowed(t, "user:"+delegate, "v_delete", "iam_access_binding:abn-ciqueue4"),
		"the delegated account administrator must reach a grant inside his account")
}

// TestCloudAdministratorAlreadyIndependentOfTheQueue — level 1 is the tier the
// emergency argument is actually about, and it was ALREADY queue-independent
// before this change: authorize_service resolves it with a flat super-gate Check
// on the cluster singleton (authzguard.SubjectIsClusterAdmin), which reads a
// GRANT and no structural pointer. This test is a control, not a fix: it is
// green both before and after, and it records why the emergency path the decision
// was written for was not in fact the broken one.
func TestCloudAdministratorAlreadyIndependentOfTheQueue(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-ciqueue5"
		owner      = "usr-ciqueueown5"
		cloudAdmin = "usr-ciqueuecloud5"
		grantee    = "usr-ciqueuegrantee5"
		role       = "rol-ciqueue5"
		binding    = "abn-ciqueue5"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, cloudAdmin, acc)
	w.seedUser(t, grantee, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "account", acc)

	w.harness.Write(t, "user:"+cloudAdmin, "system_admin", ciClusterObject)

	require.True(t, w.allowed(t, "user:"+cloudAdmin, "v_delete", "iam_access_binding:"+binding),
		"level 1 must reach any binding with no structural pointer delivered")
	require.True(t, w.allowed(t, "user:"+cloudAdmin, "v_delete", "vpc_network:net-ciqueue5"),
		"level 1 must reach an object iam does not even own")
}
