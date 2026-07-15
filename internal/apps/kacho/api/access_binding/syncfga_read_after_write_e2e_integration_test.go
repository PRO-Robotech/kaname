// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// syncfga_read_after_write_e2e_integration_test.go — RED→GREEN proof of the
// Contract-A flat read-after-write race fix (rbac-contract-a-flat-syncfga).
//
// CONFIRMED ROOT CAUSE: under the flat OpenFGA model the owner/creator per-object
// access is forward-materialized by the reconciler. The create use-cases run a
// SYNCHRONOUS post-commit ReconcileObject/ReconcileBinding, but that reconcile only
// ENQUEUES the per-object FGA tuples into kacho_iam.fga_outbox (EmitTupleWrite). The
// actual apply to OpenFGA is ASYNC (the fga_outbox drainer). The operations worker
// marks the Operation done as soon as the use-case fn returns — BEFORE the outbox has
// drained — so a client that polls Operation→done and IMMEDIATELY does an authz Check
// on the just-created object RACES the drain and gets DENIED (403).
//
// This test drives the REAL create use-cases wired with the reconciler over a REAL
// OpenFGA (testcontainers, canonical flat model) + a REAL testcontainers Postgres +
// the REAL operations worker, then — with NO extra sleep and NO manual outbox drain —
// asserts the END-TO-END Check resolves true the instant operations.Wait returns. It
// FAILS (RED) on the base branch (tuple only in fga_outbox, not yet in OpenFGA) and
// PASSES (GREEN) once the reconciler applies the materialized tuples synchronously to
// OpenFGA on the create path (reconcile.WithSyncFGA).
//
// The fga_outbox drainer is deliberately NOT started here: the only way a Check can
// resolve true is the synchronous direct-write on the create path. (A running drainer
// would mask the race — the test could not distinguish race from fix.)

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	groupapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/group"
	projectapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoacct "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestSyncFGA_ReadAfterWrite_AccountCreate_OwnerCheckImmediately is the foundational
// RED case: an Account.Create owner awaits Operation done and then IMMEDIATELY
// resolves an end-to-end OpenFGA Check for viewer/editor/admin on the created
// account:<id>. On the base branch the owner scope-self tuple (admin + v_*) is only in
// fga_outbox, so the Check is DENIED → RED. With the sync-FGA write it is applied to
// OpenFGA on the create path → GREEN.
func TestSyncFGA_ReadAfterWrite_AccountCreate_OwnerCheckImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	fga := startOpenFGAFromModel(t)
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	// Reconciler wired with the SYNC-FGA direct writer pointed at the real OpenFGA.
	// WithSyncFGA is nil-safe and additive: the durable fga_outbox enqueue still
	// happens in the writer-tx; the sync write is purely the read-after-write closer.
	rec := reconcile.New(kachopg.NewReconcileAdapter(pool), nil).WithSyncFGA(kachopg.NewSyncFGAWriter(fga.relations, nil))

	creator := mustSeedUser(t, ctx, pool, "syncacc")
	createUC := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)

	octx := asUser(ctx, creator)
	op, err := createUC.Execute(octx, domain.Account{Name: "syncfga-acc-own", OwnerUserID: creator})
	require.NoError(t, err)
	require.NotNil(t, op)

	// Deterministic await — NOT time.Sleep.
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "Account.Create operation must succeed")

	accID := newestAccountByOwner(t, ctx, repo, creator, "syncfga-acc-own")
	subject := "user:" + string(creator)
	object := "account:" + string(accID)

	// END-TO-END Check (not ledger/outbox): the owner's direct admin tuple resolves
	// viewer/editor; the v_* tuples back the verb-bearing reads. This is the GET /
	// addMember / DELETE authz gate the umbrella suites race.
	requireFGAAllows(t, fga, subject, "viewer", object)
	requireFGAAllows(t, fga, subject, "editor", object)
	requireFGAAllows(t, fga, subject, "admin", object)
}

// TestSyncFGA_ReadAfterWrite_BindingAndGroupCreate_OwnerCheckImmediately drives the
// parallel iam-content cases (C-01b forward-mat): the owner of an account creates a
// Group and an AccessBinding inside that account; the owner `*.*` ARM_ANCHOR over
// iam.group / iam.accessBinding materializes its per-object editor/admin tuple, which
// must resolve an immediate end-to-end Check after each Operation done.
func TestSyncFGA_ReadAfterWrite_BindingAndGroupCreate_OwnerCheckImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	fga := startOpenFGAFromModel(t)
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	rec := reconcile.New(kachopg.NewReconcileAdapter(pool), nil).WithSyncFGA(kachopg.NewSyncFGAWriter(fga.relations, nil))

	creator := mustSeedUser(t, ctx, pool, "syncbg")
	octx := asUser(ctx, creator)

	// (1) Account create — establishes the owner-binding whose `*.*` ARM_ANCHOR is the
	// materialization source for the iam-content objects created below.
	accCreate := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)
	accOp, err := accCreate.Execute(octx, domain.Account{Name: "syncfga-acc-bg", OwnerUserID: creator})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, accOp.ID).Error, "Account.Create must succeed")
	accID := newestAccountByOwner(t, ctx, repo, creator, "syncfga-acc-bg")
	subject := "user:" + string(creator)

	// (2) Group create in that account → owner editor on iam_group:<id> immediately.
	groupCreate := groupapp.NewCreateGroupUseCase(repo, opsRepo).WithObjectReconciler(rec)
	grpOp, err := groupCreate.Execute(octx, domain.Group{AccountID: accID, Name: "syncfga-grp"})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, grpOp.ID).Error, "Group.Create must succeed")
	grpID := newestGroupInAccount(t, ctx, pool, accID, "syncfga-grp")
	requireFGAAllows(t, fga, subject, "editor", "iam_group:"+grpID)

	// (3) AccessBinding create in that account → owner editor on iam_access_binding:<id>
	// immediately. The owner grants an assignable custom role to a member on the account
	// it owns (owner-create path → grant-authority via owner_user_id).
	role := seedAccountCustomRole(t, ctx, pool, accID, "syncfga_role")
	member := mustSeedUser(t, ctx, pool, "syncbgm")
	abCreate := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(fga.relations, nil).
		WithReconciler(rec)
	abOp, err := abCreate.Execute(octx, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(member),
		RoleID:       role,
		ResourceType: "account",
		ResourceID:   string(accID),
		Scope:        domain.ScopeAccount,
	})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, abOp.ID).Error, "AccessBinding.Create must succeed")
	abID := newestBindingInAccount(t, ctx, repo, accID, role, domain.SubjectID(member))
	requireFGAAllows(t, fga, subject, "editor", "iam_access_binding:"+abID)
}

// TestSyncFGA_ReadAfterWrite_ProjectCreate_OwnerCheckImmediately is the issue #232
// project case: the owner of an account creates a Project inside it and IMMEDIATELY
// resolves an end-to-end OpenFGA Check for viewer/editor/admin on the created
// project:<id>. The owner `*.*` ARM_ANCHOR over iam.project materializes its per-object
// admin/v_* tuple, but on the base branch project.Create has NO post-commit
// ReconcileObject — it only co-commits the reconcile event for the ASYNC drainer — so
// the owner's per-object tuple is only in fga_outbox when Operation reports done →
// Check DENIED → RED. With a synchronous post-commit ReconcileObject("iam.project", id)
// on the create path (same pattern as Group/ServiceAccount/Role/AccessBinding) the
// tuple is applied to OpenFGA before the Operation returns → GREEN. (The api-gateway
// per-RPC Check that iam-project newman `get-confirms` races is this exact gate.)
func TestSyncFGA_ReadAfterWrite_ProjectCreate_OwnerCheckImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	fga := startOpenFGAFromModel(t)
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	rec := reconcile.New(kachopg.NewReconcileAdapter(pool), nil).WithSyncFGA(kachopg.NewSyncFGAWriter(fga.relations, nil))

	creator := mustSeedUser(t, ctx, pool, "syncprj")
	octx := asUser(ctx, creator)

	// (1) Account create — establishes the owner-binding whose `*.*` ARM_ANCHOR is the
	// materialization source for the project created below.
	accCreate := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)
	accOp, err := accCreate.Execute(octx, domain.Account{Name: "syncfga-acc-prj", OwnerUserID: creator})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, accOp.ID).Error, "Account.Create must succeed")
	accID := newestAccountByOwner(t, ctx, repo, creator, "syncfga-acc-prj")
	subject := "user:" + string(creator)

	// (2) Project create in that account → owner admin/editor/viewer on project:<id>
	// immediately after Operation done (no drainer running, no sleep).
	projectCreate := projectapp.NewCreateProjectUseCase(repo, opsRepo).WithObjectReconciler(rec)
	prjOp, err := projectCreate.Execute(octx, domain.Project{AccountID: accID, Name: "syncfga-prj"})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, prjOp.ID).Error, "Project.Create must succeed")
	prjID := newestProjectInAccount(t, ctx, pool, accID, "syncfga-prj")
	object := "project:" + prjID

	requireFGAAllows(t, fga, subject, "viewer", object)
	requireFGAAllows(t, fga, subject, "editor", object)
	requireFGAAllows(t, fga, subject, "admin", object)
}

// TestSyncFGA_ReadAfterWrite_SystemViewGrantToPeer_OwnerViewerCheckImmediately is
// the EXACT iam-access-binding newman `get-confirms` replica (#232 last red class):
// the account OWNER grants the SYSTEM `view` role (rol1bda80f2be4d3658e, `*.*.*.read`)
// to ANOTHER user on the account, then — acting as the owner (NOT the grantee) —
// resolves an immediate end-to-end Check for `viewer` on the just-created
// iam_access_binding:<id>. This is precisely the api-gateway per-RPC authz gate
// AccessBindingService/Get enforces (catalog: required_relation=viewer,
// object_type=iam_access_binding). The owner `*.*.*` ARM_ANCHOR over iam.accessBinding
// must forward-materialize the owner's admin/v_* tuple on the NEW binding-object so the
// implied `viewer` Check passes the instant Operation reports done (sync-FGA write on
// the create path), with NO drainer running and NO sleep.
//
// Distinct from the BindingAndGroup test above: that uses a CUSTOM role and Checks
// `editor`; this uses the SYSTEM `view` role + a THIRD-PARTY subject and Checks the
// `viewer` relation the live umbrella newman races. If the per-object owner tuple is
// only in fga_outbox at Operation-done, the Check is DENIED → RED.
func TestSyncFGA_ReadAfterWrite_SystemViewGrantToPeer_OwnerViewerCheckImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	fga := startOpenFGAFromModel(t)
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	rec := reconcile.New(kachopg.NewReconcileAdapter(pool), nil).WithSyncFGA(kachopg.NewSyncFGAWriter(fga.relations, nil))

	owner := mustSeedUser(t, ctx, pool, "syncview")
	octx := asUser(ctx, owner)

	// (1) Account create — establishes the owner-binding (ROLE_OWNER `*.*.*` ARM_ANCHOR
	// over the full materializable set incl. iam.accessBinding) reconciled with sync-FGA.
	accCreate := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)
	accOp, err := accCreate.Execute(octx, domain.Account{Name: "syncfga-acc-view", OwnerUserID: owner})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, accOp.ID).Error, "Account.Create must succeed")
	accID := newestAccountByOwner(t, ctx, repo, owner, "syncfga-acc-view")
	ownerSubject := "user:" + string(owner)

	// (2) Owner grants the SYSTEM `view` role to a DIFFERENT user on the account it owns
	// (the exact newman create: subject=peer, role=ROLE_VIEW, resource=account/accID).
	const systemViewRoleID = domain.RoleID("rol1bda80f2be4d3658e") // md5('view')[:17]
	peer := mustSeedUser(t, ctx, pool, "syncviewpeer")
	abCreate := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(fga.relations, nil).
		WithReconciler(rec)
	abOp, err := abCreate.Execute(octx, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(peer),
		RoleID:       systemViewRoleID,
		ResourceType: "account",
		ResourceID:   string(accID),
		Scope:        domain.ScopeAccount,
	})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, abOp.ID).Error, "AccessBinding.Create must succeed")
	abID := newestBindingInAccount(t, ctx, repo, accID, systemViewRoleID, domain.SubjectID(peer))

	// (3) The OWNER (not the grantee) must resolve Check(viewer, iam_access_binding:<id>)
	// IMMEDIATELY — this is the AccessBindingService/Get authz gate the newman
	// `get-confirms` races. viewer is implied by the owner's materialized admin/editor.
	object := "iam_access_binding:" + abID
	requireFGAAllows(t, fga, ownerSubject, "viewer", object)
	requireFGAAllows(t, fga, ownerSubject, "editor", object)
	requireFGAAllows(t, fga, ownerSubject, "admin", object)
}

// TestSyncFGA_ReadAfterWrite_PopulatedAccount_OwnerViewerCheckImmediately is the
// PRECISE iam-access-binding live-newman reproduction (#232 last red class): on an
// account already populated with many iam-native content objects, the OWNER grants the
// SYSTEM `view` role (`*.*.*` ARM_ANCHOR) to a peer, then immediately resolves
// Check(viewer, iam_access_binding:<id>).
//
// The create-path synchronous reconcile of the NEW iam_access_binding fans out over BOTH
// bounded `*.*` ARM_ANCHOR bindings on the account — the owner-binding (ROLE_OWNER) AND
// the just-granted peer view-binding — each materializing per-object tuples over the
// whole populated content set. The single collected sync-FGA batch therefore exceeds
// OpenFGA's default maxTuplesPerWrite (100). Before the WriteTuples chunk fix OpenFGA
// rejected the WHOLE batch with a 400, so the owner's viewer/admin tuple on the new AB
// never landed synchronously → the immediate Check is DENIED (403) → RED. With chunked
// WriteTuples every tuple is applied across several requests → GREEN.
//
// This is the scenario the small-account BindingAndGroup / SystemViewGrantToPeer tests
// above CANNOT exercise (their fan-out stays under 100); populating the account is what
// crosses the limit and reproduces the live failure.
func TestSyncFGA_ReadAfterWrite_PopulatedAccount_OwnerViewerCheckImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	fga := startOpenFGAFromModel(t)
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	rec := reconcile.New(kachopg.NewReconcileAdapter(pool), nil).WithSyncFGA(kachopg.NewSyncFGAWriter(fga.relations, nil))

	owner := mustSeedUser(t, ctx, pool, "syncpop")
	octx := asUser(ctx, owner)

	accCreate := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)
	accOp, err := accCreate.Execute(octx, domain.Account{Name: "syncfga-acc-pop", OwnerUserID: owner})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, accOp.ID).Error, "Account.Create must succeed")
	accID := newestAccountByOwner(t, ctx, repo, owner, "syncfga-acc-pop")
	ownerSubject := "user:" + string(owner)

	// Populate the account with enough iam-native content that a `*.*` ARM_ANCHOR
	// reconcile materializes > maxTuplesPerWriteRequest (100) tuples in one batch. Each
	// custom role yields per-object tier (+ v_*) tuples PER MATCHING `*.*` binding; 80
	// roles × 2 bounded `*.*` bindings (owner + peer view) × (tier + back-compat) comfortably
	// exceeds 100 in the single ReconcileObject sync-FGA batch.
	for i := 0; i < 80; i++ {
		seedAccountCustomRole(t, ctx, pool, accID, "syncpop_role_"+itoaPop(i))
	}

	const systemViewRoleID = domain.RoleID("rol1bda80f2be4d3658e") // md5('view')[:17]
	peer := mustSeedUser(t, ctx, pool, "syncpoppeer")
	abCreate := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(fga.relations, nil).
		WithReconciler(rec)
	abOp, err := abCreate.Execute(octx, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(peer),
		RoleID:       systemViewRoleID,
		ResourceType: "account",
		ResourceID:   string(accID),
		Scope:        domain.ScopeAccount,
	})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, abOp.ID).Error, "AccessBinding.Create must succeed")
	abID := newestBindingInAccount(t, ctx, repo, accID, systemViewRoleID, domain.SubjectID(peer))

	// The owner must resolve viewer on the new binding-object IMMEDIATELY despite the
	// >100-tuple create-path reconcile batch — the AccessBindingService/Get authz gate.
	object := "iam_access_binding:" + abID
	requireFGAAllows(t, fga, ownerSubject, "viewer", object)
	requireFGAAllows(t, fga, ownerSubject, "admin", object)
}

// itoaPop — local int→string for the populated-account seed loop.
func itoaPop(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// ── helpers ─────────────────────────────────────────────────────────────────

func newestProjectInAccount(t *testing.T, ctx context.Context, pool poolQuerier, acc domain.AccountID, name string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.projects WHERE account_id = $1 AND name = $2 ORDER BY created_at DESC LIMIT 1`,
		string(acc), name).Scan(&id)
	require.NoError(t, err)
	require.NotEmpty(t, id, "project %q in account %s must exist", name, acc)
	return id
}

// requireFGAAllows asserts the end-to-end OpenFGA Check resolves true RIGHT NOW (no
// retry, no sleep) — the precise read-after-write moment the create-path race loses.
func requireFGAAllows(t *testing.T, fga *syncFGAHarness, subject, relation, object string) {
	t.Helper()
	allowed, err := fga.relations.Check(context.Background(), subject, relation, object)
	require.NoError(t, err)
	assert.True(t, allowed,
		"owner must resolve Check(%s, %s, %s) immediately after Operation done — "+
			"if false, the per-object tuple is only in fga_outbox (async drain race), not yet in OpenFGA",
		subject, relation, object)
}

func newestAccountByOwner(t *testing.T, ctx context.Context, repo *kachopg.Repository, owner domain.UserID, name string) domain.AccountID {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	accs, _, err := rd.Accounts().List(ctx, repoacct.ListFilter{PageSize: 1000})
	require.NoError(t, err)
	var id domain.AccountID
	for _, a := range accs {
		if a.OwnerUserID == owner && a.Name == domain.AccountName(name) {
			id = a.ID
		}
	}
	require.NotEmpty(t, id, "account %q owned by %s must exist", name, owner)
	return id
}

func newestGroupInAccount(t *testing.T, ctx context.Context, pool poolQuerier, acc domain.AccountID, name string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.groups WHERE account_id = $1 AND name = $2 ORDER BY created_at DESC LIMIT 1`,
		string(acc), name).Scan(&id)
	require.NoError(t, err)
	require.NotEmpty(t, id, "group %q in account %s must exist", name, acc)
	return id
}

func newestBindingInAccount(t *testing.T, ctx context.Context, repo *kachopg.Repository, acc domain.AccountID, role domain.RoleID, subj domain.SubjectID) string {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, _, err := rd.AccessBindings().ListByScope(ctx, "account", string(acc), repoab.PageFilter{PageSize: 1000})
	require.NoError(t, err)
	var id string
	for i := range rows {
		if rows[i].RoleID == role && rows[i].SubjectID == subj {
			id = string(rows[i].ID)
		}
	}
	require.NotEmpty(t, id, "access_binding (role=%s subject=%s) in account %s must exist", role, subj, acc)
	return id
}
