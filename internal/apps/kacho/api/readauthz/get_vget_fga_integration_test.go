// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package readauthz_test

// get_vget_fga_integration_test.go — real-OpenFGA + real-Postgres proof that the
// IAM read use-cases (Account/Project/User/Group/ServiceAccount .Get) authorize
// via the verb-bearing `v_get` relation (Design B), NOT the legacy owner-only
// software gate (authzguard.IsSelf) that produced the live "granted invitee →
// 404 on GET /iam/v1/accounts/<id>" bug.
//
// Authorization contract under test:
//
//	ALLOW iff  cluster-admin (cluster:cluster_kacho_root#system_admin @ subject)   — short-circuit, ANY object
//	      OR   subject holds v_get on the resource object (<fga_type>:<id>)         — owner-binding OR explicit grant
//	otherwise  NotFound  (hide existence — never PermissionDenied, no enumeration)
//	anonymous  NotFound  (fail-closed before any FGA call)
//
// The owner case is materialized as an explicit per-object v_get tuple (the
// owner-binding reconciler emits exactly this in production); the test seeds it
// directly so the proof does not depend on the reconciler path. Adversarial:
// a v_get on resource X must NOT satisfy a Get on resource Y (per-object FGA),
// and a foreign-account stranger must be hidden (no leak).
//
// Real FGA (testcontainers openfga/openfga) loads the canonical fga_model.fga, so
// these checks exercise the SAME production clients.OpenFGAHTTPClient.Check path.
// Skipped under -short / no Docker.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	accountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	groupapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/group"
	projectapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/project"
	saapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/service_account"
	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// readAuthzFixture bundles a live repo + FGA harness with a seeded topology:
//
//	owner (usr_owner)  owns account:acc_T; account/project/user/group/sa live in it.
//	invitee (usr_inv)  holds an explicit v_get on EACH resource object.
//	clusterAdmin       holds system_admin@cluster (super-gate).
//	stranger (usr_str) holds nothing on these objects.
type readAuthzFixture struct {
	pool *pgxpool.Pool
	repo *kachopg.Repository
	fga  *fgatest.Harness

	ownerID domain.UserID
	accID   domain.AccountID
	projID  domain.ProjectID
	userID  domain.UserID // a second user inside acc_T (the GET-target user)
	groupID domain.GroupID
	saID    domain.ServiceAccountID

	inviteeID  domain.UserID
	clusterID  domain.UserID
	strangerID domain.UserID
}

func newReadAuthzFixture(t *testing.T) *readAuthzFixture {
	t.Helper()
	ctx := context.Background()

	pool, err := coredb.NewPool(ctx, kachopg.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kachopg.New(pool, nil)
	fga := fgatest.New(t)

	f := &readAuthzFixture{pool: pool, repo: repo, fga: fga}

	// owner + owned account (chicken-and-egg owner_user_id resolved via the
	// users/accounts pair seeded in one tx).
	f.ownerID = seedUserWithAccount(t, ctx, pool, "owner")
	f.accID = accountOf(t, ctx, pool, f.ownerID)

	// a target user, group, sa, project — all inside acc_T.
	f.userID = seedUserInAccount(t, ctx, pool, f.accID, "target")
	f.projID = seedProject(t, ctx, repo, f.accID, "proj-t")
	f.groupID = seedGroup(t, ctx, repo, f.accID, "grp-t")
	f.saID = seedServiceAccount(t, ctx, repo, f.accID, "sa-t")

	// caller identities (rows not required for FGA-only callers, but seed them so
	// they are real users in the same DB).
	f.inviteeID = seedUserInAccount(t, ctx, pool, f.accID, "invitee")
	f.clusterID = seedUserInAccount(t, ctx, pool, f.accID, "clusteradmin")
	f.strangerID = seedUserWithAccount(t, ctx, pool, "stranger") // own foreign account

	// ── Seed FGA grants ───────────────────────────────────────────────────────
	// owner: v_get on every object (the owner-binding reconciler emits exactly this).
	f.fga.Write(t, subj(f.ownerID), "v_get", obj("account", string(f.accID)))
	f.fga.Write(t, subj(f.ownerID), "v_get", obj("project", string(f.projID)))
	f.fga.Write(t, subj(f.ownerID), "v_get", obj("iam_user", string(f.userID)))
	f.fga.Write(t, subj(f.ownerID), "v_get", obj("iam_group", string(f.groupID)))
	f.fga.Write(t, subj(f.ownerID), "v_get", obj("iam_service_account", string(f.saID)))

	// invitee: explicit v_get grant on every object (the live-bug scenario).
	f.fga.Write(t, subj(f.inviteeID), "v_get", obj("account", string(f.accID)))
	f.fga.Write(t, subj(f.inviteeID), "v_get", obj("project", string(f.projID)))
	f.fga.Write(t, subj(f.inviteeID), "v_get", obj("iam_user", string(f.userID)))
	f.fga.Write(t, subj(f.inviteeID), "v_get", obj("iam_group", string(f.groupID)))
	f.fga.Write(t, subj(f.inviteeID), "v_get", obj("iam_service_account", string(f.saID)))

	// cluster-admin: flat super-gate (no per-object tuple).
	f.fga.Write(t, subj(f.clusterID), "system_admin", "cluster:"+domain.ClusterSingletonID)

	return f
}

// ── caller ctx + FGA subject helpers ─────────────────────────────────────────

func ctxUser(id domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: string(id)})
}

func ctxAnon() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})
}

func subj(id domain.UserID) string  { return "user:" + string(id) }
func obj(fgaType, id string) string { return fgaType + ":" + id }

func requireNotFound(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.NotFound, st.Code(), "%s — must hide existence (NotFound, not PermissionDenied)", msg)
}

// ── Account.Get ──────────────────────────────────────────────────────────────

func TestReadAuthz_Account_VGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newReadAuthzFixture(t)
	uc := accountapp.NewGetAccountUseCase(f.repo).WithRelationStore(f.fga.Client)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.accID)
		require.NoError(t, err, "owner holds v_get → ALLOW")
		require.Equal(t, f.accID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.accID)
		require.NoError(t, err, "granted v_get invitee → ALLOW (was 404)")
		require.Equal(t, f.accID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.clusterID), f.accID)
		require.NoError(t, err, "cluster-admin short-circuit → ALLOW any object")
		require.Equal(t, f.accID, got.ID)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.accID)
		requireNotFound(t, err, "stranger (no v_get) → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.accID)
		requireNotFound(t, err, "anonymous → hide (fail-closed)")
	})
}

// ── Project.Get ──────────────────────────────────────────────────────────────

func TestReadAuthz_Project_VGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newReadAuthzFixture(t)
	uc := projectapp.NewGetProjectUseCase(f.repo).WithRelationStore(f.fga.Client)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.projID)
		require.NoError(t, err)
		require.Equal(t, f.projID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.projID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.projID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.projID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.projID)
		requireNotFound(t, err, "stranger → hide (project was over-exposed pre-fix: authenticated-pass-through)")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.projID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── User.Get ─────────────────────────────────────────────────────────────────

func TestReadAuthz_User_VGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newReadAuthzFixture(t)
	uc := userapp.NewGetUserUseCase(f.repo).WithRelationStore(f.fga.Client)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.userID)
		require.NoError(t, err)
		require.Equal(t, f.userID, got.ID)
	})
	t.Run("self_ALLOW", func(t *testing.T) {
		// the target user reading itself: self always holds v_get on its own
		// iam_user (owner-binding twin). Seed it to model that.
		f.fga.Write(t, subj(f.userID), "v_get", obj("iam_user", string(f.userID)))
		got, err := uc.Execute(ctxUser(f.userID), f.userID)
		require.NoError(t, err, "self → ALLOW")
		require.Equal(t, f.userID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.userID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.userID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.userID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.userID)
		requireNotFound(t, err, "stranger → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.userID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── Group.Get ────────────────────────────────────────────────────────────────

func TestReadAuthz_Group_VGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newReadAuthzFixture(t)
	uc := groupapp.NewGetGroupUseCase(f.repo).WithRelationStore(f.fga.Client)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.groupID)
		require.NoError(t, err)
		require.Equal(t, f.groupID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.groupID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.groupID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.groupID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.groupID)
		requireNotFound(t, err, "stranger → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.groupID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── ServiceAccount.Get ───────────────────────────────────────────────────────

func TestReadAuthz_ServiceAccount_VGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newReadAuthzFixture(t)
	uc := saapp.NewGetServiceAccountUseCase(f.repo).WithRelationStore(f.fga.Client)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.saID)
		require.NoError(t, err)
		require.Equal(t, f.saID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.saID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.saID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.saID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.saID)
		requireNotFound(t, err, "stranger → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.saID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── Adversarial: v_get on X does NOT satisfy Get on Y (per-object FGA) ────────

func TestReadAuthz_Adversarial_VGetOnXDoesNotGrantY(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newReadAuthzFixture(t)

	// A caller granted v_get ONLY on the account must NOT read the project / user
	// / group / sa inside it (D-2: no cascade; v_get is object-only).
	caller := f.strangerID
	f.fga.Write(t, subj(caller), "v_get", obj("account", string(f.accID)))

	t.Run("account_ALLOW", func(t *testing.T) {
		uc := accountapp.NewGetAccountUseCase(f.repo).WithRelationStore(f.fga.Client)
		_, err := uc.Execute(ctxUser(caller), f.accID)
		require.NoError(t, err, "v_get on the account → ALLOW the account itself")
	})
	t.Run("project_hide", func(t *testing.T) {
		uc := projectapp.NewGetProjectUseCase(f.repo).WithRelationStore(f.fga.Client)
		_, err := uc.Execute(ctxUser(caller), f.projID)
		requireNotFound(t, err, "v_get on account must NOT cascade to the project (D-2)")
	})
	t.Run("user_hide", func(t *testing.T) {
		uc := userapp.NewGetUserUseCase(f.repo).WithRelationStore(f.fga.Client)
		_, err := uc.Execute(ctxUser(caller), f.userID)
		requireNotFound(t, err, "v_get on account must NOT cascade to a user")
	})
	t.Run("group_hide", func(t *testing.T) {
		uc := groupapp.NewGetGroupUseCase(f.repo).WithRelationStore(f.fga.Client)
		_, err := uc.Execute(ctxUser(caller), f.groupID)
		requireNotFound(t, err, "v_get on account must NOT cascade to a group")
	})
	t.Run("sa_hide", func(t *testing.T) {
		uc := saapp.NewGetServiceAccountUseCase(f.repo).WithRelationStore(f.fga.Client)
		_, err := uc.Execute(ctxUser(caller), f.saID)
		requireNotFound(t, err, "v_get on account must NOT cascade to a service account")
	})
}

// ── seed helpers ─────────────────────────────────────────────────────────────

func seedUserWithAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid),
		"u-"+suffix+"@example.com", "User "+suffix)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), "acc-"+suffix+"-"+string(accID)[len(accID)-6:], string(uid))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid
}

func accountOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner domain.UserID) domain.AccountID {
	t.Helper()
	var accID string
	err := pool.QueryRow(ctx, `SELECT id FROM accounts WHERE owner_user_id = $1`, string(owner)).Scan(&accID)
	require.NoError(t, err)
	return domain.AccountID(accID)
}

func seedUserInAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid),
		"u-"+suffix+"-"+string(uid)[len(uid)-6:]+"@example.com", "User "+suffix)
	require.NoError(t, err)
	return uid
}

func seedProject(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.ProjectID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ProjectsW().Insert(ctx, domain.Project{
		ID:        domain.ProjectID(ids.NewID(domain.PrefixProject)),
		AccountID: accID,
		Name:      domain.ProjectName(name),
		Labels:    domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out.ID
}

func seedGroup(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.GroupID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.GroupsW().Insert(ctx, domain.Group{
		ID:        domain.GroupID(ids.NewID(domain.PrefixGroup)),
		AccountID: accID,
		Name:      domain.GroupName(name),
		Labels:    domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out.ID
}

func seedServiceAccount(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.ServiceAccountID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{
		ID:        domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		AccountID: accID,
		Name:      domain.SvcAccountName(name),
		Enabled:   true,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out.ID
}
