// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// list_authz_test.go — per-object filtered RoleService.List unit tests.
//
// Semantics:
//   - System roles (is_system) are the tenant-wide reference catalog floor: every
//     authenticated principal sees them (RoleService.Get is <exempt>; the catalog
//     of built-in roles is shared). They are NOT subject to the per-object filter.
//   - CUSTOM roles are filtered per-object via FGA ListObjects(subject, "viewer",
//     "iam_role") — the `viewer` tier cascades from the account tier
//     (admin→editor→viewer; `viewer from account`), so a role's creator /
//     account-admin resolves visibility on the roles in their account, while a
//     foreign account resolves none (no existence leak). This is the SAME
//     read-relation account/project List filter by (`viewer`), so the role
//     read-surface is consistent with the rest of iam (read==enforce).
//   - ListFilter.AccountID scopes the catalog to one Account (system +
//     that Account's custom roles); a foreign Account's custom roles never appear.
//   - Fail-closed: a nil FGA port or an FGA error → Unavailable, never an
//     unfiltered/owner-only fallback.
//   - page_size > 1000 → InvalidArgument (no silent clamp) — covered in the
//     handler/repo tests; the use-case propagates the repo/validate error.
//
// The visible custom-role id-set is the FGA ListObjects(subject,"viewer","iam_role")
// result: the `viewer` tier resolves an account-admin's own roles via the
// account-tier cascade and resolves scope_grant/cluster grants too; the use-case's
// job is to INTERSECT that set with the page and keep system roles (catalog floor).

import (
	"context"
	stderrors "errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// ───────────── fake repo (Roles().List only) ─────────────

type roleListFakeRepo struct {
	roles      map[string]domain.Role
	lastFilter reporole.ListFilter
}

func newRoleListFakeRepo() *roleListFakeRepo {
	return &roleListFakeRepo{roles: map[string]domain.Role{}}
}

func (f *roleListFakeRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &roleListFakeReader{f}, nil
}
func (f *roleListFakeRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return nil, stderrors.New("fake.Writer not used in list tests")
}
func (f *roleListFakeRepo) Close() {}

type roleListFakeReader struct{ p *roleListFakeRepo }

func (r *roleListFakeReader) Accounts() repoaccount.ReaderIface { return nil }
func (r *roleListFakeReader) Projects() project.ReaderIface     { return nil }
func (r *roleListFakeReader) Users() user.ReaderIface           { return nil }
func (r *roleListFakeReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *roleListFakeReader) Groups() group.ReaderIface                  { return nil }
func (r *roleListFakeReader) Roles() reporole.ReaderIface                { return &roleListReader{r.p} }
func (r *roleListFakeReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *roleListFakeReader) Commit(context.Context) error               { return nil }
func (r *roleListFakeReader) Rollback(context.Context) error             { return nil }

type roleListReader struct{ p *roleListFakeRepo }

func (a *roleListReader) Get(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	if ro, ok := a.p.roles[string(id)]; ok {
		return ro, nil
	}
	return domain.Role{}, stderrors.New("not found")
}
func (a *roleListReader) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	ro, err := a.Get(ctx, id)
	return ro, "v", err
}
func (a *roleListReader) ListAssignable(ctx context.Context, rt, rid string, f reporole.ListFilter) ([]domain.Role, string, error) {
	return nil, "", stderrors.New("ListAssignable not used in list tests")
}

// List mirrors the pg repo's filter contract: AccountID scopes to system +
// that Account's custom roles; VisibleIDs (when non-nil) intersects the result
// at the SQL layer so keyset pagination stays correct over the filtered set
// (D-46). The use-case must keep system roles (catalog floor) regardless of
// VisibleIDs.
func (a *roleListReader) List(ctx context.Context, f reporole.ListFilter) ([]domain.Role, string, error) {
	a.p.lastFilter = f
	visible := map[string]bool{}
	if f.VisibleIDs != nil {
		for _, id := range f.VisibleIDs {
			visible[id] = true
		}
	}
	keys := make([]string, 0, len(a.p.roles))
	for k := range a.p.roles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]domain.Role, 0, len(keys))
	for _, k := range keys {
		ro := a.p.roles[k]
		if f.AccountID != "" && !ro.IsSystem && ro.AccountID != f.AccountID {
			continue // scope: foreign Account's custom roles excluded
		}
		// push-down mirror: when VisibleIDs is non-nil, custom roles must
		// be in the set; system roles bypass (catalog floor) — same as the pg repo.
		if f.VisibleIDs != nil && !ro.IsSystem && !visible[k] {
			continue
		}
		out = append(out, ro)
	}
	return out, "", nil
}

func seedSystemRole(r *roleListFakeRepo, id string) {
	r.roles[id] = domain.Role{
		ID: domain.RoleID(id), Name: domain.RoleName("sys-" + id),
		IsSystem: true, CreatedAt: time.Now().UTC(),
	}
}
func seedCustomRole(r *roleListFakeRepo, id, acct string) {
	r.roles[id] = domain.Role{
		ID: domain.RoleID(id), Name: domain.RoleName("c-" + id),
		IsSystem: false, AccountID: domain.AccountID(acct), CreatedAt: time.Now().UTC(),
	}
}

func ctxUser(uid string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: uid})
}

func roleIDs(out []domain.Role) []string {
	ids := make([]string, 0, len(out))
	for _, r := range out {
		ids = append(ids, string(r.ID))
	}
	return ids
}

// ───────────── FGA ListObjects stub ─────────────

type roleFGAStub struct {
	clients.RelationQueries
	idsBySubject map[string][]string
	err          error
	calls        int
	relations    map[string]int // per-relation call count (union observability)
	lastSubject  string
	lastRelation string
	lastObjType  string
}

func newRoleFGAStub() *roleFGAStub {
	return &roleFGAStub{idsBySubject: map[string][]string{}, relations: map[string]int{}}
}

func (s *roleFGAStub) set(subject string, ids []string) { s.idsBySubject[subject] = ids }

func (s *roleFGAStub) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
	s.calls++
	s.relations[relation]++
	s.lastSubject = subject
	s.lastRelation = relation
	s.lastObjType = objectType
	if s.err != nil {
		return nil, s.err
	}
	// Relation-agnostic id-set: returns the same grant-set for viewer AND v_list,
	// so the use-case's viewer ∪ v_list union is exercised without these legacy
	// tests caring which relation surfaced the role.
	return s.idsBySubject[subject], nil
}

// ───────────── tests ─────────────

// read-relations + object type: the per-object filter MUST query BOTH the `viewer`
// tier relation (cascades from account-tier — account-admin sees own role, like
// account/project List) AND the `v_list` verb relation (object-only selector grant,
// selector-without-content) on iam_role — the Design-B viewer ∪ v_list union.
func TestListRoles_UsesViewerAndVListRelationsOnIamRole(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A")

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-c1"})

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	_, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.GreaterOrEqual(t, fga.relations["viewer"], 1,
		"per-object List must query the `viewer` tier relation (account-tier cascade — owner sees own role)")
	require.GreaterOrEqual(t, fga.relations["v_list"], 1,
		"per-object List must ALSO query the `v_list` verb relation (object-only selector grant, Design-B union)")
	require.Equal(t, "iam_role", fga.lastObjType, "object type must be iam_role")
	require.Equal(t, "user:usr-u1", fga.lastSubject)
}

// System roles are the tenant-wide catalog floor: visible even with an empty
// FGA grant-set. Custom roles require a grant.
func TestListRoles_D40_SystemRolesAlwaysVisible_CustomFiltered(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedSystemRole(repo, "rol-sys2")
	seedCustomRole(repo, "rol-c1", "acc-A")

	fga := newRoleFGAStub() // empty grant-set for the caller
	uc := NewListRolesUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-sys2"}, roleIDs(out),
		"system roles always visible (catalog floor); ungranted custom role hidden")
}

// LST-2 byName / LST-4 union: FGA returns exactly the granted custom ids → List
// shows system ∪ granted-custom.
func TestListRoles_D41_D43_CustomByGrant_Union(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-c1", "acc-A")
	seedCustomRole(repo, "rol-c2", "acc-A")
	seedCustomRole(repo, "rol-c3", "acc-A") // not granted

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-c1", "rol-c2"})

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-c1", "rol-c2"}, roleIDs(out),
		"system ∪ granted custom (rol-c3 ungranted → hidden, LST-4 union / LST-2 byName)")
}

// LST-5 no-leak: an ungranted custom role is absent from List (existence not leaked).
func TestListRoles_D44_NoLeak_UngrantedCustomAbsent(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-cZ", "acc-A") // foreign / ungranted

	fga := newRoleFGAStub() // no grant
	uc := NewListRolesUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.NotContains(t, roleIDs(out), "rol-cZ",
		"ungranted custom role MUST be absent from List (no existence leak, LST-5)")
}

// #185: accountId scopes the catalog — a foreign Account's custom roles never
// appear, even if (hypothetically) granted; the scope is enforced at the repo.
func TestListRoles_185_AccountScope_ForeignCustomHidden(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-cA", "acc-A")
	seedCustomRole(repo, "rol-cB", "acc-B") // foreign account

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-cA", "rol-cB"}) // even if FGA would allow both

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100, AccountID: domain.AccountID("acc-A")})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-cA"}, roleIDs(out),
		"#185: accountId=acc-A → system + acc-A custom only; acc-B custom never visible")
	require.Equal(t, domain.AccountID("acc-A"), repo.lastFilter.AccountID,
		"accountId scope is pushed into the repo filter")
}

// D-47 fail-closed: FGA error → Unavailable, never an unfiltered list.
func TestListRoles_D47_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-c1", "acc-A")

	fga := newRoleFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.Error(t, err, "FGA outage must NOT return a (degraded) list")
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(), "FGA outage → UNAVAILABLE fail-closed (D-47)")
}

// nil FGA port → fail-closed Unavailable (never an unfiltered catalog leak).
func TestListRoles_D47_NilFGA_FailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A")

	uc := NewListRolesUseCase(repo) // NO WithRelationStore
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.Error(t, err)
	require.Empty(t, out)
	st, _ := status.FromError(err)
	require.Equal(t, codes.Unavailable, st.Code(), "nil FGA port → fail-closed Unavailable")
}
