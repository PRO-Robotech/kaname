// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// list_authz_test.go — per-object filtered RoleService.List unit tests.
//
// Semantics:
//   - System roles (is_system) are the tenant-wide reference catalog floor: every
//     authenticated principal sees them (the catalog of built-in roles is shared;
//     both reads are declared `scope_filtered`, so the per-object decision is the
//     service's). They are NOT subject to the per-object filter.
//   - CUSTOM roles are filtered by a DIRECT per-object question about each row of
//     the page — `viewer` on `iam_role:<id>`, then `v_list` for what `viewer`
//     denied (authzfilter.RelationsFor("iam_role")). The `viewer` tier cascades
//     from the account tier (admin→editor→viewer; `viewer from account`), so a
//     role's creator / account-admin resolves visibility on the roles in their
//     account, while a foreign account resolves none (no existence leak).
//   - ListFilter.AccountID scopes the catalog to one Account (system +
//     that Account's custom roles); a foreign Account's custom roles never appear.
//   - Fail-closed: a nil relation port, or a question that could not be answered,
//     → Unavailable, never an unfiltered/owner-only fallback. "Could not ask" and
//     "not allowed" are different worlds.
//   - page_size > 1000 → InvalidArgument (no silent clamp) — covered in the
//     handler/repo tests; the use-case propagates the repo/validate error.
//
// # What this header used to say, and why that stopped being true
//
// The visible custom-role set used to be named as an enumeration —
// ListObjects(subject,"viewer","iam_role") — and the use-case's job as intersecting
// that set with the page. That door no longer exists in any form: the external
// relation engine was removed in stage S6 and clients.RelationQueries carries no
// method that enumerates objects. The predicate is unchanged (an enumeration
// returns, by definition, what a Check would allow); what changed is the SHAPE, and
// with it the direction of the intersection — the page is read first and each of its
// rows is asked about, so the cost of a page follows the page.
//
// The reason for the removal is kept because it is still the reason: the enumeration
// was capped server-side with no continuation token, so past that population a
// tenant's own role fell outside the returned prefix and became permanently
// invisible — Get → NOT_FOUND, List → absent — while the row and the grant both
// existed.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
	reporole "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// ───────────── fake repo (Roles().List only) ─────────────

type roleListFakeRepo struct {
	roles      map[string]domain.Role
	lastFilter reporole.ListFilter

	// projected — строки проекции, которую читает вердикт: ключ
	// «роль|точечный-тип|глагол». Дублёр отвечает ИЗ СВОЕГО НАБОРА, а не
	// «неразрешённых нет»: заглушка, возвращающая пустое, была бы
	// снисходительнее продукта и молча зеленила бы пробы деградации.
	projected map[string]bool
	// segCalls — сколько раз спрошена целость. Единица стоимости страницы.
	segCalls int
	// segFail — отказ выборки целости (полоса fail-closed).
	segFail error
	// wdCalls — сколько раз спрошена ведомость отобранного. Единица стоимости
	// страницы: вопрос обязан быть ОДИН, а не по вопросу на роль.
	wdCalls int
	// wdFail — отказ выборки ведомости (полоса fail-closed).
	wdFail error
	// withdrawn — что дублёр знает об отобранном, по ролям.
	withdrawn map[string][]domain.WithdrawnGrant
	// psCalls — сколько раз спрошена ведомость ВЫРЕЗАННОГО. Та же единица
	// стоимости, что у соседа: один вопрос на страницу, а не на роль.
	psCalls int
	// psFail — отказ выборки ведомости вырезанного (полоса fail-closed).
	psFail error
	// pruned — что дублёр знает о вырезанном, по ролям.
	pruned map[string][]domain.PrunedSelectorType

	// ─── ручки ИНЪЕКЦИИ (`ledger_read_cost_injection_test.go`) ───
	//
	// Ими вносится дефект, от которого пробы стоимости и fail-closed обязаны
	// краснеть. Держать их у дублёра, а не у пробы, приходится потому, что
	// наблюдаемое у обоих свойств — ПОВЕДЕНИЕ ЧИТАТЕЛЯ, а подменить читателя
	// прод-кода проба не может, не тронув прод (ban #13).
	//
	// В штатных прогонах обе — нулевые, поэтому дублёр остаётся тем же.

	// ledgerPerRole — считать вопрос ПО РОЛИ, как считал бы поролевой читатель.
	// Наблюдаемое совпадает с настоящим дефектом дословно: счётчик равен числу
	// ролей страницы вместо единицы.
	ledgerPerRole bool
	// ledgerSwallow — проглотить отказ ведомости и ответить пустым, как ответил
	// бы помощник, логирующий ошибку вместо возврата.
	ledgerSwallow bool
}

func newRoleListFakeRepo() *roleListFakeRepo {
	return &roleListFakeRepo{roles: map[string]domain.Role{}, projected: map[string]bool{}}
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

// UnresolvedSegments отвечает из набора проекций дублёра — по одному вопросу на
// СТРАНИЦУ, как продукт. Пустой набор здесь означает «ни один сегмент не
// спроецирован», а не «всё в порядке»: ответ «неразрешённых нет» на непустом
// входе делал бы дублёра снисходительнее продукта.
func (a *roleListReader) UnresolvedSegments(ctx context.Context, declared []domain.RoleSegment) (map[domain.RoleID][]domain.RoleSegment, error) {
	a.p.segCalls++
	if a.p.segFail != nil {
		return nil, a.p.segFail
	}
	out := map[domain.RoleID][]domain.RoleSegment{}
	for _, d := range declared {
		if a.p.matches(d) {
			continue
		}
		out[d.RoleID] = append(out[d.RoleID], d)
	}
	return out, nil
}

// WithdrawnGrants отвечает из набора дублёра — ОДНИМ вопросом на страницу, как
// продукт. Пустой ответ здесь означает «у этих ролей отобранного нет», и это
// законное состояние продукта, а не снисходительность: ведомость наполняется
// только снятием строки каталога, которого в этих пробах не происходит.
func (a *roleListReader) WithdrawnGrants(ctx context.Context, ids []domain.RoleID) (map[domain.RoleID][]domain.WithdrawnGrant, error) {
	a.p.wdCalls++
	if a.p.ledgerPerRole {
		a.p.wdCalls += len(ids) - 1
	}
	if a.p.wdFail != nil && !a.p.ledgerSwallow {
		return nil, a.p.wdFail
	}
	out := map[domain.RoleID][]domain.WithdrawnGrant{}
	for _, id := range ids {
		if g, ok := a.p.withdrawn[string(id)]; ok {
			out[id] = g
		}
	}
	return out, nil
}

// PrunedSelectorTypes отвечает из набора дублёра — ОДНИМ вопросом на страницу,
// как продукт. Пустой ответ означает «у этих ролей вырезанного нет», и это
// законное состояние: ведомость наполняется только снятием строки каталога,
// которого в этих пробах не происходит.
func (a *roleListReader) PrunedSelectorTypes(ctx context.Context, ids []domain.RoleID) (map[domain.RoleID][]domain.PrunedSelectorType, error) {
	a.p.psCalls++
	if a.p.ledgerPerRole {
		a.p.psCalls += len(ids) - 1
	}
	if a.p.psFail != nil && !a.p.ledgerSwallow {
		return nil, a.p.psFail
	}
	out := map[domain.RoleID][]domain.PrunedSelectorType{}
	for _, id := range ids {
		if g, ok := a.p.pruned[string(id)]; ok {
			out[id] = g
		}
	}
	return out, nil
}

// matches — есть ли у роли строка проекции под этот сегмент. Якорь (глагол не
// назван) удовлетворяется ЛЮБОЙ строкой своего типа.
func (f *roleListFakeRepo) matches(d domain.RoleSegment) bool {
	if d.Verb != "" {
		return f.projected[string(d.RoleID)+"|"+d.ObjectType+"|"+d.Verb]
	}
	for k := range f.projected {
		if strings.HasPrefix(k, string(d.RoleID)+"|"+d.ObjectType+"|") {
			return true
		}
	}
	return false
}

// List mirrors the pg repo's filter contract: AccountID scopes to system +
// that Account's custom roles. Read VISIBILITY is deliberately NOT a predicate
// here (same as the pg repo) — the use-case resolves it per-object over the
// returned page (internal/authzfilter), so the fake must hand back the
// UNFILTERED page for the use-case's filter to be exercised at all.
func (a *roleListReader) List(ctx context.Context, f reporole.ListFilter) ([]domain.Role, string, error) {
	a.p.lastFilter = f
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

// ───────────── relation-queries stub ─────────────

// fgaObjectID extracts the bare id from an object string
// ("iam_role:rol-c1" → "rol-c1"). Shared by the package's Check stubs.
func fgaObjectID(object string) string {
	for i := 0; i < len(object); i++ {
		if object[i] == ':' {
			return object[i+1:]
		}
	}
	return object
}

// roleFGAStub — stub clients.RelationQueries.
//
// The counters are kept because the question they now count — the per-object one —
// is the question production asks; they used to be incremented by an enumeration
// door as well, and that door is gone. A counter with no producer would make
// "nothing was asked" true by construction of this type and unable to go red.
type roleFGAStub struct {
	clients.RelationQueries
	mu           sync.Mutex // the per-object Check port is called concurrently
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

// CheckWithContext — the DIRECT per-object question the use-case asks
// (internal/authzfilter).
//
// The grant-set is relation-agnostic: the same ids answer for `viewer` AND
// `v_list`, so the use-case's viewer ∪ v_list union is exercised without these
// older tests caring which relation surfaced the role.
func (s *roleFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.relations[relation]++
	s.lastSubject = subject
	s.lastRelation = relation
	s.lastObjType = object[:len(object)-len(fgaObjectID(object))-1]
	if s.err != nil {
		return false, s.err
	}
	id := fgaObjectID(object)
	for _, got := range s.idsBySubject[subject] {
		if got == id {
			return true, nil
		}
	}
	return false, nil
}

// ───────────── tests ─────────────

// read-relations + object type: the per-object filter MUST query BOTH the `viewer`
// tier relation (cascades from account-tier — account-admin sees own role, like
// account/project List) AND the `v_list` verb relation (object-only selector grant,
// selector-without-content) on iam_role — the Design-B viewer ∪ v_list union.
func TestListRoles_UsesViewerAndVListRelationsOnIamRole(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A000000000000000")
	// A second, UNGRANTED custom role: the per-object union short-circuits on a
	// `viewer` allow, so the `v_list` arm is only reachable via a role `viewer`
	// denies. Without this row the union's second branch would never be exercised.
	seedCustomRole(repo, "rol-c2", "acc-A000000000000000")

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-c1"})

	uc := NewListRolesUseCase(repo, catalogfixture.Source()).WithRelationStore(fga)
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
// grant-set. Custom roles require a grant.
func TestListRoles_D40_SystemRolesAlwaysVisible_CustomFiltered(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedSystemRole(repo, "rol-sys2")
	seedCustomRole(repo, "rol-c1", "acc-A000000000000000")

	fga := newRoleFGAStub() // empty grant-set for the caller
	uc := NewListRolesUseCase(repo, catalogfixture.Source()).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-sys2"}, roleIDs(out),
		"system roles always visible (catalog floor); ungranted custom role hidden")
}

// LST-2 byName / LST-4 union: exactly the granted custom ids resolve → List
// shows system ∪ granted-custom.
func TestListRoles_D41_D43_CustomByGrant_Union(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-c1", "acc-A000000000000000")
	seedCustomRole(repo, "rol-c2", "acc-A000000000000000")
	seedCustomRole(repo, "rol-c3", "acc-A000000000000000") // not granted

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-c1", "rol-c2"})

	uc := NewListRolesUseCase(repo, catalogfixture.Source()).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-c1", "rol-c2"}, roleIDs(out),
		"system ∪ granted custom (rol-c3 ungranted → hidden, LST-4 union / LST-2 byName)")
}

// LST-5 no-leak: an ungranted custom role is absent from List (existence not leaked).
func TestListRoles_D44_NoLeak_UngrantedCustomAbsent(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-cZ", "acc-A000000000000000") // foreign / ungranted

	fga := newRoleFGAStub() // no grant
	uc := NewListRolesUseCase(repo, catalogfixture.Source()).WithRelationStore(fga)

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
	seedCustomRole(repo, "rol-cA", "acc-A000000000000000")
	seedCustomRole(repo, "rol-cB", "acc-B000000000000000") // foreign account

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-cA", "rol-cB"}) // even if the model would allow both

	uc := NewListRolesUseCase(repo, catalogfixture.Source()).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100, AccountID: domain.AccountID("acc-A000000000000000")})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-cA"}, roleIDs(out),
		"#185: accountId=acc-A000000000000000 → system + acc-A000000000000000 custom only; acc-B000000000000000 custom never visible")
	require.Equal(t, domain.AccountID("acc-A000000000000000"), repo.lastFilter.AccountID,
		"accountId scope is pushed into the repo filter")
}

// D-47 fail-closed: a question that could not be answered → Unavailable, never an
// unfiltered list.
func TestListRoles_D47_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-c1", "acc-A000000000000000")

	fga := newRoleFGAStub()
	fga.err = stderrors.New("relation form did not answer: connection closed")

	uc := NewListRolesUseCase(repo, catalogfixture.Source()).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.Error(t, err, "an unanswered question must NOT return a (degraded) list")
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(), "unanswered → UNAVAILABLE fail-closed (D-47)")
}

// nil relation port → fail-closed Unavailable (never an unfiltered catalog leak).
func TestListRoles_D47_NilFGA_FailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A000000000000000")

	uc := NewListRolesUseCase(repo, catalogfixture.Source()) // NO WithRelationStore
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.Error(t, err)
	require.Empty(t, out)
	st, _ := status.FromError(err)
	require.Equal(t, codes.Unavailable, st.Code(), "nil relation port → fail-closed Unavailable")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take.
//
// The refusal above authzfilter.MaxBatchChecksPerRequest keeps the stub from being
// SLACKER than the declaration it stands behind: that constant is the partition size
// authzfilter itself declares and splits a page against, so a filter that stopped
// honouring its own declaration goes red here instead of quietly changing the shape
// of the request. An error, never a trim — a short answer is indistinguishable from
// a page of denials.
func (s *roleFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batch of %d objects exceeds the declared partition size %d",
			len(objects), authzfilter.MaxBatchChecksPerRequest)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := s.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
// Visibility — структурные факты о вызывающем, объявленные НЕСУЖЁННЫМИ.
//
// Это НАМЕРЕННО снисходительнее продукта, и цена названа вслух: строк выдачи у
// этой фикстуры нет вовсе (её гранты живут только в дублёре стора отношений),
// поэтому назвать кандидатов она не может — а сузив набор до пустого, вернула бы
// пустую страницу везде и стёрла бы ровно то, о чём эти пробы спрашивают.
//
// Отсюда граница: предмет проб этого пакета — ВЕРДИКТ (каким отношением судится
// строка страницы, как ведут себя полы, что происходит на отказе стора). ОТБОР
// кандидатов они не проверяют и проверять не могут; он проверяется на настоящем
// Postgres и настоящей модели прав —
// services/iam/internal/apps/kacho/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
func (r *roleListFakeReader) Visibility() visibility.ReaderIface { return roleUnrestrictedVisibility{} }

// roleUnrestrictedVisibility — «кандидаты не сужаются»: Candidates(...) вернёт nil,
// и репозиторий не получит ни одного предиката отбора.
type roleUnrestrictedVisibility struct{}

func (roleUnrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}

// Lifecycles — дублёр: жизненное состояние ролей этот путь не спрашивает.
// Пустая карта означает «не вычислено», и вызывающий оставляет нулевое
// состояние — ровно то, что дублёр обязан отдавать о величине, которой не
// владеет.
func (*roleListReader) Lifecycles(_ context.Context, _ []domain.RoleID) (
	map[domain.RoleID]domain.RoleLifecycle, error) {
	return nil, nil
}
