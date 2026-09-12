// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// limit_integration_test.go — issue #291 S1: the invariants of a resource-count
// ceiling that only a real database can answer for.
//
// Three of them are the reason this file exists, and none is visible to a unit
// test:
//
//   - the triple is unique among the limits IN FORCE (a partial index), so a
//     withdrawn ceiling neither blocks a new one nor lingers as a second row in
//     force. A software guard would let two writers both observe "free";
//   - the revision advances on a CHANGE and stands still on a restatement, and it
//     is assigned under a lock held to commit, so its order is the order of
//     commits rather than the order of nextval calls;
//   - the reference from a limit to its account or project is a polymorphic one,
//     so it is held by a trigger rather than by a foreign key — on the insert side
//     with a locking probe, on the delete side by withdrawing what pointed at the
//     departing row.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/pgtest"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// newLimitRepo — a fresh database plus the adapter under test.
func newLimitRepo(t *testing.T) (*kanamepg.LimitRepo, *pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие пула — С ПРЕДЕЛОМ, а не отложенным вызовом. Отложенное ждёт
	// соединение, которое проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, и уносит с собой вердикт всего пакета.
	pgtest.ClosePoolAtEnd(t, pool)
	return kanamepg.NewLimitRepo(pool), pool, ctx
}

// seedLimitScopeObjects — one account with one project inside it, written with
// plain SQL.
//
// The seed is deliberate about ORDER: `accounts.owner_user_id` is a deferrable
// reference, so the user and the account may be written in either order within one
// transaction, and the project follows its account.
func seedLimitScopeObjects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (accountID, projectID string) {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	accountID = ids.NewID(domain.PrefixAccount)
	projectID = ids.NewID(domain.PrefixProject)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		uid, accountID, "ext-lim-"+suffix+"-"+uid, "lim-"+suffix+"@example.com", "Limit Fixture "+suffix)
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accountID, "lim-acc-"+suffix, uid)
	require.NoError(t, err, "seed account")

	_, err = tx.Exec(ctx, `
		INSERT INTO projects (id, account_id, name, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		projectID, accountID, "lim-prj-"+suffix)
	require.NoError(t, err, "seed project")

	require.NoError(t, tx.Commit(ctx), "commit limit fixture")
	return accountID, projectID
}

func newLimit(scope domain.LimitScope, scopeID string, kind domain.LimitKind, value int64) domain.Limit {
	return domain.Limit{
		ID:      domain.LimitID(ids.NewHyphenID(ids.PrefixLimitHyphen)),
		Scope:   scope,
		ScopeID: scopeID,
		Kind:    kind,
		Value:   value,
	}
}

// TestLimit_01_InsertGet_RoundTrip — VPCQ-01's storage half: what went in comes
// back, and the two values the DATABASE assigns (created_at, revision) are there.
func TestLimit_01_InsertGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "roundtrip")

	in := newLimit(domain.LimitScopeProject, prj, "vpc.network", 4)
	created, err := repo.Insert(ctx, in)
	require.NoError(t, err)
	require.Equal(t, in.ID, created.ID)
	require.Len(t, string(created.ID), 21, "id form is lim- + 17 body chars")
	require.Equal(t, int64(4), created.Value)
	require.False(t, created.CreatedAt.IsZero(), "created_at is assigned by the database")
	require.Positive(t, created.Revision, "revision is assigned by the trigger, not by the caller")
	require.False(t, created.Withdrawn())

	got, err := repo.Get(ctx, in.ID)
	require.NoError(t, err)
	require.Equal(t, created, got)
}

// TestLimit_04_AbsentID_NotFoundLane — VPCQ-04: a well-formed id with no row
// answers on the DIRECT-READ lane, with the contract tone AND the machine token.
//
// Both halves are asserted because they can drift apart: the code is what the edge
// maps to a status, the token is what a client keys on, and prose is neither.
func TestLimit_04_AbsentID_NotFoundLane(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, _, ctx := newLimitRepo(t)

	absent := domain.LimitID(ids.NewHyphenID(ids.PrefixLimitHyphen))
	_, err := repo.Get(ctx, absent)
	require.Error(t, err)

	st, ok := grpcstatus.FromError(err)
	require.True(t, ok, "the refusal must carry a gRPC status")
	require.Equal(t, codes.NotFound, st.Code())
	require.Equal(t, fmt.Sprintf("Limit %s not found", absent), st.Message())
	require.Equal(t, "RESOURCE_NOT_FOUND", reasonToken(t, st))
}

// TestLimit_06_DuplicateTriple_AlreadyExists — VPCQ-06: the triple is unique among
// the ceilings in force, and the promise is the database's.
func TestLimit_06_DuplicateTriple_AlreadyExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "dup")

	_, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 4))
	require.NoError(t, err)

	_, err = repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 8))
	require.Error(t, err)
	require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists),
		"a second ceiling on the same triple must be refused, got %v", err)
}

// TestLimit_06b_WithdrawnTripleIsFree — the partial index in one assertion: a
// withdrawn ceiling does not hold the slot.
//
// This is the whole reason the index is partial. Without it a ceiling withdrawn by
// mistake could never be stated again, and the only remedy would be editing the
// database by hand.
func TestLimit_06b_WithdrawnTripleIsFree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "reissue")

	first, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.subnet", 4))
	require.NoError(t, err)

	_, existed, err := repo.Withdraw(ctx, first.ID)
	require.NoError(t, err)
	require.True(t, existed)

	second, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.subnet", 9))
	require.NoError(t, err, "a withdrawn ceiling must not hold the triple")
	require.NotEqual(t, first.ID, second.ID)

	// The withdrawn one reads as absent; the new one reads as itself.
	_, err = repo.Get(ctx, first.ID)
	require.Error(t, err, "a withdrawn ceiling reads as absent")
	got, err := repo.Get(ctx, second.ID)
	require.NoError(t, err)
	require.Equal(t, int64(9), got.Value)
}

// TestLimit_07_ScopeSubjectMustExist — VPCQ-07: a ceiling may not be stated for an
// account or a project that is not there, and the refusal is the DIRECT-READ lane,
// because both are iam's OWN rows.
//
// FAILED_PRECONDITION would be the answer for a real foreign key — a peer's
// precondition — and there is no peer here.
func TestLimit_07_ScopeSubjectMustExist(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, _, ctx := newLimitRepo(t)

	absentProject := ids.NewID(domain.PrefixProject)
	_, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, absentProject, "vpc.network", 4))
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.NotFound, st.Code())
	require.Equal(t, fmt.Sprintf("Project %s not found", absentProject), st.Message())
	require.Equal(t, "RESOURCE_NOT_FOUND", reasonToken(t, st))

	absentAccount := ids.NewID(domain.PrefixAccount)
	_, err = repo.Insert(ctx, newLimit(domain.LimitScopeAccount, absentAccount, "vpc.network", 4))
	require.Error(t, err)
	st, ok = grpcstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.NotFound, st.Code())
	require.Equal(t, fmt.Sprintf("Account %s not found", absentAccount), st.Message())
}

// TestLimit_08_PrecedenceAndFallback — VPCQ-08: PROJECT beats ACCOUNT beats
// DEFAULT, and withdrawing the winner hands the answer to the next scope.
//
// The DEFAULT rows are NOT written by this test — they are the seed the migration
// ships, and asserting against them is the point: the platform's numbers live in
// exactly one place, and this is the read that proves the place is reachable.
func TestLimit_08_PrecedenceAndFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	acc, prj := seedLimitScopeObjects(t, ctx, pool, "precedence")

	// Seeded platform default for vpc.network is 16 (migration 0092).
	require.Equal(t, int64(16), effectiveValue(t, ctx, repo, prj, "vpc.network"),
		"with nothing stated for the tenant, the platform default answers")

	accLimit, err := repo.Insert(ctx, newLimit(domain.LimitScopeAccount, acc, "vpc.network", 8))
	require.NoError(t, err)
	require.Equal(t, int64(8), effectiveValue(t, ctx, repo, prj, "vpc.network"),
		"the account overrides the platform default")

	prjLimit, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 4))
	require.NoError(t, err)
	require.Equal(t, int64(4), effectiveValue(t, ctx, repo, prj, "vpc.network"),
		"the project overrides the account")

	// A kind with nothing stated for the tenant still answers from the default —
	// the answer is per KIND, not per tenant.
	require.Equal(t, int64(64), effectiveValue(t, ctx, repo, prj, "vpc.subnet"))

	// Withdrawal hands the answer back, one scope at a time.
	_, _, err = repo.Withdraw(ctx, prjLimit.ID)
	require.NoError(t, err)
	require.Equal(t, int64(8), effectiveValue(t, ctx, repo, prj, "vpc.network"))

	_, _, err = repo.Withdraw(ctx, accLimit.ID)
	require.NoError(t, err)
	require.Equal(t, int64(16), effectiveValue(t, ctx, repo, prj, "vpc.network"))

	// Посев миграции доезжает до резолва ЦЕЛИКОМ: по строке на каждый вид
	// каталога домена, и каждая строка называет носителя из каталога.
	//
	// ПОЧЕМУ ПРЕЖНЕЕ ОЖИДАНИЕ БЫЛО НЕВЕРНЫМ. Здесь недолго стоял отбор по
	// носителю — засчитывались только виды корня аренды, и проба требовала
	// восьми строк из двенадцати. Она закрепляла ДЕФЕКТ, а не свойство:
	// вырезание вложенных видов лишало владельца типа единственного источника,
	// из которого берётся снимок при заведении родителя. Родитель заводился без
	// строки учёта, и первый же ребёнок получал отказ «потолок не назван» при
	// потолке, названном умолчанием каталога; на сквозном прогоне это
	// останавливало создание слушателей и репозиториев целиком.
	//
	// Беда, ради которой отбор вводился, закрывается не вырезанием, а полем
	// носителя: оно едет вместе с величиной, и потребитель разводит по нему учёт
	// корня аренды и умолчание вложенности.
	//
	// ПОЧЕМУ ПАРА, А НЕ ЧИСЛО. На одном числе строк обе стороны ошибки остаются
	// зелёными: потерянный вид даёт отказ создать ребёнка, подменённый носитель —
	// строку учёта, которая не наполнится никогда, и оба дефекта сохраняют
	// длину ответа. Поэтому утверждается пара «вид и носитель».
	//
	// ПРЕДМЕТ ИМЕННО ЭТОЙ ПРОБЫ — что до резолва доезжает ПОСЕВ: виды берутся из
	// каталога, величины из базы, и ни один вид каталога в ответе не пропущен.
	// Что посев покрывает каждый АВТОРИТЕТНЫЙ вид (и ни одного вида посадки),
	// держит TestLimit_SeedCoversTheAuthorityKindsAndOnlyThem;
	// что резолв не путает носителя на синтетике — пробы домена.
	wantCarrier := map[domain.LimitKind]domain.LimitCarrier{}
	nested := 0
	for _, k := range domain.CountableKindsOfService("vpc") {
		c, known := domain.CarrierOfKind(k)
		require.Truef(t, known, "вид %q каталога не объявил носителя", k)
		wantCarrier[k] = c
		if c != domain.CarrierProject && c != domain.CarrierAccount {
			nested++
		}
	}
	require.NotEmpty(t, wantCarrier, "каталог не назвал ни одного вида домена vpc")
	require.NotZero(t, nested,
		"у домена vpc не осталось видов, считаемых в родителе: проба стала вакуумной, "+
			"и её надо снимать вместе с предметом, а не держать зелёной")

	stated, ok, err := repo.StatedFor(ctx, prj)
	require.NoError(t, err)
	require.True(t, ok)

	gotCarrier := map[domain.LimitKind]domain.LimitCarrier{}
	for _, e := range domain.ResolveEffective("vpc", stated) {
		gotCarrier[e.Kind] = e.Carrier
	}
	require.Equal(t, wantCarrier, gotCarrier,
		"резолв обязан ответить по строке на КАЖДЫЙ вид каталога домена и назвать "+
			"носителя из каталога")

	t.Logf("перепись: видов каталога vpc %d, из них считаемых в родителе %d, строк в ответе %d",
		len(wantCarrier), nested, len(gotCarrier))
}

// TestLimit_08b_ResolveByAccountId — the same read addressed by an ACCOUNT: the
// project arm cannot win because there is no project, and the account arm does.
//
// The kind of object is established by LOOKING IT UP; nothing here reads a prefix.
func TestLimit_08b_ResolveByAccountId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	acc, prj := seedLimitScopeObjects(t, ctx, pool, "byaccount")

	_, err := repo.Insert(ctx, newLimit(domain.LimitScopeAccount, acc, "vpc.network", 8))
	require.NoError(t, err)
	_, err = repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 4))
	require.NoError(t, err)

	require.Equal(t, int64(8), effectiveValue(t, ctx, repo, acc, "vpc.network"),
		"asked about the ACCOUNT, a project's override must not win")

	// An id that names neither a project nor an account is not a scope object.
	_, ok, err := repo.StatedFor(ctx, ids.NewID(domain.PrefixProject))
	require.NoError(t, err)
	require.False(t, ok)
}

// TestLimit_11_RevisionMovesOnChangeOnly — VPCQ-11: the delta reports changes and
// only changes.
//
// The negative half is the load-bearing one. A revision that advanced on every
// write would make an idempotent re-assignment — the ordinary shape of a
// configuration tool running twice — look like a change to every puller, and the
// projection of every owner service would be rebuilt for nothing.
func TestLimit_11_RevisionMovesOnChangeOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "delta")

	first, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 4))
	require.NoError(t, err)
	cursor := first.Revision

	second, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.subnet", 8))
	require.NoError(t, err)
	require.Greater(t, second.Revision, first.Revision)

	changed, next, err := repo.ChangedSince(ctx, cursor, 100)
	require.NoError(t, err)
	require.Len(t, changed, 1, "only what happened after the cursor")
	require.Equal(t, second.ID, changed[0].ID)
	require.Equal(t, second.Revision, next)

	// A restatement of the SAME value moves nothing.
	same, err := repo.Update(ctx, second.ID, 8)
	require.NoError(t, err)
	require.Equal(t, second.Revision, same.Revision,
		"a write that restates the value must not move the revision")
	changed, _, err = repo.ChangedSince(ctx, next, 100)
	require.NoError(t, err)
	require.Empty(t, changed, "a restatement must not appear in the delta")

	// A real change moves it, and the entry carries the new value.
	raised, err := repo.Update(ctx, second.ID, 9)
	require.NoError(t, err)
	require.Greater(t, raised.Revision, second.Revision)
	changed, next, err = repo.ChangedSince(ctx, next, 100)
	require.NoError(t, err)
	require.Len(t, changed, 1)
	require.Equal(t, int64(9), changed[0].Value)

	// A withdrawal is a change too, and it is carried EXPLICITLY — a puller that
	// only ever learned about writes could never drop a projection row.
	_, _, err = repo.Withdraw(ctx, second.ID)
	require.NoError(t, err)
	changed, _, err = repo.ChangedSince(ctx, next, 100)
	require.NoError(t, err)
	require.Len(t, changed, 1)
	require.True(t, changed[0].Withdrawn(), "the delta must report the withdrawal")
	require.Equal(t, second.ID, changed[0].ID, "and it must name the triple to drop")
}

// TestLimit_12_ProjectDeleteWithdrawsItsLimits — VPCQ-12: a departing scope object
// takes the ceilings stated for it, and touches nothing else.
//
// The second half is the one that would be missed: a teardown that also withdrew
// the account's or the platform's rows would silently un-limit every OTHER tenant.
func TestLimit_12_ProjectDeleteWithdrawsItsLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	acc, prj := seedLimitScopeObjects(t, ctx, pool, "teardown")

	prjA, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 4))
	require.NoError(t, err)
	prjB, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.subnet", 8))
	require.NoError(t, err)
	accLimit, err := repo.Insert(ctx, newLimit(domain.LimitScopeAccount, acc, "vpc.network", 8))
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, prj)
	require.NoError(t, err, "a stated ceiling must not hold a project hostage")

	for _, id := range []domain.LimitID{prjA.ID, prjB.ID} {
		_, gerr := repo.Get(ctx, id)
		require.Error(t, gerr, "the project's ceilings must be withdrawn with it")
	}
	stillThere, err := repo.Get(ctx, accLimit.ID)
	require.NoError(t, err, "the account's ceiling is not the project's")
	require.Equal(t, int64(8), stillThere.Value)

	// The platform defaults are untouched — measured, not assumed.
	//
	// СВЕРЯЕТСЯ С АВТОРИТЕТНОЙ ПОЛОВИНОЙ каталога, а не с ним целиком (`П25`,
	// задача продукта #2117): у трёх видов, чей владелец — сама служба доступа,
	// величина приходит из посадки, и посева у них нет НАМЕРЕННО.
	//
	// Здесь стояло `len(domain.CountableKinds())`, и разница ровно в эти три вида
	// — перемерено предикатом, а не на глаз: каталог 27 = авторитетных 24 +
	// посадки 3, и три недостающих в отказе назывались поимённо теми же тремя.
	//
	// Утверждение НЕ ослаблено: оно по-прежнему требует, чтобы снос арендатора не
	// задел НИ ОДНОГО умолчания платформы. Сузилось множество, о котором оно
	// делается, — и сузилось до того, которое посев вообще заводит. Что множество
	// это полно и не содержит лишнего, держит соседняя
	// `TestLimit_SeedCoversTheAuthorityKindsAndOnlyThem`.
	rows, _, err := repo.List(ctx, 100, "", domain.LimitFilter{Scope: domain.LimitScopeDefault})
	require.NoError(t, err)
	require.NotEmpty(t, domain.AuthorityStatedKinds(),
		"авторитетных видов ноль — утверждение о выживании умолчаний стало вакуумным")
	require.Len(t, rows, len(domain.AuthorityStatedKinds()),
		"every seeded default must survive a tenant teardown")
}

// TestLimit_ConcurrentSameTriple_ExactlyOneWinner — the race the partial UNIQUE
// exists for. A software "read then write" guard would let both writers observe
// "free" and both insert.
func TestLimit_ConcurrentSameTriple_ExactlyOneWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "race")

	const writers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		wins    int
		refused int
		other   []error
	)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			_, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.address", int64(n+1)))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case stderrors.Is(err, iamerr.ErrAlreadyExists):
				refused++
			default:
				other = append(other, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	require.Empty(t, other, "every loser must lose with ALREADY_EXISTS, not with something else")
	require.Equal(t, 1, wins, "exactly one writer may state the ceiling")
	require.Equal(t, writers-1, refused)
}

// TestLimit_ZeroIsLegalAndNegativeIsNot — zero means "none of this kind", which is
// a decision an administrator may make; a negative ceiling is not a decision.
//
// The DB CHECK is asserted from OUTSIDE the domain validator on purpose: the
// validator gives the caller a named field, and the constraint makes the state
// inexpressible for every writer, including the ones that do not exist yet.
func TestLimit_ZeroIsLegalAndNegativeIsNot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "bounds")

	zero, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.gateway", 0))
	require.NoError(t, err, "zero is a legal ceiling")
	require.Equal(t, int64(0), zero.Value)

	_, err = repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.routeTable", -1))
	require.Error(t, err, "a negative ceiling must be inexpressible")
	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "got %v", err)
}

// TestLimit_DeltaCursorCodec — the cursor round-trips, and garbage is refused
// rather than read as "from the beginning".
//
// Treating an unreadable cursor as zero is the failure this asserts against: it
// would replay the entire history and look exactly like a healthy first run.
func TestLimit_DeltaCursorCodec(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, _, _ := newLimitRepo(t)

	for _, rev := range []int64{0, 1, 4096} {
		got, err := repo.Decode(repo.Encode(rev))
		require.NoError(t, err)
		require.Equal(t, rev, got)
	}

	empty, err := repo.Decode("")
	require.NoError(t, err, "an empty cursor means 'from the beginning of time'")
	require.Equal(t, int64(0), empty)

	for _, bad := range []string{"not-a-cursor", "!!!", repo.Encode(1) + "x"} {
		_, derr := repo.Decode(bad)
		require.Errorf(t, derr, "a cursor this codec did not produce must be refused: %q", bad)
		require.True(t, stderrors.Is(derr, iamerr.ErrInvalidArg))
	}
}

// effectiveValue — the resolved ceiling for one kind, through the same two steps
// the use-case takes.
func effectiveValue(t *testing.T, ctx context.Context, repo *kanamepg.LimitRepo, scopeID string, kind domain.LimitKind) int64 {
	t.Helper()
	stated, ok, err := repo.StatedFor(ctx, scopeID)
	require.NoError(t, err)
	require.True(t, ok, "scope object %s must exist", scopeID)
	for _, e := range domain.ResolveEffective(kind.Service(), stated) {
		if e.Kind == kind {
			return e.Value
		}
	}
	t.Fatalf("no effective ceiling resolved for %s", kind)
	return 0
}

// reasonToken — the machine-readable lane token from the refusal's details.
//
// Asserted separately from the code because the two can drift: a client keys on
// the token, and a refusal that carries the right code with no token is a refusal
// the client cannot classify.
func reasonToken(t *testing.T, st *grpcstatus.Status) string {
	t.Helper()
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			require.Equal(t, "iam.kacho.cloud", info.GetDomain())
			return info.GetReason()
		}
	}
	t.Fatalf("refusal carries no ErrorInfo — the lane is not machine-readable: %v", st)
	return ""
}

// TestLimit_SeedCoversTheAuthorityKindsAndOnlyThem — посев покрывает КАЖДЫЙ вид,
// чью величину назначает АВТОРИТЕТ, и НИ ОДНОГО вида, чью величину объявляет
// посадка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗДЕСЬ СТОЯЛО «у каждого вида каталога есть посеянное умолчание» — предмет уехал
//
// Утверждение было верно, пока величину всех видов назначал авторитет. Решение
// `П25` (приёмка `KAN-QUOTA-1`, задача продукта #2117) развело две роли: у трёх
// видов, чей владелец — сама служба доступа, величина приходит из ПОСАДКИ, и
// посев у них снят намеренно, новой миграцией.
//
// Проба не ослаблена и не расширена: вопрос задан ТОЧНЕЕ. «Каждый вид каталога»
// после `П25` неверно by construction, а «хотя бы один вид» перестало бы отличать
// полный посев от пустого. Обе половины утверждаются ПОИМЁННО и раздельно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВТОРАЯ ПОЛОВИНА — УТВЕРЖДЕНИЕ, А НЕ УМОЛЧАНИЕ
//
// «У трёх видов посева нет» обязано быть сказано ЯВНО. Вернувшаяся посевная
// строка на вид посадки — это класс «принято-и-проигнорировано»: администратор
// увидел бы величину, а списание её не читает, потому что читает проекцию
// посадки. Молчаливо такая строка не отличается от исправной работы.
//
// И ровно эта половина стережёт обратный случай, о котором иначе некому сказать:
// пропади посев у ЧЕТВЁРТОГО вида — он остаётся авторитетным, значит попадает в
// `Missing` и роняет пробу. Разбиение по роли не заводит слепой зоны.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОИМЁННО, А НЕ СЧЁТОМ (довод прежней редакции, он не устарел)
//
// Счёт строк зелёный и тогда, когда один вид потерян, а другой посеян дважды.
// Правило V2-3 «не сказано = ОТКАЗ» превращает потерянный посев в запрет
// создавать ресурсы этого вида — отказ, снаружи неотличимый от исправно
// работающей квоты.
//
// Посев живёт в миграции, каталог — в коде, и разъезжаются они молча: каталог
// растёт правкой Go-файла, а посев требует НОВОЙ миграции. Ровно этот шов и
// стережёт проба.
func TestLimit_SeedCoversTheAuthorityKindsAndOnlyThem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, _, ctx := newLimitRepo(t)

	c := seedCoverageByRole(t, ctx, repo)
	t.Logf("перепись: видов каталога %d — авторитетных %d, посадки %d; "+
		"посеяно строк DEFAULT %d; без посева %d, задвоенных %d, лишних у посадки %d, вне каталога %d",
		len(domain.CountableKinds()), len(domain.AuthorityStatedKinds()),
		len(domain.PostureStatedKinds()), c.SeededRows,
		len(c.Missing), len(c.Duplicated), len(c.Unexpected), len(c.Orphan))

	// Предпосылка: обе половины НЕПУСТЫ. На пустой любая из двух проверок ниже
	// выполняется тривиально, и «покрытие сошлось» перестаёт что-либо значить.
	require.NotEmpty(t, domain.AuthorityStatedKinds(),
		"авторитетных видов ноль — утверждение о покрытии посевом стало вакуумным")
	require.NotEmpty(t, domain.PostureStatedKinds(),
		"видов посадки ноль — вторая половина утверждения стала вакуумной")
	require.NotZero(t, c.SeededRows,
		"строк DEFAULT не прочитано ни одной: посев не применился, и «лишних нет» "+
			"здесь означало бы «ничего не осмотрено»")

	require.Emptyf(t, c.Missing,
		"АВТОРИТЕТНЫЙ вид каталога без посеянного умолчания: %v.\n"+
			"    По правилу «не сказано = ОТКАЗ» это запрет создавать ресурсы этого вида,\n"+
			"    неотличимый снаружи от исправно работающей квоты. Посев живёт в миграции,\n"+
			"    каталог — в коде; новый вид требует НОВОЙ миграции (применённую не правим).",
		c.Missing)
	require.Empty(t, c.Duplicated,
		"вид с двумя действующими умолчаниями: частичный UNIQUE обязан был это запретить")

	require.Emptyf(t, c.Unexpected,
		"у вида ПОСАДКИ есть посеянное умолчание: %v.\n"+
			"    Величину этих видов объявляет посадка службы, и списание читает ЕЁ.\n"+
			"    Посеянная строка была бы принята, сохранена и НЕ ПРИМЕНЕНА ни разу —\n"+
			"    администратор увидел бы величину, а арендатор прежний потолок (`П25`).",
		c.Unexpected)

	// Обратное направление: посеяно ровно то, что каталог называет, и ничего
	// сверх. Умолчание на вид вне каталога — потолок, который никто не читает.
	require.Emptyf(t, c.Orphan,
		"посеяно умолчание на вид вне каталога: %v — потолок, которого никто не применит",
		c.Orphan)
}

// TestLimit_SeedCoverageProbeCanFailInBothDirections — ДВЕ инъекции, у каждой
// свой законный близнец.
//
// Проба покрытия сама по себе не доказывает своей способности упасть: на
// исправной базе она зелёная, и зелёной же осталась бы, если бы читала не то.
//
// НАПРАВЛЕНИЙ ДВА, и одного мало. Прежняя редакция кормила пробу ровно одним
// дефектом — снятым посевом, — а второе утверждение («у вида посадки посева нет»)
// осталось бы без доказательства падаемости вовсе: оно молчаливо верно на всякой
// базе, где посева нет ни у кого.
//
// Близнецы РАЗВЕДЕНЫ по направлениям намеренно. Прежний близнец наследовал ту же
// предпосылку, что и его проба, — «недостающих нет по ВСЕМУ каталогу», — и потому
// упал вместе с ней, когда предмет уехал. Теперь каждый близнец утверждает свою
// половину и на чужой инъекции молчит.
func TestLimit_SeedCoverageProbeCanFailInBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	t.Run("снятый посев авторитетного вида — находка с ИМЕНЕМ", func(t *testing.T) {
		repo, pool, ctx := newLimitRepo(t)
		const victim = domain.LimitKind("registry.repositories")
		require.True(t, domain.IsCountableKind(victim) && !domain.IsPostureStatedKind(victim),
			"жертва инъекции обязана быть АВТОРИТЕТНЫМ видом каталога, иначе инъекция "+
				"вносит не тот дефект, который проверяет")

		// Законный близнец СВОЕЙ половины: недостающих авторитетных нет.
		base := seedCoverageByRole(t, ctx, repo)
		require.Empty(t, base.Missing,
			"законный близнец: на посеянной базе авторитетный вид без посева не найден")
		require.Empty(t, base.Unexpected,
			"контроль: инъекция первой половины не должна задевать вторую")

		_, err := pool.Exec(ctx,
			`DELETE FROM kaname.limits WHERE scope = 'DEFAULT' AND kind = $1`, string(victim))
		require.NoError(t, err)

		after := seedCoverageByRole(t, ctx, repo)
		require.Equal(t, []string{string(victim)}, after.Missing,
			"гейт обязан НАЗВАТЬ вид, чьё умолчание снято, а не просто покраснеть числом")
		require.Empty(t, after.Unexpected,
			"инъекция уронила ЧУЖУЮ половину: значит красное могло прийти не от "+
				"внесённого дефекта")
	})

	t.Run("вернувшийся посев вида посадки — находка с ИМЕНЕМ", func(t *testing.T) {
		repo, pool, ctx := newLimitRepo(t)
		victim := domain.PostureStatedKinds()[0]

		// Законный близнец СВОЕЙ половины: лишних у посадки нет.
		base := seedCoverageByRole(t, ctx, repo)
		require.Empty(t, base.Unexpected,
			"законный близнец: на посеянной базе посева на вид посадки нет")
		require.Empty(t, base.Missing,
			"контроль: инъекция второй половины не должна задевать первую")

		// Строка заводится ПРЯМО В ТАБЛИЦУ: предмет инъекции — что проба увидит
		// вернувшийся посев, а не что вход авторитета его отвергает (последнее
		// держит проба домена).
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.limits (id, scope, scope_id, kind, limit_value)
			VALUES ('lim-0000000000000000b', 'DEFAULT', '', $1, 7)`, string(victim))
		require.NoError(t, err)

		after := seedCoverageByRole(t, ctx, repo)
		require.Equal(t, []string{string(victim)}, after.Unexpected,
			"гейт обязан НАЗВАТЬ вид посадки, которому вернули посев: величина была бы "+
				"принята и не применена ни разу")
		require.Empty(t, after.Missing,
			"инъекция уронила ЧУЖУЮ половину: значит красное могло прийти не от "+
				"внесённого дефекта")
	})
}

// seedCoverage — покрытие посевом, разобранное ПО РОЛИ вида.
//
// Одна структура на оба направления: два обхода одной таблицы разошлись бы на
// первом же уточнении вопроса, и разошлись бы молча.
type seedCoverage struct {
	// Missing — АВТОРИТЕТНЫЙ вид без посеянного умолчания.
	Missing []string
	// Duplicated — вид с двумя действующими умолчаниями.
	Duplicated []string
	// Unexpected — вид ПОСАДКИ, которому посев вернули.
	Unexpected []string
	// Orphan — посеяно на вид вне каталога.
	Orphan []string
	// SeededRows — сколько строк DEFAULT прочитано. Без этого числа «лишних нет»
	// неотличимо от «ничего не осмотрено».
	SeededRows int
}

// seedCoverageByRole — предикат покрытия, вынесенный отдельно ровно затем, чтобы
// его можно было прогнать на повреждённой базе. Проверка, которую нельзя
// покормить настоящим дефектом, о своей способности упасть не утверждает ничего.
func seedCoverageByRole(t *testing.T, ctx context.Context, repo *kanamepg.LimitRepo) seedCoverage {
	t.Helper()
	rows, _, err := repo.List(ctx, 1000, "", domain.LimitFilter{Scope: domain.LimitScopeDefault})
	require.NoError(t, err)

	seeded := make(map[domain.LimitKind]int, len(rows))
	for _, r := range rows {
		seeded[r.Kind]++
	}

	c := seedCoverage{SeededRows: len(rows)}
	for _, k := range domain.CountableKinds() {
		n := seeded[k]
		if domain.IsPostureStatedKind(k) {
			if n > 0 {
				c.Unexpected = append(c.Unexpected, string(k))
			}
			continue
		}
		switch n {
		case 1:
		case 0:
			c.Missing = append(c.Missing, string(k))
		default:
			c.Duplicated = append(c.Duplicated, string(k))
		}
	}
	for k := range seeded {
		if !domain.IsCountableKind(k) {
			c.Orphan = append(c.Orphan, string(k))
		}
	}
	sort.Strings(c.Missing)
	sort.Strings(c.Duplicated)
	sort.Strings(c.Unexpected)
	sort.Strings(c.Orphan)
	return c
}

// TestLimit_NestedKindFormIsAccepted — схема принимает трёхчастный вид и
// по-прежнему отвергает четырёхчастный.
//
// Форма расширена миграцией 0094 аддитивно, поэтому утверждаются ОБА края:
// принятие нового и сохранение прежнего запрета. Без второй половины «форма
// расширена» было бы неотличимо от «проверка формы снята».
func TestLimit_NestedKindFormIsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	_, pool, ctx := newLimitRepo(t)
	_, prj := seedLimitScopeObjects(t, ctx, pool, "nestedform")

	insert := func(kind string) error {
		_, err := pool.Exec(ctx,
			`INSERT INTO kaname.limits (id, scope, scope_id, kind, limit_value)
			 VALUES ($1, 'PROJECT', $2, $3, 4)`,
			string(ids.NewHyphenID(ids.PrefixLimitHyphen)), prj, kind)
		return err
	}

	require.NoError(t, insert("vpc.network.subnet"),
		"трёхчастный вид обязан приниматься схемой — иначе предел на родителя невыразим")

	require.Error(t, insert("vpc.network.subnet.route"),
		"четыре части — предел на внука, у которого нет своего носителя; обязан отвергаться")
	require.Error(t, insert("vpcnetwork"),
		"законный близнец прежнего запрета: вид без точки по-прежнему отвергается")
}
