// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// account_delete_cycle_integration_test.go — арендатор снимает свой аккаунт
// (задача kaname#664, приёмка
// `docs/engineering/acceptance/own-account-and-identity-are-removed-in-order.md`,
// сценарии S2: KN664-10, 11, 13, 14, 15, 20).
//
// # Предмет
//
// Самостоятельно зарегистрированный арендатор не мог снять свой личный аккаунт:
// на аккаунт указывает колонка дома его же строки, ключ `users_account_fk` был
// `RESTRICT`, и `RESTRICT` в Postgres не откладывается. Проба исполняет
// НАСТОЯЩИЕ глаголы (`ProjectService.Delete`, `AccountService.Delete`) над
// миром, который заводит настоящая регистрация (`RegisterMirrorTx`), и судит
// исход операции, состояние строк и прямые факты модели прав
// (`kaname.relation_fact`, их наполняет и чистит триггер журнала намерений той
// же транзакцией).
//
// # Пары
//
// Каждое отрицание стоит рядом с положительным близнецом: снятие с проектом
// отказывает (KN664-11) там, где снятие без проекта проходит (KN664-10);
// указатели членства в снятом аккаунте уходят (KN664-14), а указатель того же
// человека в соседнем аккаунте остаётся.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// removalEnv — настоящая база, настоящий репозиторий и лента операций.
type removalEnv struct {
	pool *pgxpool.Pool
	repo *kanamepg.Repository
	ops  operations.Repo
}

func newRemovalEnv(t *testing.T) *removalEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &removalEnv{pool: pool, repo: kanamepg.New(pool, nil), ops: operations.NewRepo(pool, "kaname")}
}

// opOutcome — исход операции после завершения всех воркеров: код и текст
// ошибки; (0, "") — успех.
type opOutcome struct {
	code int32
	msg  string
}

func (o opOutcome) String() string {
	if o.code == 0 && o.msg == "" {
		return "ok"
	}
	return fmt.Sprintf("code=%d %q", o.code, o.msg)
}

func (e *removalEnv) outcome(t *testing.T, op *operations.Operation) opOutcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, operations.Wait(ctx), "операции не завершились в срок")
	got, err := e.ops.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, got.Done, "операция %s не завершилась", op.ID)
	if got.Error != nil {
		return opOutcome{code: got.Error.GetCode(), msg: got.Error.GetMessage()}
	}
	return opOutcome{}
}

func (e *removalEnv) deleteProject(t *testing.T, caller domain.UserID, prj domain.ProjectID) opOutcome {
	t.Helper()
	op, err := projectapp.NewDeleteProjectUseCase(e.repo, e.ops).Execute(principalCtx(caller), prj)
	require.NoError(t, err)
	return e.outcome(t, op)
}

func (e *removalEnv) deleteAccount(t *testing.T, caller domain.UserID, acc domain.AccountID) opOutcome {
	t.Helper()
	op, err := accountapp.NewDeleteAccountUseCase(e.repo, e.ops).Execute(principalCtx(caller), acc)
	require.NoError(t, err)
	return e.outcome(t, op)
}

func (e *removalEnv) deleteUser(t *testing.T, caller, uid domain.UserID) opOutcome {
	t.Helper()
	op, err := userapp.NewDeleteUserUseCase(e.repo, e.ops).Execute(principalCtx(caller), uid)
	require.NoError(t, err)
	return e.outcome(t, op)
}

// selfRegistered — человек, заведённый настоящей регистрацией: строка, личный
// аккаунт, проект по умолчанию, выдачи и намерения модели прав.
func (e *removalEnv) selfRegistered(t *testing.T, tag string) (domain.UserID, domain.AccountID, domain.ProjectID) {
	t.Helper()
	ctx := context.Background()
	uid, acc := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_kn664_"+tag, "kn664-"+tag+"@example.com")
	return uid, acc, defaultProjectOf(t, ctx, e.pool, acc)
}

// emptied — личный аккаунт, у которого снят проект по умолчанию (KN664-10, Дано).
func (e *removalEnv) emptied(t *testing.T, tag string) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid, acc, prj := e.selfRegistered(t, tag)
	require.Equal(t, opOutcome{}, e.deleteProject(t, uid, prj), "Дано: проект по умолчанию снят")
	return uid, acc
}

// seedMember — человек `M`, приглашённый и активированный: колонка дома = home,
// членство в home (его заводит зеркало строки) и в каждом из extra; указатель
// членства на каждый аккаунт — намерением в той же транзакции, как его кладёт
// продукт. Строка пароля — способ входа (kaname#608).
func (e *removalEnv) seedMember(t *testing.T, tag string, home domain.AccountID, extra ...domain.AccountID) domain.UserID {
	t.Helper()
	ctx := context.Background()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	tx, err := e.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'KN664 member', 'ACTIVE')`,
		string(uid), string(home), "ext-kn664-"+tag+"-"+string(uid), "kn664-"+tag+"-member@example.com")
	require.NoError(t, err, "Дано: строка участника")
	for _, acc := range extra {
		_, err = tx.Exec(ctx, `
			INSERT INTO kaname.memberships (id, user_id, account_id, state)
			VALUES (kaname.membership_mirror_id($1, $2), $1, $2, 'ACTIVE')`, string(uid), string(acc))
		require.NoError(t, err, "Дано: членство участника в %s", acc)
	}
	activewayin.Seed(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))

	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	var tuples []service.RelationTuple
	for _, acc := range append([]domain.AccountID{home}, extra...) {
		tuples = append(tuples, service.RelationTuple{
			User: "account:" + string(acc), Relation: "account", Object: "iam_user:" + string(uid),
		})
	}
	require.NoError(t, w.EmitFGARelationWrite(ctx, tuples))
	require.NoError(t, w.Commit(ctx))
	return uid
}

// membershipPointers — прямые факты «указатель членства» человека, строками
// `iam_user:<u>#account@account:<A>`.
func membershipPointers(t *testing.T, pool *pgxpool.Pool, uid domain.UserID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT object_type || ':' || object_id || '#' || relation || '@' || subject
		  FROM kaname.relation_fact
		 WHERE object_type = 'iam_user' AND object_id = $1 AND relation = 'account'
		 ORDER BY 1`, string(uid))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

func pointer(uid domain.UserID, acc domain.AccountID) string {
	return "iam_user:" + string(uid) + "#account@account:" + string(acc)
}

func countRows(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), q, args...).Scan(&n))
	return n
}

// firstValue — первое значение одноколоночного чтения либо "" (строк нет):
// исход гонки читается и тогда, когда держащего не осталось, и сравнение
// с ожидаемым текстом решает исход, а не отказ чтения.
func firstValue(t *testing.T, pool *pgxpool.Pool, q string, args ...any) string {
	t.Helper()
	var v string
	err := pool.QueryRow(context.Background(), q, args...).Scan(&v)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)
	return v
}

// firstProjectOf — наименьший id проекта аккаунта: его называет отказ снятия
// аккаунта (kaname#725, Р1).
func firstProjectOf(t *testing.T, pool *pgxpool.Pool, acc domain.AccountID) string {
	return firstValue(t, pool, `SELECT id FROM kaname.projects WHERE account_id = $1 ORDER BY id LIMIT 1`, string(acc))
}

// ownedAccountOf — наименьший id аккаунта во владении человека: его называет
// отказ снятия человека (kaname#725, Р1).
func ownedAccountOf(t *testing.T, pool *pgxpool.Pool, uid domain.UserID) string {
	return firstValue(t, pool, `SELECT id FROM kaname.accounts WHERE owner_user_id = $1 ORDER BY id LIMIT 1`, string(uid))
}

func memberships(t *testing.T, pool *pgxpool.Pool, uid domain.UserID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT account_id FROM kaname.memberships WHERE user_id = $1 ORDER BY 1`, string(uid))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestKN664_10_OwnerRemovesTheEmptyPersonalAccount — KN664-10 (+ KN664-17:
// исход глагола от вызывающего не зависит, его права решает край).
func TestKN664_10_OwnerRemovesTheEmptyPersonalAccount(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid, acc := e.emptied(t, "10")
	require.Equal(t, []string{string(acc)}, memberships(t, e.pool, uid), "предпосылка: U — участник A")

	require.Equal(t, opOutcome{}, e.deleteAccount(t, uid, acc),
		"владелец снимает пустой личный аккаунт — операция обязана завершиться успешно")

	rd, err := e.repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	_, err = rd.Accounts().Get(ctx, acc)
	require.Error(t, err)
	require.Equal(t, "Account "+string(acc)+" not found", iamerr.StripSentinel(err))
	got, err := rd.Users().Get(ctx, uid)
	require.NoError(t, err, "человек переживает свой аккаунт")
	require.Equal(t, uid, got.ID)
	require.Empty(t, got.AccountID, "колонка дома пуста: аккаунта нет")
	require.Empty(t, memberships(t, e.pool, uid), "членства в снятом аккаунте нет")
}

// TestKN664_11_AccountWithAProjectIsRefused — KN664-11, близнец KN664-10.
func TestKN664_11_AccountWithAProjectIsRefused(t *testing.T) {
	e := newRemovalEnv(t)
	uid, acc, prj := e.selfRegistered(t, "11")

	require.Equal(t, opOutcome{code: 9, msg: "Account " + string(acc) + " contains projects and cannot be deleted: delete Project " +
		string(prj) + " first (projects: 1)"},
		e.deleteAccount(t, uid, acc))
	require.Equal(t, 1, countRows(t, e.pool, `SELECT count(*) FROM kaname.accounts WHERE id = $1`, string(acc)))
	require.Equal(t, []string{string(acc)}, memberships(t, e.pool, uid), "членство U в A на месте")
}

// TestKN664_13_MemberWhoseHomeIsTheAccountStays — KN664-13.
func TestKN664_13_MemberWhoseHomeIsTheAccountStays(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid, acc := e.emptied(t, "13")
	_, other := e.emptied(t, "13b")
	member := e.seedMember(t, "13", acc, other)
	require.ElementsMatch(t, []string{string(acc), string(other)}, memberships(t, e.pool, member),
		"предпосылка: M — участник A и B")

	require.Equal(t, opOutcome{}, e.deleteAccount(t, uid, acc))

	rd, err := e.repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Users().Get(ctx, member)
	require.NoError(t, err, "участник, чей дом — снятый аккаунт, остаётся")
	require.Empty(t, got.AccountID, "дом участника пуст, а не назван снятым аккаунтом")
	require.Equal(t, []string{string(other)}, memberships(t, e.pool, member),
		"членство в B осталось, в A — снято")
	var wayIn int
	require.NoError(t, e.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, string(member)).Scan(&wayIn))
	require.Equal(t, 1, wayIn, "способ входа участника не задет")
}

// TestKN664_14_AccountRemovalRemovesEveryMembershipPointer — KN664-14.
func TestKN664_14_AccountRemovalRemovesEveryMembershipPointer(t *testing.T) {
	e := newRemovalEnv(t)
	uid, acc := e.emptied(t, "14")
	_, other := e.emptied(t, "14b")
	member := e.seedMember(t, "14", acc, other)

	require.Contains(t, membershipPointers(t, e.pool, uid), pointer(uid, acc), "предпосылка: указатель U в A есть")
	require.ElementsMatch(t, []string{pointer(member, acc), pointer(member, other)},
		membershipPointers(t, e.pool, member), "предпосылка: указатели M в A и B есть")

	require.Equal(t, opOutcome{}, e.deleteAccount(t, uid, acc))

	require.NotContains(t, membershipPointers(t, e.pool, uid), pointer(uid, acc),
		"указатель членства владельца в снятом аккаунте пережил аккаунт")
	require.Equal(t, []string{pointer(member, other)}, membershipPointers(t, e.pool, member),
		"указатель M в снятом A обязан уйти, указатель M в B — остаться")
	require.Zero(t, countRows(t, e.pool, `SELECT count(*) FROM kaname.relation_fact
		WHERE subject = $1 OR (object_type = 'account' AND object_id = $2)`, "account:"+string(acc), string(acc)),
		"в модели прав остались факты, называющие снятый аккаунт")
}

// TestKN664_15_IntentRefusalLeavesNothing — KN664-15, близнец KN664-14: запись
// намерения отказывает внутри транзакции.
func TestKN664_15_IntentRefusalLeavesNothing(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid, acc := e.emptied(t, "15")
	_, other := e.emptied(t, "15b")
	member := e.seedMember(t, "15", acc, other)
	intentsBefore := countRows(t, e.pool, `SELECT count(*) FROM kaname.fga_outbox`)

	// Отказ записи намерения — триггером, который отвергает намерение,
	// называющее объект личности участника: его пишет только снятие указателя
	// членства. Отказ хранилища, а не продукта: текст наружу не идёт.
	_, err := e.pool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION kaname.kn664_refuse_intent() RETURNS trigger LANGUAGE plpgsql AS $f$
		BEGIN
		  IF NEW.payload::text LIKE '%%%s%%' THEN
		    RAISE EXCEPTION 'kn664 injected intent refusal';
		  END IF;
		  RETURN NEW;
		END $f$;
		CREATE TRIGGER kn664_refuse_intent BEFORE INSERT ON kaname.fga_outbox
		  FOR EACH ROW EXECUTE FUNCTION kaname.kn664_refuse_intent();`, "iam_user:"+string(member)))
	require.NoError(t, err)

	require.Equal(t, opOutcome{code: 13, msg: "internal error"}, e.deleteAccount(t, uid, acc))

	require.Equal(t, 1, countRows(t, e.pool, `SELECT count(*) FROM kaname.accounts WHERE id = $1`, string(acc)), "A на месте")
	require.Contains(t, memberships(t, e.pool, uid), string(acc), "членство U в A на месте")
	require.Contains(t, memberships(t, e.pool, member), string(acc), "членство M в A на месте")
	var home string
	require.NoError(t, e.pool.QueryRow(ctx, `SELECT account_id FROM kaname.users WHERE id = $1`, string(member)).Scan(&home))
	require.Equal(t, string(acc), home, "колонка дома M = A")
	require.Equal(t, intentsBefore, countRows(t, e.pool, `SELECT count(*) FROM kaname.fga_outbox`),
		"новых строк очереди намерений нет")
}

// TestKN664_20_AccountRemovalRacesProjectCreation — KN664-20: сто повторов,
// исход каждого — из замкнутого набора. Исход (в) — синхронный отказ двери
// прав края — на этом уровне не производится: дверь стоит на слушателе.
func TestKN664_20_AccountRemovalRacesProjectCreation(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	const repeats = 100
	counts := map[string]int{}
	for i := 0; i < repeats; i++ {
		owner := mustSeedUser(t, ctx, e.pool, fmt.Sprintf("kn66420o%d", i))
		acc := seedAccount(t, ctx, e.repo, fmt.Sprintf("kn664-20-%d", i), owner)

		var (
			wg             sync.WaitGroup
			delOp, prjOp   *operations.Operation
			delErr, prjErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			delOp, delErr = accountapp.NewDeleteAccountUseCase(e.repo, e.ops).Execute(principalCtx(owner), acc.ID)
		}()
		go func() {
			defer wg.Done()
			prjOp, prjErr = projectapp.NewCreateProjectUseCase(e.repo, e.ops).Execute(principalCtx(owner),
				domain.Project{AccountID: acc.ID, Name: domain.ProjectName(fmt.Sprintf("p%d", i)), Labels: domain.Labels{}})
		}()
		wg.Wait()
		require.NoError(t, delErr)
		require.NoError(t, prjErr)
		del, prj := e.outcome(t, delOp), e.outcome(t, prjOp)
		projectsLeft := countRows(t, e.pool, `SELECT count(*) FROM kaname.projects WHERE account_id = $1`, string(acc.ID))
		accountLeft := countRows(t, e.pool, `SELECT count(*) FROM kaname.accounts WHERE id = $1`, string(acc.ID))

		switch {
		case prj == opOutcome{} && del == opOutcome{code: 9, msg: "Account " + string(acc.ID) + " contains projects and cannot be deleted: delete Project " +
			firstProjectOf(t, e.pool, acc.ID) + " first (projects: 1)"}:
			counts["а: проект создан, снятие отвергнуто"]++
			require.Equal(t, 1, accountLeft)
		case del == opOutcome{} && prj == opOutcome{code: 9, msg: "Account " + string(acc.ID) + " not found"}:
			counts["б: аккаунт снят, создание — «not found»"]++
			require.Zero(t, accountLeft)
		default:
			t.Fatalf("повтор %d: исход вне набора KN664-20: снятие %s, создание %s", i, del, prj)
		}
		require.False(t, accountLeft == 0 && projectsLeft > 0, "повтор %d: проект пережил свой аккаунт", i)
	}
	t.Logf("KN664-20: повторов %d; по исходам: %v", repeats, counts)
	total := 0
	for _, n := range counts {
		total += n
	}
	require.Equal(t, repeats, total)
}

// TestKN664_20b_ProjectIntoARemovedAccountNamesTheAccount — исход (б) KN664-20
// детерминированно: транзакция создания проекта встречает снятый аккаунт, и
// отказ называет АККАУНТ, а не проект. Подсказка вставки несла имя проекта и
// служила обеим ветвям — уникальности имени и ключа аккаунта; гонка KN664-20
// показала отказ «Account <имя проекта> not found».
func TestKN664_20b_ProjectIntoARemovedAccountNamesTheAccount(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	gone := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.ProjectsW().Insert(ctx, domain.Project{
		ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: gone,
		Name: "kn664-20b", Labels: domain.Labels{},
	})
	require.Error(t, err)
	require.Equal(t, "Account "+string(gone)+" not found", iamerr.StripSentinel(err))

	// Близнец: ветвь уникальности по-прежнему называет ИМЯ проекта.
	owner := mustSeedUser(t, ctx, e.pool, "kn66420b")
	acc := seedAccount(t, ctx, e.repo, "kn664-20b", owner)
	w2, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w2.Rollback(ctx) }()
	for i := 0; i < 2; i++ {
		_, err = w2.ProjectsW().Insert(ctx, domain.Project{
			ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: acc.ID,
			Name: "kn664-20b-dup", Labels: domain.Labels{},
		})
	}
	require.Error(t, err)
	require.Equal(t, "Project with name kn664-20b-dup already exists", iamerr.StripSentinel(err))
}
