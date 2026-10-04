// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// account_id_supplied_integration_test.go — идентификатор аккаунта, указанный
// при создании (задача kaname#549, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`).
//
// Сценарии уровня I, которые судят use-case создания с НАСТОЯЩИМ хранилищем:
// AID-02, AID-06, AID-11, AID-14, AID-18, AID-26. Хранилище прав — дублёр с
// ответом по сценарию и счётом вопросов: решение о праве принимает модель, и
// проба спрашивает, задан ли вопрос и что сделано с ответом, а не саму модель.
//
// Use-case получает указанный идентификатор полем `domain.Account.ID` — тем
// же полем, которым он сегодня принимает аккаунт и которое сегодня перезаписывает
// генератором. Поэтому пробы собираются до реализации и красны УТВЕРЖДЕНИЕМ:
// «присланный идентификатор не записан», «вопроса к модели не было», «реестра нет».

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// generatorAccountID — форма генератора: `acc` и 17 знаков его алфавита.
var generatorAccountID = regexp.MustCompile(`^acc[0-9abcdefghjkmnpqrstvwxyz]{17}$`)

// suppliedLiteral — годный литерал формы генератора из таблицы AID-05/06.
const suppliedLiteral = "acc7m3k9q2x5v8b4n6t1"

// relationDouble — дублёр хранилища прав: отвечает по сценарию и считает вопросы.
type relationDouble struct {
	mu      sync.Mutex
	asked   []string
	admin   bool
	failure error
}

func (d *relationDouble) Check(_ context.Context, subject, relation, object string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, subject+"#"+relation+"@"+object)
	if d.failure != nil {
		return false, d.failure
	}
	return d.admin && relation == "system_admin" && object == "cluster:cluster_root", nil
}

func (d *relationDouble) questions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.asked...)
}

// newProbeEnv — база пробы, у которой воркеры операций дожидаются ДО закрытия
// пула. Проба, упавшая на утверждении раньше своего ожидания, иначе оставляла бы
// воркер писать в закрытый пул, и его ошибка досталась бы следующей пробе.
func newProbeEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	t.Cleanup(func() { _ = operations.Wait(context.Background()) })
	return env
}

func createUseCase(env *testEnv, rel *relationDouble) *account.CreateAccountUseCase {
	return account.NewCreateAccountUseCase(env.repo, env.opsRepo).
		WithRelationStore(rel, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func createMetadata(t *testing.T, op *operations.Operation) *iamv1.CreateAccountMetadata {
	t.Helper()
	require.NotNil(t, op.Metadata, "у операции создания нет метаданных")
	m := &iamv1.CreateAccountMetadata{}
	require.NoError(t, op.Metadata.UnmarshalTo(m))
	return m
}

func finished(t *testing.T, env *testEnv, opID string) *operations.Operation {
	t.Helper()
	got, err := env.opsRepo.Get(context.Background(), opID)
	require.NoError(t, err)
	require.True(t, got.Done, "операция %s не завершена после ожидания воркеров", opID)
	return got
}

func responseAccount(t *testing.T, op *operations.Operation) *iamv1.Account {
	t.Helper()
	require.Nil(t, op.Error, "операция завершилась ошибкой: %v", op.Error)
	require.NotNil(t, op.Response, "у завершённой операции нет response")
	msg, err := op.Response.UnmarshalNew()
	require.NoError(t, err)
	acc, ok := msg.(*iamv1.Account)
	require.True(t, ok, "response не Account: %T", msg)
	return acc
}

func accountRows(t *testing.T, pool *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.accounts WHERE id = $1`, id).Scan(&n))
	return n
}

// requireRegistry — реестр выданных идентификаторов (Р5) стоит в схеме.
func requireRegistry(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var present bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT to_regclass('kaname.issued_account_ids') IS NOT NULL`).Scan(&present))
	require.True(t, present, "реестра выданных идентификаторов kaname.issued_account_ids в схеме нет: "+
		"неповторяемость идентификатора аккаунта держать нечему (Р5)")
}

func registryRows(t *testing.T, pool *pgxpool.Pool, id string) int {
	t.Helper()
	requireRegistry(t, pool)
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.issued_account_ids WHERE id = $1`, id).Scan(&n))
	return n
}

// requireAlreadyExists — исход операции: ALREADY_EXISTS с текстом идентификатора.
func requireAlreadyExists(t *testing.T, op *operations.Operation, id string) {
	t.Helper()
	require.Nil(t, op.Response, "занятый идентификатор %s: операция вернула ресурс", id)
	require.NotNil(t, op.Error, "занятый идентификатор %s: операция завершилась без ошибки", id)
	require.Equal(t, int32(codes.AlreadyExists), op.Error.Code, "код исхода: %v", op.Error)
	require.Equal(t, "Account "+id+" already exists", op.Error.Message)
}

// supplyAndCreate — создание с указанным идентификатором; утверждает, что
// присланный идентификатор и есть идентификатор операции и аккаунта.
func supplyAndCreate(t *testing.T, env *testEnv, uc *account.CreateAccountUseCase, owner domain.UserID, id, name string) (*operations.Operation, *iamv1.CreateAccountMetadata) {
	t.Helper()
	op, err := uc.Execute(withPrincipal(owner), domain.Account{
		ID: domain.AccountID(id), Name: domain.AccountName(name), Labels: domain.Labels{},
	})
	require.NoError(t, err, "создание с указанным идентификатором %s отвергнуто синхронно", id)
	require.NotNil(t, op)
	md := createMetadata(t, op)
	require.Equal(t, id, md.GetAccountId(), "указанный идентификатор не записан: metadata.accountId — не присланный")
	return op, md
}

// ── AID-02 ───────────────────────────────────────────────────────────────────

// TestAccountID02_WithoutIDTheModelIsNotAsked — без `id` модель прав не
// спрашивается вовсе: поведение генератора не зависит от хранилища прав.
// Близнец — AID-11 (тот же дублёр, указан `id`).
func TestAccountID02_WithoutIDTheModelIsNotAsked(t *testing.T) {
	env := newProbeEnv(t)
	owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid02")
	rel := &relationDouble{failure: errors.New("relation store: connection refused")}

	op, err := createUseCase(env, rel).Execute(withPrincipal(owner), domain.Account{
		Name: "aid02-generated", Labels: domain.Labels{},
	})
	require.NoError(t, err)
	require.NotNil(t, op, "операция не заведена")
	require.Regexp(t, generatorAccountID, createMetadata(t, op).GetAccountId())
	awaitWorkers(t)
	require.Empty(t, rel.questions(), "без указанного идентификатора задан вопрос к модели прав")
}

// ── AID-06 ───────────────────────────────────────────────────────────────────

// TestAccountID06_BoundaryValuesOfTheFormAreAccepted — граничные значения формы
// генератора принимаются побайтово. Близнец AID-05 по оси формы.
func TestAccountID06_BoundaryValuesOfTheFormAreAccepted(t *testing.T) {
	env := newProbeEnv(t)
	owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid06")
	uc := createUseCase(env, &relationDouble{admin: true})

	for i, id := range []string{"acc00000000000000000", "acczzzzzzzzzzzzzzzzz", suppliedLiteral} {
		require.True(t, ids.IsValid(id, domain.PrefixAccount), "литерал пробы %q не формы генератора", id)
		op, err := uc.Execute(withPrincipal(owner), domain.Account{
			ID: domain.AccountID(id), Name: domain.AccountName("aid06-" + string(rune('a'+i))), Labels: domain.Labels{},
		})
		require.NoError(t, err, "граничное значение %s отвергнуто", id)
		require.NotNil(t, op)
		require.Equal(t, id, createMetadata(t, op).GetAccountId(),
			"граничное значение %s: metadata.accountId не равен присланному", id)
	}
	awaitWorkers(t)
}

// ── AID-11 ───────────────────────────────────────────────────────────────────

// TestAccountID11_ModelUnavailableRefusesSuppliedIDWithUnavailable — модель прав
// недоступна: создание с `id` не исполняется и отвечает UNAVAILABLE.
// Близнецы: без `id` — успех (AID-02); дублёр «администратор» — успех (AID-06).
func TestAccountID11_ModelUnavailableRefusesSuppliedIDWithUnavailable(t *testing.T) {
	env := newProbeEnv(t)
	owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid11")
	rel := &relationDouble{failure: errors.New("relation store: connection refused")}

	op, err := createUseCase(env, rel).Execute(withPrincipal(owner), domain.Account{
		ID: suppliedLiteral, Name: "aid11-supplied", Labels: domain.Labels{},
	})
	awaitWorkers(t)
	require.Error(t, err, "модель прав недоступна, а создание с указанным идентификатором исполнилось")
	require.Nil(t, op, "операция заведена при недоступной модели прав")
	st, ok := status.FromError(err)
	require.True(t, ok, "ожидается статус gRPC: %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
	require.Equal(t, "authz backend unavailable", st.Message())
	require.Zero(t, accountRows(t, env.pool, suppliedLiteral), "вставка состоялась при отказе")
	require.NotEmpty(t, rel.questions(), "отказ получен без вопроса к модели прав")
}

// ── AID-14 ───────────────────────────────────────────────────────────────────

// TestAccountID14_ConcurrentCreatesWithOneIDLetExactlyOneThrough — восемь
// одновременных созданий с одним `id`: проходит ровно одно, по ограничению базы.
// Близнец — восемь разных идентификаторов: проходят все восемь.
func TestAccountID14_ConcurrentCreatesWithOneIDLetExactlyOneThrough(t *testing.T) {
	const n = 8
	race := func(t *testing.T, idOf func(int) string) (env *testEnv, ops []*operations.Operation) {
		env = newProbeEnv(t)
		// Свой человек на каждую горутину: темп заведения считается на личность
		// (3 за окно у фикстуры), а предмет пробы — единственность по ключу, а не
		// темп. С одним владельцем близнец упирался бы в темп, а не проходил.
		owners := make([]domain.UserID, n)
		for i := range owners {
			owners[i], _ = seedUserAccount(t, context.Background(), env.pool, fmt.Sprintf("aid14-%d", i))
		}
		uc := createUseCase(env, &relationDouble{admin: true})
		ops = make([]*operations.Operation, n)
		errs := make([]error, n)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				ops[i], errs[i] = uc.Execute(withPrincipal(owners[i]), domain.Account{
					ID: domain.AccountID(idOf(i)), Name: domain.AccountName("aid14-" + string(rune('a'+i))), Labels: domain.Labels{},
				})
			}(i)
		}
		close(start)
		wg.Wait()
		awaitWorkers(t)
		for i := 0; i < n; i++ {
			require.NoError(t, errs[i], "горутина %d: синхронный отказ", i)
			require.Equal(t, idOf(i), createMetadata(t, ops[i]).GetAccountId(),
				"горутина %d: указанный идентификатор не записан", i)
			ops[i] = finished(t, env, ops[i].ID)
		}
		return env, ops
	}

	t.Run("one_id", func(t *testing.T) {
		env, ops := race(t, func(int) string { return suppliedLiteral })
		var won, lost int
		for _, op := range ops {
			if op.Response != nil {
				won++
				require.Equal(t, suppliedLiteral, responseAccount(t, op).GetId())
				continue
			}
			lost++
			requireAlreadyExists(t, op, suppliedLiteral)
		}
		require.Equal(t, 1, won, "из %d одновременных созданий с одним id прошло %d", n, won)
		require.Equal(t, n-1, lost)
		require.Equal(t, 1, accountRows(t, env.pool, suppliedLiteral))
		require.Equal(t, 1, registryRows(t, env.pool, suppliedLiteral))
	})

	t.Run("twin_distinct_ids", func(t *testing.T) {
		distinct := make([]string, n)
		for i := range distinct {
			distinct[i] = ids.NewID(domain.PrefixAccount)
		}
		_, ops := race(t, func(i int) string { return distinct[i] })
		for i, op := range ops {
			require.Equal(t, distinct[i], responseAccount(t, op).GetId())
		}
	})
}

// ── AID-18 ───────────────────────────────────────────────────────────────────

// removeAccount — штатное снятие аккаунта для «Дано» AID-18: сперва проект по
// умолчанию хранилищем проекта, затем аккаунт хранилищем аккаунта. Оба исхода
// утверждаются до вопроса к реестру.
func removeAccount(t *testing.T, env *testEnv, accID, projID string) {
	t.Helper()
	ctx := context.Background()
	w, err := env.repo.Writer(journalfixture.Writing(ctx))
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	require.NoError(t, w.ProjectsW().Delete(ctx, domain.ProjectID(projID)), "снятие проекта по умолчанию")
	require.NoError(t, w.AccountsW().Delete(ctx, domain.AccountID(accID)), "снятие аккаунта")
	require.NoError(t, w.Commit(ctx))
	var projects int
	require.NoError(t, env.pool.QueryRow(ctx, `SELECT count(*) FROM kaname.projects WHERE account_id = $1`, accID).Scan(&projects))
	require.Zero(t, projects, "у снятого аккаунта остались проекты")
	require.Zero(t, accountRows(t, env.pool, accID), "аккаунт не снят")
}

// TestAccountID18_EveryProducerEntersTheRegistryAndDeletionDoesNotFree — AID-18.
func TestAccountID18_EveryProducerEntersTheRegistryAndDeletionDoesNotFree(t *testing.T) {
	t.Run("a_generator", func(t *testing.T) {
		env := newProbeEnv(t)
		owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid18a")
		uc := createUseCase(env, &relationDouble{admin: true})
		op, err := uc.Execute(withPrincipal(owner), domain.Account{Name: "aid18-a", Labels: domain.Labels{}})
		require.NoError(t, err)
		md := createMetadata(t, op)
		awaitWorkers(t)
		require.Equal(t, md.GetAccountId(), responseAccount(t, finished(t, env, op.ID)).GetId())

		require.Equal(t, 1, registryRows(t, env.pool, md.GetAccountId()), "генератор не внёс идентификатор в реестр")
		removeAccount(t, env, md.GetAccountId(), md.GetDefaultProjectId())
		require.Equal(t, 1, registryRows(t, env.pool, md.GetAccountId()), "снятие освободило идентификатор")

		again, _ := supplyAndCreate(t, env, uc, owner, md.GetAccountId(), "aid18-a-again")
		awaitWorkers(t)
		requireAlreadyExists(t, finished(t, env, again.ID), md.GetAccountId())
	})

	t.Run("b_supplied", func(t *testing.T) {
		env := newProbeEnv(t)
		owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid18b")
		uc := createUseCase(env, &relationDouble{admin: true})
		id := ids.NewID(domain.PrefixAccount)
		op, md := supplyAndCreate(t, env, uc, owner, id, "aid18-b")
		awaitWorkers(t)
		require.Equal(t, id, responseAccount(t, finished(t, env, op.ID)).GetId())

		require.Equal(t, 1, registryRows(t, env.pool, id), "указанный идентификатор не внесён в реестр")
		removeAccount(t, env, id, md.GetDefaultProjectId())
		require.Equal(t, 1, registryRows(t, env.pool, id), "снятие освободило идентификатор")

		again, _ := supplyAndCreate(t, env, uc, owner, id, "aid18-b-again")
		awaitWorkers(t)
		requireAlreadyExists(t, finished(t, env, again.ID), id)
	})

	t.Run("c_personal_account_of_the_mirror", func(t *testing.T) {
		env := newProbeEnv(t)
		ctx := context.Background()
		store := kanamepg.NewRegistrationStore(env.pool)
		w, err := store.Writer(journalfixture.Writing(ctx))
		require.NoError(t, err)
		res, err := userapp.RegisterMirrorTx(ctx, w.MirrorWriter(), userapp.MirrorInput{
			Email:           domain.Email("aid18c-" + ids.NewID("tst")[3:11] + "@example.invalid"),
			ExternalID:      domain.ExternalSubject("ext-aid18c-" + ids.NewID("tst")[3:]),
			CandidateUserID: domain.UserID(ids.NewID(domain.PrefixUser)),
			Actor:           "registration",
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
		personal := string(res.AccountID)
		require.Equal(t, 1, accountRows(t, env.pool, personal), "личный аккаунт не заведён")

		require.Equal(t, 1, registryRows(t, env.pool, personal), "личный аккаунт не внесён в реестр")

		owner, _ := seedUserAccount(t, ctx, env.pool, "aid18c")
		again, _ := supplyAndCreate(t, env, createUseCase(env, &relationDouble{admin: true}), owner, personal, "aid18-c-again")
		awaitWorkers(t)
		requireAlreadyExists(t, finished(t, env, again.ID), personal)
	})

	t.Run("seeded_is_in_the_registry", func(t *testing.T) {
		env := newProbeEnv(t)
		require.Equal(t, 1, accountRows(t, env.pool, "acc1a18042d81fb438d6"), "посеянного аккаунта нет — мир не тот")
		require.Equal(t, 1, registryRows(t, env.pool, "acc1a18042d81fb438d6"), "посеянный идентификатор не в реестре")
	})

	t.Run("boundary_not_the_form_is_not_entered", func(t *testing.T) {
		env := newProbeEnv(t)
		ctx := context.Background()
		owner, _ := seedUserAccount(t, ctx, env.pool, "aid18x")
		const odd = "acc00000000000000lim"
		_, err := env.pool.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
			VALUES ($1, 'aid18-boundary', $2, '{}'::jsonb)`, odd, string(owner))
		require.NoError(t, err, "запись в обход службы не формы генератора отвергнута")
		require.Zero(t, registryRows(t, env.pool, odd), "идентификатор не формы генератора внесён в реестр")
	})

	t.Run("twin_never_issued_inserts", func(t *testing.T) {
		env := newProbeEnv(t)
		ctx := context.Background()
		owner, _ := seedUserAccount(t, ctx, env.pool, "aid18t")
		fresh := ids.NewID(domain.PrefixAccount)
		_, err := env.pool.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
			VALUES ($1, 'aid18-twin', $2, '{}'::jsonb)`, fresh, string(owner))
		require.NoError(t, err, "вставка с невыдававшимся идентификатором формы генератора обязана проходить")
	})
}

// ── AID-26 ───────────────────────────────────────────────────────────────────

// TestAccountID26_CreationEventNamesTheIDSource — событие создания называет
// источник идентификатора. Близнец — две ветви, отличающиеся только полем.
func TestAccountID26_CreationEventNamesTheIDSource(t *testing.T) {
	for _, branch := range []struct {
		name, supplied, source string
	}{
		{"generated", "", "generated"},
		{"supplied", suppliedLiteral, "supplied"},
	} {
		t.Run(branch.name, func(t *testing.T) {
			env := newProbeEnv(t)
			ctx := context.Background()
			owner, _ := seedUserAccount(t, ctx, env.pool, "aid26"+branch.name[:3])
			op, err := createUseCase(env, &relationDouble{admin: true}).Execute(withPrincipal(owner), domain.Account{
				ID: domain.AccountID(branch.supplied), Name: domain.AccountName("aid26-" + branch.name), Labels: domain.Labels{},
			})
			require.NoError(t, err)
			md := createMetadata(t, op)
			if branch.supplied != "" {
				require.Equal(t, branch.supplied, md.GetAccountId(), "указанный идентификатор не записан")
			}
			awaitWorkers(t)
			accID := responseAccount(t, finished(t, env, op.ID)).GetId()

			r := requireOneAuditRow(ctx, t, env.pool, "iam.account.created", accID)
			require.NotNil(t, r.tenant)
			require.Equal(t, accID, *r.tenant)
			require.Equal(t, string(owner), r.payload["actor"])
			require.Equal(t, accID, r.payload["resource_id"])
			require.Equal(t, branch.source, r.payload["id_source"], "событие создания не называет источник идентификатора")
		})
	}
}
