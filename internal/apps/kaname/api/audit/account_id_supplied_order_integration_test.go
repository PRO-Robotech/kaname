// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// account_id_supplied_order_integration_test.go — порядок синхронных проверок
// создания с указанным идентификатором и спорный путь «удаление и создание
// одного идентификатора одновременно» (задача kaname#549, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, §7 п. 3–5;
// разбор экспозиции классов, условия 1, 6 и заказ П2).
//
// Сценарии уровня E (AID-04, AID-05, AID-07, AID-08) судят то же снаружи, но
// снаружи не видно двух вещей, которые несут сокрытие существования: что до
// ответа права не было НИ ЧТЕНИЯ, НИ ОПЕРАЦИИ, и что форма судится раньше вопроса
// к модели. Здесь они видны — счётом вопросов дублёра и строками базы.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// operationRowsFor — строки операций, денормализованные на идентификатор
// аккаунта: по ним читает лента аккаунта.
func operationRowsFor(t *testing.T, env *testEnv, accID string) int {
	t.Helper()
	var n int
	require.NoError(t, env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.operations WHERE account_id = $1`, accID).Scan(&n))
	return n
}

// TestAccountID05_UseCaseRefusesAMalformedIDBeforeTheRightsQuestion — форма судится
// синхронно, первой после рода принципала, и раньше вопроса о праве: дублёр,
// который ответил бы «администратор», не спрошен ни разу. Близнец — AID-06
// (годная форма проходит).
func TestAccountID05_UseCaseRefusesAMalformedIDBeforeTheRightsQuestion(t *testing.T) {
	env := newProbeEnv(t)
	owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid05i")
	rel := &relationDouble{admin: true}
	uc := createUseCase(env, rel)

	for _, bad := range []string{
		"acc7M3K9Q2X5V8B4N6T1",  // заглавные
		"acc7m3k9q2x5v8b4n6tu",  // `u` вне алфавита
		"acc7m3k9q2x5v8b4n6ti",  // `i` вне алфавита
		"acc7m3k9q2x5v8b4n6t",   // 19 знаков
		"acc7m3k9q2x5v8b4n6t12", // 21 знак
		"prj7m3k9q2x5v8b4n6t1",  // чужой префикс
		"acc-7m3k9q2x5v8b4n6t1", // дефисная форма
		" acc7m3k9q2x5v8b4n6t1", // ведущий пробел
		"acc7m3k9q2x5v8b4n6tа",  // кириллическая «а»
	} {
		op, err := uc.Execute(withPrincipal(owner), domain.Account{
			ID: domain.AccountID(bad), Name: "aid05-malformed", Labels: domain.Labels{},
		})
		require.Error(t, err, "негодная форма %q принята", bad)
		require.Nil(t, op, "на негодной форме %q заведена операция", bad)
		st, ok := status.FromError(err)
		require.True(t, ok, "ожидается статус gRPC: %v", err)
		require.Equal(t, codes.InvalidArgument, st.Code(), "%q: %v", bad, err)
		require.Equal(t, "invalid account id '"+bad+"'", st.Message())
		var field string
		for _, d := range st.Details() {
			if br, isBR := d.(*errdetails.BadRequest); isBR && len(br.GetFieldViolations()) > 0 {
				field = br.GetFieldViolations()[0].GetField()
			}
		}
		require.Equal(t, "id", field, "%q: отказ формы не называет поле id", bad)
		require.Zero(t, operationRowsFor(t, env, bad), "%q: строка операции заведена", bad)
	}
	require.Empty(t, rel.questions(), "форма судится раньше права, а модель спрошена")
}

// TestAccountID08_UseCaseRefusesANonAdminBeforeAnyReadOrOperation — модель
// ответила «нет»: синхронный PERMISSION_DENIED, и до него не было ни операции,
// ни вставки. Иначе лента аккаунта X получила бы строку от постороннего, а отказ
// стал бы различим по занятости X. Близнец — тот же вызывающий без `id`.
func TestAccountID08_UseCaseRefusesANonAdminBeforeAnyReadOrOperation(t *testing.T) {
	env := newProbeEnv(t)
	owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid08i")
	rel := &relationDouble{admin: false}
	uc := createUseCase(env, rel)
	x := ids.NewID(domain.PrefixAccount)

	op, err := uc.Execute(withPrincipal(owner), domain.Account{
		ID: domain.AccountID(x), Name: "aid08-denied", Labels: domain.Labels{},
	})
	awaitWorkers(t)
	require.Error(t, err, "не администратор облака задал идентификатор, а создание исполнилось")
	require.Nil(t, op)
	st, ok := status.FromError(err)
	require.True(t, ok, "ожидается статус gRPC: %v", err)
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Equal(t, "permission denied", st.Message())
	require.Equal(t, []string{"user:" + string(owner) + "#system_admin@cluster:cluster_root"}, rel.questions(),
		"вопрос к модели — ровно один, о праве администратора облака")
	require.Zero(t, operationRowsFor(t, env, x), "до ответа права заведена операция с account_id = X")
	require.Zero(t, accountRows(t, env.pool, x))

	// Близнец: тот же вызывающий без идентификатора — создание идёт, модель не
	// спрошена сверх прежнего.
	twin, err := uc.Execute(withPrincipal(owner), domain.Account{Name: "aid08-twin", Labels: domain.Labels{}})
	require.NoError(t, err)
	require.NotNil(t, twin)
	awaitWorkers(t)
	require.Len(t, rel.questions(), 1, "без идентификатора модель спрошена")
}

// TestAccountID04_UseCaseDefaultNameIsTheSuppliedID — без имени имя аккаунта —
// присланный идентификатор, а не чеканный: идентификатор назначается ДО
// подстановки умолчания и до проверки имени (разбор, условие 1).
func TestAccountID04_UseCaseDefaultNameIsTheSuppliedID(t *testing.T) {
	env := newProbeEnv(t)
	owner, _ := seedUserAccount(t, context.Background(), env.pool, "aid04i")
	x := ids.NewID(domain.PrefixAccount)

	op, _ := supplyAndCreate(t, env, createUseCase(env, &relationDouble{admin: true}), owner, x, "")
	require.Equal(t, "Create account "+x, op.Description)
	awaitWorkers(t)
	acc := responseAccount(t, finished(t, env, op.ID))
	require.Equal(t, x, acc.GetId())
	require.Equal(t, x, acc.GetName(), "имя по умолчанию не равно присланному идентификатору")
}

// TestAccountID16_ConcurrentDeleteAndCreateOfOneIDNeverReissues — заказ П2.
// Удаление X держит транзакцию открытой; создание X в это время стоит на
// первичном ключе. Удаление фиксируется — ключ аккаунта свободен, и единственное,
// что отказывает создание, — реестр выданных. Барьер — видимое ожидание замка
// в pg_stat_activity, а не время.
func TestAccountID16_ConcurrentDeleteAndCreateOfOneIDNeverReissues(t *testing.T) {
	env := newProbeEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "aid16i")
	uc := createUseCase(env, &relationDouble{admin: true})
	x := ids.NewID(domain.PrefixAccount)

	first, md := supplyAndCreate(t, env, uc, owner, x, "aid16-first")
	awaitWorkers(t)
	require.Equal(t, x, responseAccount(t, finished(t, env, first.ID)).GetId())

	// Удаление X в открытой транзакции.
	w, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	require.NoError(t, w.ProjectsW().Delete(ctx, domain.ProjectID(md.GetDefaultProjectId())))
	require.NoError(t, w.AccountsW().Delete(ctx, domain.AccountID(x)))

	again, _ := supplyAndCreate(t, env, uc, owner, x, "aid16-again")

	// Вставка создания стоит на замке строки X, пока удаление не зафиксировано.
	require.Eventually(t, func() bool {
		var waiting int
		if qerr := env.pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'
			   AND query ILIKE '%INSERT INTO accounts%'`).Scan(&waiting); qerr != nil {
			return false
		}
		return waiting == 1
	}, 20*time.Second, 50*time.Millisecond, "вставка создания X не встала на замок удаления X")

	require.NoError(t, w.Commit(ctx))
	awaitWorkers(t)

	requireAlreadyExists(t, finished(t, env, again.ID), x)
	require.Zero(t, accountRows(t, env.pool, x), "удалённый X воскрешён созданием")
	require.Equal(t, 1, registryRows(t, env.pool, x))

	// Близнец: свежий идентификатор после того же снятия проходит.
	fresh := ids.NewID(domain.PrefixAccount)
	twin, _ := supplyAndCreate(t, env, uc, owner, fresh, "aid16-twin")
	awaitWorkers(t)
	require.Equal(t, fresh, responseAccount(t, finished(t, env, twin.ID)).GetId())
}
