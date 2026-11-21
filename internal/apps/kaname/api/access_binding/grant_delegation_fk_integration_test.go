// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_fk_integration_test.go — внешний ключ
// `grant_delegations_active_delegate_fk` отвечает текстом Р6 с обеих сторон
// (PRO-Robotech/kaname#986, строка GD-45 DoD приёмки; находка ревью
// FK-23503-UNMAPPED).
//
// Программная проверка (`create.go` — учётка есть; `saWriter.Delete` — нет
// действующего делегирования) и последний рубеж FK проверяются отдельно:
//
//   - сторона ВСТАВКИ: строка делегирования на учётку, которой нет, — ответ
//     ключа, а не программной проверки (её этот вызов обходит);
//   - обычная гонка снятия ждёт compatibility fence до бизнес-SQL, после
//     commit вставки precheck называет делегирование (Р6);
//   - отдельная изолированная инъекция после precheck доводит настоящее
//     удаление до delete-side FK и проверяет его fallback Р6 без id.
//
// Ожидание замка — держателем, а не паузой: проба ждёт, пока удаление
// встанет на точном legacy compat key за PID вставки, и только тогда её фиксирует.
// Отдельный read-only KEY SHARE holder проверяет настоящий SA FOR UPDATE:
// compat очередь сама по себе уже не доказывает FK/row-lock конфликт.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rawDelegation — строка делегирования пары (acc-A, delegate) от usr-A, оси D1.
func (w *gdWorld) rawDelegation(delegate string) domain.GrantDelegation {
	return domain.GrantDelegation{
		ID:           domain.GrantDelegationID(ids.NewID(domain.PrefixGrantDelegation)),
		AccountID:    w.accA,
		DelegateID:   domain.ServiceAccountID(delegate),
		RoleIDs:      []domain.RoleID{w.rolPuller},
		TargetTypes:  []string{"registry.registries"},
		SubjectTypes: []domain.SubjectType{domain.SubjectTypeServiceAccount},
		Module:       "registry",
		Status:       domain.GrantDelegationActive,
		DelegatedBy:  domain.GrantDelegationActor{Type: "user", ID: string(w.usrA)},
	}
}

// GD-45, сторона вставки: делегирование на учётку, которой нет, — текст Р6
// «ServiceAccount <id> not found», а не общий текст неразобранного ключа.
func TestGrantDelegation_GD45_KeyRefusesADelegationToAMissingAccountWithItsText(t *testing.T) {
	w := newGDWorld(t)
	missing := ids.NewID(domain.PrefixServiceAccount)

	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(w.ctx) }()
	_, ierr := wr.AccessBindingsW().GrantDelegationsW().Insert(w.ctx, w.rawDelegation(missing))
	require.Error(t, ierr, "строка делегирования на несуществующую учётку вставлена")

	st, _ := status.FromError(shared.MapRepoErr(ierr))
	assert.Equal(t, codes.FailedPrecondition, st.Code(), "код (текст %q)", st.Message())
	assert.Equal(t, fmt.Sprintf("ServiceAccount %s not found", missing), st.Message(), "текст Р6")
}

// GD-45, сторона снятия: удаление учётки, пришедшее, пока делегирование на неё
// вставлено и не зафиксировано, после фиксации отвечает текстом Р6 с id
// делегирования; учётка на месте.
func TestGrantDelegation_GD45_DeleteRacingAnInsertNamesTheDelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-45 гонка")

	ins, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = ins.Rollback(w.ctx)
		}
	}()
	d, err := ins.AccessBindingsW().GrantDelegationsW().Insert(w.ctx, w.rawDelegation(w.svaIss))
	require.NoError(t, err, "Дано: делегирование на sva-iss вставлено (не зафиксировано)")

	holderPID := gdCompatOwner(w)
	op, err := w.sas.Delete(asUser(w.ctx, w.usrS), &iamv1.DeleteServiceAccountRequest{ServiceAccountId: w.svaIss})
	require.NoError(t, err, "удаление учётки асинхронно: отказ — в операции")

	gdAwaitCompatWaiter(w, holderPID, "")
	require.NoError(t, ins.Commit(w.ctx), "фиксация вставки делегирования")
	committed = true

	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "учётка-делегат удалена при действующем делегировании")
	assert.Equal(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "код (текст %q)", done.Error.Message)
	assert.Equal(t, fmt.Sprintf("service account %s holds an active grant delegation %s; revoke it first", w.svaIss, d.ID),
		done.Error.Message, "текст Р6")
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE id = $1`, w.svaIss).Scan(&n))
	assert.Equal(t, 1, n, "учётка на месте")
	// Legacy очередь предшествует бизнес-SQL; отдельно сохраняем точный
	// row-lock oracle: FK KEY SHARE против настоящего Delete FOR UPDATE.
	gdRequireDeleteAccountRowLock(w, w.svaIss, string(d.ID))
}

// awaitLockWaiter — ждёт, пока в базе мира появится сеанс, стоящий на замке, чей
// запрос называет `table`. Срок истёк — проба падает: расстановка не создана,
// и судить исход нельзя.
func (w *gdWorld) awaitLockWaiter(table string, within time.Duration, why string) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.ctx, within)
	defer cancel()
	for {
		var n int
		require.NoError(w.t, w.pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%' || $1 || '%'`,
			table).Scan(&n))
		if n > 0 {
			return
		}
		select {
		case <-ctx.Done():
			w.t.Fatalf("%s: за %s ни один сеанс не встал на замке (%s)", why, within, table)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Изолированная fault-injection проба последнего рубежа, не admitted гонка:
// BEFORE DELETE вставляет валидное ACTIVE делегирование в той же target TX
// ПОСЛЕ snapshot программной охраны. Настоящий FK и его mapping не подменяются.
func TestGrantDelegation_GD45_DeleteFKBackstopRejectsLateDelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-45 последний рубеж FK")
	ctx, cancel := context.WithTimeout(w.ctx, gduBarrierDeadline)
	defer cancel()
	account := seedServiceAccount(t, ctx, w.pool, w.accS, "gd45-fk-backstop")
	d := w.rawDelegation(account)
	var allowed bool
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT has_schema_privilege(current_user,'kaname','CREATE') AND has_table_privilege(current_user,'kaname.service_accounts','TRIGGER') AND has_table_privilege(current_user,'kaname.grant_delegations','INSERT')`).Scan(&allowed))
	require.True(t, allowed, "изолированная fixture connection должна владеть DDL/trigger/insert правами")
	_, err := w.pool.Exec(ctx, `CREATE FUNCTION kaname.gd45_inject_late_delegation() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN
 INSERT INTO kaname.grant_delegations
 (id,account_id,delegate_id,active_delegate_id,role_ids,target_types,subject_types,module,status,delegated_by_type,delegated_by_id,created_at)
 VALUES (TG_ARGV[0],TG_ARGV[1],OLD.id,OLD.id,ARRAY[TG_ARGV[2]],ARRAY['registry.registries'],ARRAY['service_account'],'registry','ACTIVE','user',TG_ARGV[3],clock_timestamp());
 RETURN OLD;
 END; $$`)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := w.pool.Exec(ctx, `DROP TRIGGER IF EXISTS gd45_late_delegation ON kaname.service_accounts; DROP FUNCTION IF EXISTS kaname.gd45_inject_late_delegation()`)
		assert.NoError(t, err, "уборка изолированной fault-injection функции и trigger")
	})
	_, err = w.pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER gd45_late_delegation BEFORE DELETE ON kaname.service_accounts FOR EACH ROW WHEN (OLD.id=%s) EXECUTE FUNCTION kaname.gd45_inject_late_delegation(%s,%s,%s,%s)`,
		gdSQLLiteral(account), gdSQLLiteral(string(d.ID)), gdSQLLiteral(string(d.AccountID)), gdSQLLiteral(string(w.rolPuller)), gdSQLLiteral(string(w.usrA))))
	require.NoError(t, err)
	trace := &gd45FKErrorTrace{native: make(chan *pgconn.PgError, 1)}
	cfg := w.pool.Config()
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	writer, err := kanamepg.New(pool, nil).Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback(ctx) }()
	err = writer.ServiceAccountsW().Delete(ctx, domain.ServiceAccountID(account))
	require.Error(t, err, "без настоящего delete-side FK удаление ошибочно удалось бы")
	st, _ := status.FromError(shared.MapRepoErr(err))
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.Equal(t, fmt.Sprintf("service account %s holds an active grant delegation; revoke it first", account), st.Message(), "именно fallback Р6 без id, не прежний precheck")
	select {
	case native := <-trace.native:
		require.Equal(t, "23503", native.Code)
		require.Equal(t, "grant_delegations_active_delegate_fk", native.ConstraintName)
		require.True(t, strings.Contains(native.Message, `update or delete on table "service_accounts"`), "23503 обязан прийти со стороны удаления SA, не от INSERT инъекции")
		require.Equal(t, fmt.Sprintf(`Key (id)=(%s) is still referenced from table "grant_delegations".`, account), native.Detail)
	default:
		t.Fatal("нет настоящего backend 23503 от delete-side FK")
	}
	require.NoError(t, writer.Rollback(ctx))
	var accounts, delegations int
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.service_accounts WHERE id=$1),(SELECT count(*) FROM kaname.grant_delegations WHERE id=$2)`, account, d.ID).Scan(&accounts, &delegations))
	require.Equal(t, 1, accounts, "SA сохраняется после FK отказа")
	require.Zero(t, delegations, "rollback удаляет инъекцию вместе с target TX")
}
