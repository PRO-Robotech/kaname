// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_role_narrowing_race_integration_test.go — аддитивный форвард
// и сужение правил роли, идущие одновременно (kaname#926).
//
// ПРЕДМЕТ. Форвард решает, какой ярус выдать на объекте, по правилам роли,
// прочитанным в его транзакции, и пишет члена, реестр и строку журнала позже, в
// той же транзакции. Сужение роли коммитит новые правила и после коммита
// запускает веер по её выдачам: веер снимает членов, чей отпечаток правила больше
// не желаем. Член форварда, лёгший ПОСЛЕ того, как веер прочитал набор членов,
// снять некому до следующего полного прохода, — и до него субъект держит ярус,
// который сужение уже отобрало.
//
// ФОРМА ПРОБЫ. Порядок задаётся, а не угадывается: форвард идёт настоящим кодом
// реконсайлера и останавливается СРАЗУ ПОСЛЕ чтения фактов выдачи (pausingTx) —
// там, где правила роли уже прочитаны, а записи ещё нет. В этот момент идёт
// настоящая правка роли (UpdateRoleUseCase со сверкой кортежей уровня выдачи в
// её транзакции) и затем настоящий веер (RoleMembershipFanout). Исходов два, и оба
// проба принимает:
//   - сужение и веер прошли, не дожидаясь форварда, — форвард отпускается после;
//   - сужение встало на замке строки роли — форвард отпускается, сужение и веер
//     доходят до конца после его коммита.
//
// Утверждается не порядок, а ИСХОД: сразу после веера прямые факты субъекта
// совпадают с теми, что даёт ещё один полный проход (сведение), а вердикт яруса,
// снятого сужением, — отказ. Ожидание замка проба наблюдает в pg_stat_activity.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — тот же форвард в той же остановке, но сужение идёт ПОСЛЕ
// его коммита: последовательный порядок обязан дать тот же исход. Без него
// совпадение «после веера» и «после сведения» было бы неотличимо от прохода, не
// пишущего ничего; положительный контроль — суженная роль по-прежнему даёт ярус
// чтения.

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// subjectFactRelations — отношения прямых фактов субъекта на объекте, по порядку.
func subjectFactRelations(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subj, objType, objID string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT relation FROM kaname.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND subject = $3`, objType, objID, subj)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		require.NoError(t, rows.Scan(&r))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// raceObjectVerdict — вердикт отношения субъекта на объекте гонки.
func raceObjectVerdict(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subj, relation string) relverdict.Verdict {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: subj, ObjectType: "compute_instance", ObjectID: "iRace", Relation: relation,
	})
	require.NoError(t, err)
	return v
}

// narrowRole — правка правил роли настоящим use-case и затем настоящий веер по её
// выдачам — то, что use-case запускает после коммита.
func narrowRole(ctx context.Context, pool *pgxpool.Pool, fx gammaFixture, roleID domain.RoleID, rules domain.Rules, rec *reconcile.Reconciler) error {
	opsRepo := operations.NewRepo(pool, "kaname")
	asOwner := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(fx.owner)})
	op, err := roleapp.NewUpdateRoleUseCase(fx.repo, opsRepo, catalogfixture.Source()).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		Execute(asOwner, roleapp.UpdateRoleInput{ID: roleID, Rules: rules, UpdateMask: []string{"rules"}})
	if err != nil {
		return fmt.Errorf("синхронный путь сужения роли: %w", err)
	}
	if err := awaitOperationOutcome(ctx, opsRepo, op.ID); err != nil {
		return fmt.Errorf("операция сужения роли: %w", err)
	}
	if err := accessbindingapp.NewRoleMembershipFanout(fx.repo, rec).ReconcileActiveBindings(ctx, roleID); err != nil {
		return fmt.Errorf("веер сужения роли: %w", err)
	}
	return nil
}

// waitDoneOrLockWait — ждёт, пока сужение либо завершится, либо любой бэкенд базы
// пробы встанет в ожидание замка. true — сужение завершилось.
func waitDoneOrLockWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool, done <-chan error) (bool, error) {
	t.Helper()
	deadline := time.NewTimer(2 * expiryRaceBudget)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return true, err
		case <-deadline.C:
			t.Fatalf("сужение не завершилось и не встало на замке за %s", 2*expiryRaceBudget)
			return false, nil
		case <-tick.C:
			var n int
			require.NoError(t, pool.QueryRow(ctx, `
				SELECT count(*) FROM pg_stat_activity
				 WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n))
			if n > 0 {
				return false, nil
			}
		}
	}
}

func forwardVsRoleNarrowing(t *testing.T, kind forwardKind, suffix string, race bool) {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	rec, adapter := newReconciler(pool)
	ptx := newPausingTx(adapter)
	t.Cleanup(ptx.let)
	forwarder := reconcile.New(ptx, nil, catalogfixture.Source())

	// Роль до сужения — глаголы get и update (ярус редактора); после — только get.
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule()})
	narrowed := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	subj := "user:" + string(fx.member)

	fwdDone := make(chan error, 1)
	go func() {
		if kind == bindingForward {
			fwdDone <- forwarder.ReconcileBindingForward(ctx, bid)
			return
		}
		fwdDone <- forwarder.ReconcileObjectForward(ctx, "compute.instance", "iRace")
	}()
	select {
	case <-ptx.paused:
	case err := <-fwdDone:
		t.Fatalf("ПРЕДПОСЫЛКА: форвард завершился (%v), не дойдя до чтения фактов выдачи", err)
	case <-time.After(expiryRaceBudget):
		t.Fatalf("ПРЕДПОСЫЛКА: форвард не дошёл до чтения фактов выдачи за %s", expiryRaceBudget)
	}
	if !race {
		// Близнец: форвард доходит до коммита ДО сужения — последовательный порядок.
		ptx.let()
		require.NoError(t, <-fwdDone, "форвард близнеца")
		require.Equal(t, relverdict.Allow, raceObjectVerdict(t, ctx, pool, subj, "editor"),
			"ПРЕДПОСЫЛКА близнеца: до сужения роль даёт ярус редактора на объекте")
		require.NoError(t, narrowRole(ctx, pool, fx, roleID, narrowed, rec), "сужение близнеца")
	} else {
		narrowDone := make(chan error, 1)
		go func() { narrowDone <- narrowRole(ctx, pool, fx, roleID, narrowed, rec) }()
		finished, nerr := waitDoneOrLockWait(t, ctx, pool, narrowDone)
		if finished {
			require.NoError(t, nerr, "сужение")
			t.Logf("исход: сужение роли и её веер завершились, не дожидаясь форварда")
		} else {
			t.Logf("исход: сужение роли встало на замке до коммита форварда")
		}
		ptx.let()
		select {
		case err := <-fwdDone:
			require.NoError(t, err, "форвард")
		case <-time.After(expiryRaceBudget):
			t.Fatalf("форвард не завершился за %s после отпускания", expiryRaceBudget)
		}
		if !finished {
			select {
			case err := <-narrowDone:
				require.NoError(t, err, "сужение после коммита форварда")
			case <-time.After(3 * expiryRaceBudget):
				t.Fatalf("сужение не завершилось за %s после коммита форварда", 3*expiryRaceBudget)
			}
		}
	}
	afterFanout := subjectFactRelations(t, ctx, pool, subj, "compute_instance", "iRace")
	editorAfterFanout := raceObjectVerdict(t, ctx, pool, subj, "editor")
	// Сведение — ещё один полный проход выдачи (то, что делает периодический обход).
	require.NoError(t, rec.ReconcileBinding(ctx, bid), "сведение")
	afterSweep := subjectFactRelations(t, ctx, pool, subj, "compute_instance", "iRace")
	t.Logf("факты субъекта после веера: %v; после сведения: %v; вердикт editor после веера: %s",
		afterFanout, afterSweep, editorAfterFanout)
	assert.Positive(t, len(afterSweep), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: суженная роль по-прежнему даёт ярус чтения")
	assert.Equal(t, relverdict.Deny, raceObjectVerdict(t, ctx, pool, subj, "editor"),
		"после сведения суженная роль яруса редактора не даёт")
	assert.Equal(t, afterSweep, afterFanout,
		"сразу после сужения роли и её веера прямые факты обязаны совпадать с последовательным исходом")
	assert.Equal(t, relverdict.Deny, editorAfterFanout,
		"сразу после сужения роли и её веера ярус редактора, снятый сужением, не действует")
}

func TestForwardVsRoleNarrowing_ObjectForward(t *testing.T) {
	forwardVsRoleNarrowing(t, objectForward, "k926a", true)
}

func TestForwardVsRoleNarrowing_ObjectForwardTwinSequential(t *testing.T) {
	forwardVsRoleNarrowing(t, objectForward, "k926b", false)
}

func TestForwardVsRoleNarrowing_BindingForward(t *testing.T) {
	forwardVsRoleNarrowing(t, bindingForward, "k926c", true)
}

func TestForwardVsRoleNarrowing_BindingForwardTwinSequential(t *testing.T) {
	forwardVsRoleNarrowing(t, bindingForward, "k926d", false)
}
