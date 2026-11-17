// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// Сохраняем имя исторической пробы и её 3s budget, но явно меняем проверяемую
// фазу согласно принятому §8.3 grant-authority-matches-the-whole-effect.md.
// Старый synthetic holder (adapter.WithTx + AcquireBindingLock + LoadBinding)
// останавливал уже admitted unsigned writer: нынешний compatibility admission
// законно держит exclusive 9292 до конца TX. Это НЕ preparation полного прохода.
// Нельзя требовать lock-free forward при бесконечно удерживаемой apply-фазе:
// сериализация внутри account разрешена. Здесь жив настоящий FULL reconcile,
// остановленный ДО первого inventory SELECT в RR preparation и ДО coordinator.
// Пока он остановлен без authority/legacy/business locks, настоящий FULL Resource
// forward обязан за прежние 3s материализовать новый зарегистрированный объект.
// После release проверяем actual restage и сохранность committed результата.

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

const forwardLockFreeBudget = 3 * time.Second

type forwardPreparationContextKey struct{}
type forwardPreparationBeginKey struct{}

// Только помеченный вызов настоящего ReconcileBinding. Callback не выполняет
// SQL/assertions и не меняет production query; однократная остановка стоит перед
// bindingCoordinatePage. Последующие restage проходят без паузы.
type forwardPreparationPause struct {
	binding  string
	reached  chan struct{}
	release  chan struct{}
	once     sync.Once
	paused   atomic.Bool
	pid      atomic.Uint32
	rrPID    atomic.Uint32
	rrOK     atomic.Bool
	txStatus atomic.Uint32
	stages   atomic.Int32
	entries  atomic.Int32
}

func (p *forwardPreparationPause) open() { p.once.Do(func() { close(p.release) }) }
func (p *forwardPreparationPause) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if ctx.Value(forwardPreparationContextKey{}) != p {
		return ctx
	}
	sql := strings.ToLower(strings.TrimSpace(d.SQL))
	if sql == "begin isolation level repeatable read" {
		return context.WithValue(ctx, forwardPreparationBeginKey{}, true)
	}
	if strings.Contains(d.SQL, "CREATE TEMP TABLE kaname_binding_stage") {
		p.stages.Add(1)
	}
	if strings.Contains(d.SQL, "kaname.authority_protocol_enter_") || strings.Contains(d.SQL, "kaname.authority_resource_enter_") || strings.Contains(d.SQL, "kaname.authority_resource_source_enter_") || strings.Contains(d.SQL, "kaname.authority_parent_prelock_admit_") {
		p.entries.Add(1)
	}
	if strings.HasPrefix(d.SQL, "SELECT id FROM (SELECT m.object_id AS id FROM kaname.resource_mirror") && len(d.Args) > 0 {
		binding, ok := d.Args[0].(string)
		if ok && binding == p.binding && p.paused.CompareAndSwap(false, true) {
			p.pid.Store(c.PgConn().PID())
			p.txStatus.Store(uint32(c.PgConn().TxStatus()))
			close(p.reached)
			select {
			case <-p.release:
			case <-ctx.Done():
			}
		}
	}
	return ctx
}
func (p *forwardPreparationPause) TraceQueryEnd(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	if ctx.Value(forwardPreparationContextKey{}) == p && ctx.Value(forwardPreparationBeginKey{}) == true {
		p.rrPID.Store(c.PgConn().PID())
		p.rrOK.Store(d.Err == nil && c.PgConn().TxStatus() == 'T')
	}
}

// Настоящий backend preparation: begin RR успешно завершён, TX ещё жива;
// отсутствие любого advisory сильнее отдельных проверок root/account/compat/
// binding keys. Никаких business row-lock modes или tuple locks до inventory.
func forwardPreparationAssertUnfenced(t *testing.T, f resourcePublicFixture, p *forwardPreparationPause, base context.Context) {
	t.Helper()
	require.True(t, p.rrOK.Load(), "реальный BEGIN REPEATABLE READ должен завершиться")
	require.NotZero(t, p.pid.Load())
	require.Equal(t, p.rrPID.Load(), p.pid.Load())
	require.Equal(t, uint32('T'), p.txStatus.Load())
	require.Zero(t, p.entries.Load(), "coordinator/admission до preparation запрещён")
	ctx, cancel := context.WithTimeout(base, 5*time.Second)
	defer cancel()
	var alive bool
	var bad int
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND datname=current_database() AND usename=$2 AND state='idle in transaction' AND xact_start IS NOT NULL), (SELECT count(*) FROM pg_catalog.pg_locks l LEFT JOIN pg_catalog.pg_class c ON c.oid=l.relation LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=$1 AND (l.locktype IN ('advisory','tuple') OR (n.nspname='kaname' AND l.mode<>'AccessShareLock')))`, p.pid.Load(), f.r.runtime.Config().ConnConfig.User).Scan(&alive, &bad))
	require.True(t, alive, "наблюдаем именно живую runtime TX остановленного full pass")
	require.Zero(t, bad, "preparation не держит root/account/binding/compat или business row locks")
}

func forwardPreparationEffects(t *testing.T, f resourcePublicFixture, base context.Context, id string, want bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(base, 5*time.Second)
	defer cancel()
	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"visible": "yes"}}
	var members, active, ledger, grant int
	require.NoError(t, f.r.runtime.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE verification_status='ACTIVE' AND rule_fp=$3),
        (SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$4),
        (SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$4 AND fga_user=$5 AND relation='v_get')
        FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_type='vpc.network' AND object_id=$2`, string(f.bindings[0]), id, rule.Fingerprint(), "vpc_network:"+id, "user:"+f.members[0]).Scan(&members, &active, &ledger, &grant))
	if !want {
		require.Zero(t, members, "Given и baseline не должны материализовать held object")
		require.Zero(t, ledger, "до actual forward нет ни одного emitted tuple этого binding/object")
		return
	}
	require.Equal(t, 1, members)
	require.Equal(t, 1, active, "committed target-member обязан быть ACTIVE для исходного rule")
	require.Positive(t, ledger)
	require.Equal(t, 1, grant, "committed per-object grant виден до release preparation")
}

func TestReconcileForward_07_DoesNotQueueBehindInFlightFullPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	f := newResourcePublicFixture(t, 2)
	base, cancelBase := context.WithCancel(context.WithoutCancel(f.ctx))
	t.Cleanup(cancelBase)
	freeID, heldID := ids.NewID("net"), ids.NewID("net")
	// Given: штатный Register с реальным module identity и receipt, до FULL.
	// Необязательный postcommit accelerator не запускается: проверяем именно
	// отдельный forward, как исходная проба, а не detached 30s Register callback.
	// Нет fake mirror/permissions; отсутствие effects ниже обязательно.
	f.uc.WithObjectReconciler(nil, slog.Default())
	for _, id := range []string{freeID, heldID} {
		ctx, cancel := context.WithTimeout(base, 30*time.Second)
		err := f.uc.Register(ctx, f.request(0, id, time.Now()))
		cancel()
		require.NoError(t, err)
		forwardPreparationEffects(t, f, base, id, false)
	}
	pause := &forwardPreparationPause{binding: string(f.bindings[0]), reached: make(chan struct{}), release: make(chan struct{})}
	// Настройка tracer предшествует FULL. Реконструируем full repository и
	// ResourceDecisionRunner на одном обычном LOGIN pool, без добавочного pool.
	cfg := f.r.runtime.Config()
	cfg.ConnConfig.Tracer = pause
	f.r.runtime.Close()
	setup, cancelSetup := context.WithTimeout(base, 30*time.Second)
	defer cancelSetup()
	pool, err := pgxpool.NewWithConfig(setup, cfg)
	if pool != nil {
		t.Cleanup(pool.Close)
	}
	require.NoError(t, err)
	require.NotNil(t, pool)
	f.r.runtime, f.r.repo, f.r.ctx = pool, kanamepg.New(pool, nil), setup
	// Предыдущий активный набор закрывается штатно перед повторным FULL staging.
	require.NoError(t, lifecycleOwner(f.r).CloseAuthorityBundle(setup))
	f.r.repo, _ = fullContractActivate(t, f.r)
	// Gate не переносим с закрытого staged pool.
	f.gate = authzguard.NewRelationWriteGate(delegationNativeDoor{f.r}).WithModuleRoster(f.roster)
	runner, err := kanamepg.NewResourceDecisionRunner(setup, f.r.repo, f.r.bundle, f.gate)
	require.NoError(t, err)
	f.engine, err = runner.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	full := bindingStageEngine(t, f.r, nil) // nil не заменяет full repo новым staged repo
	cancelSetup()

	forward := func(id string) {
		ctx, cancel := context.WithTimeout(base, forwardLockFreeBudget)
		done := make(chan struct{})
		var callErr error
		var elapsed time.Duration
		// Hard await из исходной пробы сохранён; cleanup зарегистрирован до worker.
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Errorf("FULL forward worker did not join after cancellation")
			}
		})
		go func() {
			defer close(done)
			started := time.Now()
			callErr = f.engine.ReconcileObjectForward(ctx, "vpc.network", id)
			elapsed = time.Since(started)
		}()
		select {
		case <-done:
			cancel()
			require.NoError(t, callErr, "FULL forward обязан пройти при живой unfenced preparation")
			require.LessOrEqual(t, elapsed, forwardLockFreeBudget, "прежний 3s budget не расширен")
		case <-time.After(forwardLockFreeBudget + time.Second):
			t.Fatal("FULL forward не завершился в прежний bounded await")
		}
		forwardPreparationEffects(t, f, base, id, true)
	}
	// Положительный контроль на том же FULL runner до запуска holder.
	forward(freeID)
	forwardPreparationEffects(t, f, base, heldID, false)

	prepCtx, cancelPrep := context.WithTimeout(context.WithValue(base, forwardPreparationContextKey{}, pause), 30*time.Second)
	done := make(chan struct{})
	var fullErr error
	// Cleanup установлен ДО горутины и любых последующих assertions.
	t.Cleanup(func() {
		pause.open()
		cancelPrep()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Errorf("FULL preparation worker did not join after cancel/release")
		}
	})
	go func() { defer close(done); fullErr = full.ReconcileBinding(prepCtx, f.bindings[0]) }()
	select {
	case <-pause.reached:
	case <-done:
		require.NoError(t, fullErr)
		t.Fatal("actual full pass не достиг inventory barrier")
	case <-prepCtx.Done():
		t.Fatal("actual full pass не достиг inventory barrier до request deadline")
	}
	require.EqualValues(t, 1, pause.stages.Load())
	forwardPreparationAssertUnfenced(t, f, pause, base)
	forwardPreparationEffects(t, f, base, heldID, false)
	forward(heldID)
	// Эффект уже committed, а inventory SQL полного прохода ещё не отправлен.
	select {
	case <-done:
		t.Fatal("preparation завершилась до явного release")
	default:
	}
	forwardPreparationAssertUnfenced(t, f, pause, base)
	pause.open()
	select {
	case <-done:
		require.NoError(t, fullErr)
	case <-prepCtx.Done():
		t.Fatal("full pass не завершился после release в прежний request budget")
	}
	cancelPrep()
	require.GreaterOrEqual(t, pause.stages.Load(), int32(2), "concurrent forward обязан инвалидировать старый snapshot и вызвать штатный restage")
	forwardPreparationEffects(t, f, base, freeID, true)
	forwardPreparationEffects(t, f, base, heldID, true)
	// Отдельный bounded consistency pass не подменяет уже проверенные эффекты.
	ctx, cancel := context.WithTimeout(base, 30*time.Second)
	defer cancel()
	require.NoError(t, full.ReconcileBinding(ctx, f.bindings[0]))
	forwardPreparationEffects(t, f, base, freeID, true)
	forwardPreparationEffects(t, f, base, heldID, true)
}
