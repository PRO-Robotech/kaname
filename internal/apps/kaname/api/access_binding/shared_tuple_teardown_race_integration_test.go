// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// shared_tuple_teardown_race_integration_test.go — снятие одной из двух выдач,
// держащих ОБЩИЙ кортеж (kaname#919): SD-919-N1 и DB-919-A.
//
// # Предмет
//
// Реестр выпущенных кортежей ключуется выдачей, а прямой факт отношения — нет:
// его ключ (объект, отношение, субъект). Две выдачи ОДНОМУ субъекту на ОДНУ
// область с ролями, дающими один ярус, держат две строки реестра на один факт.
// Снятие выдачи (отзыв, удаление) пишет строки снятия на свой реестр; триггер
// журнала намерений снимает факт в той же транзакции, если версия факта не новее
// версии строки снятия и факт не держит никто другой. Прежде «держит ли другая
// ДЕЙСТВУЮЩАЯ выдача» спрашивал use-case, до вставки строки, на снимке своей
// транзакции; теперь — свёртка строки, под замком строки факта (kaname#919).
//
// SD-919-N1 — последовательно: снятие одной выдачи не убирает факт, который
// держит вторая. Близнецы в том же прогоне: собственный кортеж снятой выдачи
// снят (снятие действительно сработало), а снятие второй, последней, выдачи
// снимает и общий факт (наблюдение способно увидеть снятие).
//
// DB-919-A — гонка: вторая выдача того же кортежа ФИКСИРУЕТСЯ между проверкой
// «ещё держит» у снятия первой и вставкой его строки снятия. Проверка второй
// выдачи не видит (она не зафиксирована), и строка снятия несёт общий кортеж.
// Утверждается исход после обеих транзакций: вторая выдача действует, её строка
// реестра есть, И ПРЯМОЙ ФАКТ ЕСТЬ — иначе действующая выдача не даёт доступа.
// Порядков начала транзакций два, оба ставятся:
//   - revoke-first: снятие открыло транзакцию раньше выдачи;
//   - grant-first:  выдача открыла транзакцию раньше снятия и держит коммит,
//     пока снятие не пройдёт проверку.
//
// # Как поставлена остановка
//
// Обе стороны — НАСТОЯЩИЕ use-case (Create, Revoke, Delete) на настоящем
// pg-репозитории. Остановку даёт обёртка порта Repository, которая не меняет ни
// одного ответа: у снятия она останавливает транзакцию ПЕРЕД вставкой строк снятия
// (EmitRelationDelete) — снятие к этому моменту решило, что снимает, и всё, что
// оно спросило о соседях, уже спрошено; у выдачи — перед Commit. Набор строк
// снятия записывается: снятие, не назвавшее общий кортеж, — отказ ПРЕДПОСЫЛКИ
// (гонке не о чем), а не исход.
//
// Прежде остановка стояла после проверки приложения «ещё держит»
// (SelectTuplesClaimedByOtherActiveBindings). Проверка снята: вопрос о держателях
// задаёт свёртка строки снятия под замком строки факта (миграция
// 20261019180000). Точка «решено, что снимать, строки снятия ещё нет» от этого не
// сдвинулась — она стоит там же относительно гонки на обеих ревизиях.
//
// # Остальные писатели того же кортежа (kaname#919)
//
// Строку снятия пишет не только отзыв и удаление. Перепись писателей — смена
// роли (RoleTupleReconciler), снос области, истечение срока, отзыв
// администратора кластера, полный проход — и все они пишут её одной функцией,
// а свёртка у неё одна. Пробы ниже:
//   - DB-919-B — два снятия двух держателей общего кортежа, оба решили, что
//     снимать, до коммита соседа: после обоих факта нет (ни один держатель не
//     остался — факт без держателя был бы доступом без выдачи);
//   - SD-919-R — смена роли выводит общий кортеж из реестра выдачи A: факт,
//     который держит B, остаётся; без B тот же шаг его снимает (близнец: свой
//     реестр писатель убирает ДО строки снятия);
//   - SD-919-W — строка снятия ЛЮБОГО писателя (журнал напрямую) не снимает
//     факт, который держит реестр действующей выдачи; близнец — факт без
//     держателя той же строкой снимается;
//   - SD-919-C — назначение администратора кластера держит тот же кортеж, что
//     выдача роли кластера: строка снятия не снимает его, пока назначение
//     действует; близнец — снятое назначение.
//
// # Почему конструктор Create зовётся отражением
//
// Проба гонится на двух головах (ветка задачи и ветка эпика), у которых
// конструктор CreateAccessBindingUseCase различается третьим параметром —
// источником каталога. Отражение подаёт его, только если конструктор его ждёт;
// поведение use-case от этого не зависит.

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// sharedRaceBudget — предел ожидания каждой остановки и каждой операции.
const sharedRaceBudget = 30 * time.Second

// ── остановка внутри настоящего use-case ─────────────────────────────────────

// pausePoint — точка остановки: reached закрывается при первом достижении,
// дальше исполнение ждёт release.
type pausePoint struct {
	reached chan struct{}
	release chan struct{}
	hitOnce sync.Once
	letOnce sync.Once
	mu      sync.Mutex
	named   []abrepo.RelationTuple
}

func newPausePoint() *pausePoint {
	return &pausePoint{reached: make(chan struct{}), release: make(chan struct{})}
}

func (p *pausePoint) hit() {
	p.hitOnce.Do(func() { close(p.reached) })
	<-p.release
}

func (p *pausePoint) let() { p.letOnce.Do(func() { close(p.release) }) }

func (p *pausePoint) record(named []abrepo.RelationTuple) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.named = append([]abrepo.RelationTuple(nil), named...)
}

// deleteSet — набор строк снятия, который снятие назвало у остановки.
func (p *pausePoint) deleteSet() []abrepo.RelationTuple {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.named
}

// waitReached — точка достигнута; иначе отказ ПРЕДПОСЫЛКИ с названным шагом.
func waitReached(t *testing.T, p *pausePoint, what string, done <-chan error) {
	t.Helper()
	select {
	case <-p.reached:
	case err := <-done:
		t.Fatalf("ПРЕДПОСЫЛКА: %s — операция завершилась (%v), не дойдя до остановки", what, err)
	case <-time.After(sharedRaceBudget):
		t.Fatalf("ПРЕДПОСЫЛКА: %s — остановка не достигнута за %s", what, sharedRaceBudget)
	}
}

// pausingRepo — порт Repository настоящего pg-репозитория, ответы которого не
// меняются; добавлены лишь остановки.
type pausingRepo struct {
	accessbindingapp.Repo
	beforeDeleteRows *pausePoint // перед вставкой строк снятия
	beforeCommit     *pausePoint // перед фиксацией пишущей транзакции
}

func (r pausingRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	w, err := r.Repo.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &pausingWriter{Writer: w, r: r}, nil
}

type pausingWriter struct {
	kanamerepo.Writer
	r pausingRepo
}

func (w *pausingWriter) AccessBindingsW() abrepo.WriterIface {
	if w.r.beforeDeleteRows == nil {
		return w.Writer.AccessBindingsW()
	}
	return pausingABWriter{WriterIface: w.Writer.AccessBindingsW(), p: w.r.beforeDeleteRows}
}

func (w *pausingWriter) Commit(ctx context.Context) error {
	if w.r.beforeCommit != nil {
		w.r.beforeCommit.hit()
	}
	return w.Writer.Commit(ctx)
}

type pausingABWriter struct {
	abrepo.WriterIface
	p *pausePoint
}

func (w pausingABWriter) EmitRelationDelete(ctx context.Context, tuples []abrepo.RelationTuple) error {
	w.p.record(tuples)
	w.p.hit()
	return w.WriterIface.EmitRelationDelete(ctx, tuples)
}

// ── фикстура ─────────────────────────────────────────────────────────────────

type sharedFixture struct {
	pool    *pgxpool.Pool
	repo    *kanamepg.Repository
	opsRepo operations.Repo
	owner   domain.UserID
	member  domain.UserID
	acc     domain.AccountID
	roleA   domain.RoleID
	roleB   domain.RoleID
}

// newSharedFixture — владелец аккаунта, участник и ДВЕ роли аккаунта с одним и
// тем же набором разрешений: выдачи участнику на аккаунт по каждой из них
// выпускают один и тот же кортеж яруса на якоре аккаунта.
func newSharedFixture(t *testing.T, ctx context.Context, suffix string) sharedFixture {
	t.Helper()
	pool := poolFromDSN(t, setupTestDB(t))
	fx := sharedFixture{
		pool:    pool,
		repo:    kanamepg.New(pool, nil),
		opsRepo: operations.NewRepo(pool, "kaname"),
	}
	fx.owner = mustSeedUser(t, ctx, pool, suffix+"o")
	fx.acc = seedAccountByOwner(t, ctx, pool, "acc-"+suffix, fx.owner)
	fx.member = mustSeedUser(t, ctx, pool, suffix+"m")
	fx.roleA = seedAccountCustomRole(t, ctx, pool, fx.acc, suffix+"_a")
	fx.roleB = seedAccountCustomRole(t, ctx, pool, fx.acc, suffix+"_b")
	return fx
}

// newCreateUseCase — настоящий Create на данном порте (см. шапку: отражение
// подаёт источник каталога, только если конструктор его ждёт).
func newCreateUseCase(t *testing.T, repo accessbindingapp.Repo, opsRepo operations.Repo) *accessbindingapp.CreateAccessBindingUseCase {
	t.Helper()
	ctor := reflect.ValueOf(accessbindingapp.NewCreateAccessBindingUseCase)
	args := []reflect.Value{reflect.ValueOf(&repo).Elem(), reflect.ValueOf(&opsRepo).Elem()}
	switch ctor.Type().NumIn() {
	case 2:
	case 3:
		args = append(args, reflect.ValueOf(catalogfixture.Source()))
	default:
		t.Fatalf("ПРЕДПОСЫЛКА: конструктор Create ждёт %d параметров — проба знает формы с 2 и 3", ctor.Type().NumIn())
	}
	uc := ctor.Call(args)[0].Interface().(*accessbindingapp.CreateAccessBindingUseCase)
	return uc.WithRelationStore(denyingRelations{}, nil)
}

// startGrant запускает настоящий Create выдачи участнику на аккаунт по роли.
func startGrant(t *testing.T, ctx context.Context, fx sharedFixture, repo accessbindingapp.Repo, role domain.RoleID) <-chan error {
	t.Helper()
	op, err := newCreateUseCase(t, repo, fx.opsRepo).Execute(asUser(ctx, fx.owner), domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(fx.member),
		RoleID: role, ResourceType: "account", ResourceID: string(fx.acc),
		Scope: domain.ScopeAccount,
	})
	require.NoError(t, err, "синхронный путь Create (право владельца аккаунта) обязан пройти")
	return awaitOutcome(ctx, fx.opsRepo, op.ID)
}

// startRevoke / startDelete — настоящие Revoke и Delete выдачи.
func startRevoke(t *testing.T, ctx context.Context, fx sharedFixture, repo accessbindingapp.Repo, id domain.AccessBindingID) <-chan error {
	t.Helper()
	op, err := accessbindingapp.NewRevokeAccessBindingUseCase(repo, fx.opsRepo).
		WithRelationStore(ownerHoldsRemoval{owner: string(fx.owner)}, nil).Execute(asUser(ctx, fx.owner), id)
	require.NoError(t, err, "синхронный путь Revoke (право владельца аккаунта) обязан пройти")
	return awaitOutcome(ctx, fx.opsRepo, op.ID)
}

func startDelete(t *testing.T, ctx context.Context, fx sharedFixture, repo accessbindingapp.Repo, id domain.AccessBindingID) <-chan error {
	t.Helper()
	op, err := accessbindingapp.NewDeleteAccessBindingUseCase(repo, fx.opsRepo).
		WithRelationStore(ownerHoldsRemoval{owner: string(fx.owner)}, nil).Execute(asUser(ctx, fx.owner), id)
	require.NoError(t, err, "синхронный путь Delete (право владельца аккаунта) обязан пройти")
	return awaitOutcome(ctx, fx.opsRepo, op.ID)
}

// awaitOutcome — канал исхода операции: nil при успехе, ошибка с текстом отказа.
func awaitOutcome(ctx context.Context, opsRepo operations.Repo, id string) <-chan error {
	done := make(chan error, 1)
	go func() {
		deadline := time.NewTimer(2 * sharedRaceBudget)
		defer deadline.Stop()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-deadline.C:
				done <- &opRefused{msg: "операция " + id + " не завершилась за " + (2 * sharedRaceBudget).String()}
				return
			case <-tick.C:
				op, err := opsRepo.Get(ctx, id)
				if err != nil {
					done <- err
					return
				}
				if !op.Done {
					continue
				}
				if op.Error != nil {
					done <- &opRefused{msg: fmt.Sprintf("%v", op.Error)}
					return
				}
				done <- nil
				return
			}
		}
	}()
	return done
}

type opRefused struct{ msg string }

func (e *opRefused) Error() string {
	return "операция завершилась отказом: " + e.msg
}

func mustDone(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err, what)
	case <-time.After(3 * sharedRaceBudget):
		t.Fatalf("%s: исхода нет за %s", what, 3*sharedRaceBudget)
	}
}

// activeBindingOf — id ДЕЙСТВУЮЩЕЙ выдачи участнику на аккаунт по роли.
func activeBindingOf(t *testing.T, ctx context.Context, fx sharedFixture, role domain.RoleID) domain.AccessBindingID {
	t.Helper()
	var id string
	require.NoError(t, fx.pool.QueryRow(ctx, `
		SELECT id FROM kaname.access_bindings
		 WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2
		   AND subject_id = $3 AND status = 'ACTIVE'`,
		string(role), string(fx.acc), string(fx.member)).Scan(&id),
		"действующая выдача по роли %s", role)
	return domain.AccessBindingID(id)
}

func bindingStatusOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.AccessBindingID) string {
	t.Helper()
	var st string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT status FROM kaname.access_bindings WHERE id = $1`, string(id)).Scan(&st))
	return st
}

// ledgerOf — строки реестра выпущенных кортежей выдачи.
func ledgerOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.AccessBindingID) map[abrepo.RelationTuple]struct{} {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT fga_user, relation, object FROM kaname.access_binding_emitted_tuples
		 WHERE binding_id = $1`, string(id))
	require.NoError(t, err)
	defer rows.Close()
	out := map[abrepo.RelationTuple]struct{}{}
	for rows.Next() {
		var k abrepo.RelationTuple
		require.NoError(t, rows.Scan(&k.User, &k.Relation, &k.Object))
		out[k] = struct{}{}
	}
	require.NoError(t, rows.Err())
	return out
}

// factual — кортеж, который складывается в прямой факт: глаголы (`v_*`) свёртка
// журнала отбрасывает, их доступ выводится из выдачи.
func factual(k abrepo.RelationTuple) bool { return !strings.HasPrefix(k.Relation, "v_") }

// sharedFacts — кортежи-факты, которые есть в реестрах ОБЕИХ выдач.
func sharedFacts(a, b map[abrepo.RelationTuple]struct{}) []abrepo.RelationTuple {
	var out []abrepo.RelationTuple
	for k := range a {
		if _, ok := b[k]; ok && factual(k) {
			out = append(out, k)
		}
	}
	return out
}

// ownFacts — кортежи-факты реестра a, которых нет в реестре b.
func ownFacts(a, b map[abrepo.RelationTuple]struct{}) []abrepo.RelationTuple {
	var out []abrepo.RelationTuple
	for k := range a {
		if _, ok := b[k]; !ok && factual(k) {
			out = append(out, k)
		}
	}
	return out
}

// factPresent — есть ли прямой факт кортежа.
func factPresent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, k abrepo.RelationTuple) bool {
	t.Helper()
	typ, id, ok := strings.Cut(k.Object, ":")
	require.True(t, ok, "объект кортежа %v без формы <тип>:<id>", k)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		typ, id, k.Relation, k.User).Scan(&n))
	return n > 0
}

func containsTuple(set []abrepo.RelationTuple, k abrepo.RelationTuple) bool {
	for _, s := range set {
		if s == k {
			return true
		}
	}
	return false
}

// ── SD-919-N1: снятие одной из двух выдач не убирает факт, который держит вторая ─

func TestAccessBinding_SD919N1_TeardownKeepsFactHeldBySecondGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, tc := range []struct {
		name  string
		start func(*testing.T, context.Context, sharedFixture, accessbindingapp.Repo, domain.AccessBindingID) <-chan error
	}{
		{"revoke", startRevoke},
		{"delete", startDelete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx := newSharedFixture(t, ctx, "n1"+tc.name[:1])

			mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleA), "выдача A")
			mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleB), "выдача B")
			idA := activeBindingOf(t, ctx, fx, fx.roleA)
			idB := activeBindingOf(t, ctx, fx, fx.roleB)
			ledgerA, ledgerB := ledgerOf(t, ctx, fx.pool, idA), ledgerOf(t, ctx, fx.pool, idB)
			shared := sharedFacts(ledgerA, ledgerB)
			ownA := ownFacts(ledgerA, ledgerB)
			t.Logf("перепись: реестр A %d, реестр B %d, общих фактов %d, своих фактов A %d", len(ledgerA), len(ledgerB), len(shared), len(ownA))
			require.NotEmpty(t, shared, "ПРЕДПОСЫЛКА: у двух выдач нет общего кортежа-факта — предмету не о чем")
			require.NotEmpty(t, ownA, "ПРЕДПОСЫЛКА: у выдачи A нет своего кортежа-факта — близнецу «снятие сработало» не о чем")
			for _, k := range append(append([]abrepo.RelationTuple{}, shared...), ownA...) {
				require.True(t, factPresent(t, ctx, fx.pool, k), "ПРЕДПОСЫЛКА: прямого факта %v нет до снятия", k)
			}

			mustDone(t, tc.start(t, ctx, fx, fx.repo, idA), "снятие выдачи A ("+tc.name+")")

			for _, k := range ownA {
				assert.False(t, factPresent(t, ctx, fx.pool, k),
					"БЛИЗНЕЦ: собственный факт %v снятой (%s) выдачи A остался — снятие не сработало, и сохранность общего факта ни о чём", k, tc.name)
			}
			assert.Equal(t, string(domain.AccessBindingStatusActive), bindingStatusOf(t, ctx, fx.pool, idB), "выдача B действует")
			for _, k := range shared {
				assert.True(t, factPresent(t, ctx, fx.pool, k),
					"снятие (%s) выдачи A сняло прямой факт %v, который держит действующая выдача B, — доступ потерян", tc.name, k)
			}

			// Близнец наблюдения: снятие ПОСЛЕДНЕЙ выдачи снимает и общий факт.
			mustDone(t, startRevoke(t, ctx, fx, fx.repo, idB), "отзыв выдачи B")
			for _, k := range shared {
				assert.False(t, factPresent(t, ctx, fx.pool, k),
					"БЛИЗНЕЦ: после снятия последней выдачи общий факт %v остался — наблюдение не видит снятия", k)
			}
		})
	}
}

// ── DB-919-A: вторая выдача фиксируется между «ещё держит» и строкой снятия ──

func TestAccessBinding_DB919A_SecondGrantCommittedBetweenClaimCheckAndDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, order := range []string{"revoke-first", "grant-first"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			fx := newSharedFixture(t, ctx, "a"+order[:1])

			mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleA), "выдача A")
			idA := activeBindingOf(t, ctx, fx, fx.roleA)

			checkPause := newPausePoint()
			t.Cleanup(checkPause.let)
			revokeRepo := pausingRepo{Repo: fx.repo, beforeDeleteRows: checkPause}

			var revokeDone, grantDone <-chan error
			switch order {
			case "revoke-first":
				// Снятие открывает транзакцию и решает, что снимать; выдача B начинается
				// и фиксируется целиком, пока снятие стоит перед строками снятия.
				revokeDone = startRevoke(t, ctx, fx, revokeRepo, idA)
				waitReached(t, checkPause, "отзыв A перед строками снятия", revokeDone)
				mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleB), "выдача B в паузе отзыва")
			case "grant-first":
				// Выдача B открывает транзакцию первой и держит коммит; снятие решает,
				// что снимать, не видя её; затем выдача фиксируется.
				commitPause := newPausePoint()
				t.Cleanup(commitPause.let)
				grantDone = startGrant(t, ctx, fx, pausingRepo{Repo: fx.repo, beforeCommit: commitPause}, fx.roleB)
				waitReached(t, commitPause, "выдача B перед коммитом", grantDone)
				revokeDone = startRevoke(t, ctx, fx, revokeRepo, idA)
				waitReached(t, checkPause, "отзыв A перед строками снятия", revokeDone)
				commitPause.let()
				mustDone(t, grantDone, "выдача B после решения отзыва")
			}

			idB := activeBindingOf(t, ctx, fx, fx.roleB)
			ledgerB := ledgerOf(t, ctx, fx.pool, idB)
			shared := sharedFacts(ledgerOf(t, ctx, fx.pool, idA), ledgerB)
			require.NotEmpty(t, shared, "ПРЕДПОСЫЛКА: у выдач A и B нет общего кортежа-факта — гонке не о чем")
			named := checkPause.deleteSet()
			for _, k := range shared {
				require.True(t, containsTuple(named, k),
					"ПРЕДПОСЫЛКА: отзыв A не назвал общий кортеж %v в строках снятия — гонке не о чем", k)
				require.True(t, factPresent(t, ctx, fx.pool, k),
					"БЛИЗНЕЦ В ПРОГОНЕ: зафиксированная выдача B обязана дать прямой факт %v до строки снятия — иначе исход ни о чём", k)
			}
			t.Logf("перепись: общих фактов %d, строк снятия названо %d", len(shared), len(named))

			checkPause.let()
			mustDone(t, revokeDone, "отзыв A после коммита выдачи B")

			assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatusOf(t, ctx, fx.pool, idA), "выдача A отозвана")
			assert.Equal(t, string(domain.AccessBindingStatusActive), bindingStatusOf(t, ctx, fx.pool, idB), "выдача B действует")
			after := ledgerOf(t, ctx, fx.pool, idB)
			for _, k := range shared {
				_, inLedger := after[k]
				assert.True(t, inLedger, "строка реестра выдачи B по %v пропала", k)
				assert.True(t, factPresent(t, ctx, fx.pool, k),
					"%s: после обеих транзакций прямого факта %v нет, а выдача B, его выпустившая, действует — доступ без факта потерян", order, k)
			}
		})
	}
}

// ── DB-919-B: оба держателя сняты, каждый решил до коммита соседа ────────────

func TestAccessBinding_DB919B_BothHoldersTornDownBeforeEitherCommits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, tc := range []struct {
		name   string
		startB func(*testing.T, context.Context, sharedFixture, accessbindingapp.Repo, domain.AccessBindingID) <-chan error
		aFirst bool
	}{
		{"revoke-revoke/a-commits-first", startRevoke, true},
		{"revoke-revoke/b-commits-first", startRevoke, false},
		{"revoke-delete/a-commits-first", startDelete, true},
		{"revoke-delete/b-commits-first", startDelete, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx := newSharedFixture(t, ctx, "b"+tc.name[7:8]+tc.name[strings.Index(tc.name, "/")+1:][:1])

			mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleA), "выдача A")
			mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleB), "выдача B")
			idA := activeBindingOf(t, ctx, fx, fx.roleA)
			idB := activeBindingOf(t, ctx, fx, fx.roleB)
			ledgerA, ledgerB := ledgerOf(t, ctx, fx.pool, idA), ledgerOf(t, ctx, fx.pool, idB)
			shared := sharedFacts(ledgerA, ledgerB)
			ownA := ownFacts(ledgerA, ledgerB)
			require.NotEmpty(t, shared, "ПРЕДПОСЫЛКА: у двух выдач нет общего кортежа-факта — предмету не о чем")
			require.NotEmpty(t, ownA, "ПРЕДПОСЫЛКА: у выдачи A нет своего кортежа-факта — близнецу «снятие сработало» не о чем")
			for _, k := range shared {
				require.True(t, factPresent(t, ctx, fx.pool, k), "ПРЕДПОСЫЛКА: прямого факта %v нет до снятия", k)
			}

			pA, pB := newPausePoint(), newPausePoint()
			t.Cleanup(pA.let)
			t.Cleanup(pB.let)
			doneA := startRevoke(t, ctx, fx, pausingRepo{Repo: fx.repo, beforeDeleteRows: pA}, idA)
			waitReached(t, pA, "снятие A перед строками снятия", doneA)
			doneB := tc.startB(t, ctx, fx, pausingRepo{Repo: fx.repo, beforeDeleteRows: pB}, idB)
			waitReached(t, pB, "снятие B перед строками снятия", doneB)
			t.Logf("перепись: общих фактов %d, строк снятия A %d, B %d", len(shared), len(pA.deleteSet()), len(pB.deleteSet()))

			if tc.aFirst {
				pA.let()
				mustDone(t, doneA, "снятие A")
				pB.let()
				mustDone(t, doneB, "снятие B")
			} else {
				pB.let()
				mustDone(t, doneB, "снятие B")
				pA.let()
				mustDone(t, doneA, "снятие A")
			}

			assert.NotEqual(t, string(domain.AccessBindingStatusActive), bindingStatusOf(t, ctx, fx.pool, idA), "выдача A снята")
			for _, k := range ownA {
				assert.False(t, factPresent(t, ctx, fx.pool, k),
					"БЛИЗНЕЦ: собственный факт %v снятой выдачи A остался — снятие не сработало вовсе", k)
			}
			for _, k := range shared {
				assert.False(t, factPresent(t, ctx, fx.pool, k),
					"%s: обе выдачи, выпустившие %v, сняты, а прямой факт остался — доступ без выдачи", tc.name, k)
			}
		})
	}
}

// ── SD-919-R: смена роли выводит общий кортеж из реестра одной из двух выдач ─

func TestAccessBinding_SD919R_RoleNarrowingKeepsFactHeldBySecondGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, tc := range []struct {
		name        string
		secondGrant bool
	}{
		{"held-by-second-grant", true},
		{"no-other-holder", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx := newSharedFixture(t, ctx, "r"+tc.name[:1])

			mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleA), "выдача A")
			idA := activeBindingOf(t, ctx, fx, fx.roleA)
			before := ledgerOf(t, ctx, fx.pool, idA)
			if tc.secondGrant {
				mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleB), "выдача B")
			}

			// Смена роли A с чтения на правку — шаг смены роли, тот же, что зовёт
			// Role.Update в своей транзакции: ярус выдачи уходит с viewer на editor,
			// и кортеж viewer (общий с B) выходит из реестра A. Пустой набор
			// разрешений ярус не снимает — он читается наименьшим (viewer).
			w, err := fx.repo.Writer(ctx)
			require.NoError(t, err)
			committed := false
			t.Cleanup(func() {
				if !committed {
					_ = w.Rollback(context.Background())
				}
			})
			require.NoError(t, accessbindingapp.NewRoleTupleReconciler().ReconcileRoleTuples(ctx, w, fx.roleA,
				domain.Role{ID: fx.roleA, AccountID: fx.acc, Name: "narrowed", Permissions: domain.Permissions{"iam.users.*.update"}}))
			require.NoError(t, w.Commit(ctx))
			committed = true

			after := ledgerOf(t, ctx, fx.pool, idA)
			removed := ownFacts(before, after)
			require.NotEmpty(t, removed, "ПРЕДПОСЫЛКА: смена роли не вывела из реестра A ни одного кортежа-факта — снятию не о чем")
			t.Logf("перепись: реестр A до %d, после %d, выведено кортежей-фактов %d", len(before), len(after), len(removed))

			var ledgerB map[abrepo.RelationTuple]struct{}
			if tc.secondGrant {
				ledgerB = ledgerOf(t, ctx, fx.pool, activeBindingOf(t, ctx, fx, fx.roleB))
			}
			heldByB := 0
			for _, k := range removed {
				_, held := ledgerB[k]
				if held {
					heldByB++
					assert.True(t, factPresent(t, ctx, fx.pool, k),
						"смена роли A сняла прямой факт %v, который держит действующая выдача B, — доступ потерян", k)
					continue
				}
				assert.False(t, factPresent(t, ctx, fx.pool, k),
					"смена роли A не сняла прямой факт %v, которого не держит никто, — доступ сверх роли", k)
			}
			if tc.secondGrant {
				require.NotZero(t, heldByB, "ПРЕДПОСЫЛКА: среди выведенного из реестра A нет кортежа, который держит B, — предмету не о чем")
			}
		})
	}
}

// ── SD-919-W: строка снятия любого писателя и факт, который держит выдача ────

// journal кладёт строки журнала одной транзакцией — так пишет любой писатель,
// кроме use-case выдачи (снос области, отзыв администратора кластера, смена
// ресурса, полный проход).
func journal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, emit func(context.Context, pgx.Tx, []clients.RelationTuple) error, k clients.RelationTuple) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	require.NoError(t, emit(ctx, tx, []clients.RelationTuple{k}))
	require.NoError(t, tx.Commit(ctx))
}

func asClient(k abrepo.RelationTuple) clients.RelationTuple {
	return clients.RelationTuple{User: k.User, Relation: k.Relation, Object: k.Object}
}

func TestRelationFact_SD919W_AnyWritersDeleteRowKeepsAFactAGrantHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	fx := newSharedFixture(t, ctx, "w")
	mustDone(t, startGrant(t, ctx, fx, fx.repo, fx.roleA), "выдача A")
	ledgerA := ledgerOf(t, ctx, fx.pool, activeBindingOf(t, ctx, fx, fx.roleA))
	held := ownFacts(ledgerA, nil)
	require.NotEmpty(t, held, "ПРЕДПОСЫЛКА: выдача A не выпустила ни одного кортежа-факта")

	for _, k := range held {
		require.True(t, factPresent(t, ctx, fx.pool, k), "ПРЕДПОСЫЛКА: прямого факта %v нет", k)
		journal(t, ctx, fx.pool, fga_outbox.EmitDeleteTx, asClient(k))
		assert.True(t, factPresent(t, ctx, fx.pool, k),
			"строка снятия стороннего писателя сняла прямой факт %v, который держит реестр действующей выдачи A", k)
	}

	// Близнец: факт, которого не держит никто, та же строка снимает.
	free := abrepo.RelationTuple{User: "user:" + string(fx.member), Relation: "editor", Object: "account:" + string(fx.acc)}
	_, inLedger := ledgerA[free]
	require.False(t, inLedger, "ПРЕДПОСЫЛКА: кортеж близнеца %v держит реестр A", free)
	journal(t, ctx, fx.pool, fga_outbox.EmitWriteTx, asClient(free))
	require.True(t, factPresent(t, ctx, fx.pool, free), "ПРЕДПОСЫЛКА: запись близнеца не легла фактом")
	journal(t, ctx, fx.pool, fga_outbox.EmitDeleteTx, asClient(free))
	assert.False(t, factPresent(t, ctx, fx.pool, free),
		"БЛИЗНЕЦ: строка снятия не сняла факт %v, которого не держит никто, — свёртка не снимает вовсе", free)
}

// ── SD-919-C: назначение администратора кластера держит свой кортеж ──────────

func TestRelationFact_SD919C_ClusterAdminGrantHoldsItsFact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	fx := newSharedFixture(t, ctx, "c")
	grantID := "cag_" + ids.NewID(domain.PrefixClusterAdminGrant)[3:]
	_, err := fx.pool.Exec(ctx, `
		INSERT INTO kaname.cluster_admin_grants (id, cluster_id, subject_type, subject_id, granted_by)
		VALUES ($1, $2, 'user', $3, 'probe-919')`, grantID, domain.ClusterSingletonID, string(fx.member))
	require.NoError(t, err, "ПРЕДПОСЫЛКА: назначение администратора кластера")
	k := abrepo.RelationTuple{User: "user:" + string(fx.member), Relation: "system_admin", Object: "cluster:" + domain.ClusterSingletonID}
	journal(t, ctx, fx.pool, fga_outbox.EmitWriteTx, asClient(k))
	require.True(t, factPresent(t, ctx, fx.pool, k), "ПРЕДПОСЫЛКА: запись назначения не легла фактом")

	journal(t, ctx, fx.pool, fga_outbox.EmitDeleteTx, asClient(k))
	assert.True(t, factPresent(t, ctx, fx.pool, k),
		"строка снятия сняла прямой факт %v, который держит действующее назначение администратора кластера", k)

	// Близнец: назначение снято тем же способом, что отзыв (срок — момент снятия).
	_, err = fx.pool.Exec(ctx, `UPDATE kaname.cluster_admin_grants SET granted_until = now() WHERE id = $1`, grantID)
	require.NoError(t, err)
	journal(t, ctx, fx.pool, fga_outbox.EmitDeleteTx, asClient(k))
	assert.False(t, factPresent(t, ctx, fx.pool, k),
		"БЛИЗНЕЦ: назначение снято, а строка снятия не сняла факт %v — свёртка не снимает вовсе", k)
}
