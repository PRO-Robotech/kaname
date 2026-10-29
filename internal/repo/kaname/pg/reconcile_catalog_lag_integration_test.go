// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_catalog_lag_integration_test.go — сверка отличает «тип ещё не дошёл до
// снимка каталога реплики» от «тип снят» (kaname#937).
//
// ПРЕДМЕТ. Тип члена выдачи сверка переводит в тип модели по снимку каталога своего
// процесса. Снимок обновляется периодом (до 60 с), поэтому после применения манифеста,
// заведшего тип, реплика с ещё не обновлённым снимком этого типа не знает. До починки
// она считала члена такого типа ВЫПАВШИМ и снимала его кортежи по реестру выдачи:
// доступ, только что выданный соседней репликой, исчезал на окно до обновления снимка
// (отказ закрытый, но доступ теряется). Снятый тип — другое дело: там кортежи
// снимаются, и это верно.
//
// ОБСТАНОВКА — две реплики над ОДНОЙ базой, как в проде:
//
//	B — снимок прочитан ДО применения манифеста и не обновлялся (реплика, отставшая на период);
//	A — тот же снимок, обновлённый после применения (реплика, уже увидевшая тип).
//
// Тип заводит и снимает НАСТОЯЩИЙ применитель каталога (переселение проекций,
// вырезание селекторов, снятие строк), а не правка строк вручную: близнец «тип снят»
// обязан стоять на том же состоянии базы, какое оставляет продукт.
//
// ПАРЫ (кейс — законный близнец, отличие — ровно один факт):
//
//	тип ЖИВ в строках каталога, B его не знает → кортежи члена ОСТАЮТСЯ
//	тип СНЯТ применением манифеста, B его не знает → кортежи члена СНИМАЮТСЯ
//	тип ЖИВ, B его не знает, но объект УШЁЛ из зеркала → кортежи СНИМАЮТСЯ
//	  (удержание не глушит настоящее выпадение)
//
// Каждая пара — для полного прохода выдачи и для прохода по объекту.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// lagKeepRes — второй ресурс синтетического модуля. Он живёт на всём протяжении пробы:
// манифест близнеца «тип снят» объявляет только его, и применитель снимает ровно
// verdictAppliedRes, а модуль остаётся живым.
const lagKeepRes = "omega"

// lagObjectID — объект типа verdictAppliedDotted под проектом выдачи.
const lagObjectID = "a937"

type catalogLagProbe struct {
	pool   *pgxpool.Pool
	bid    domain.AccessBindingID
	subj   string
	behind *reconcile.Reconciler
	ledger int
}

// lagRule — правило якоря по синтетическому типу: всякий объект типа под областью.
func lagRule() domain.Rule {
	return domain.Rule{Module: applierProbeModule, Resources: []string{verdictAppliedRes}, Verbs: []string{"get", "update"}}
}

// newCatalogLagProbe — тип заведён применением манифеста, реплика A его видит и
// материализовала члена; реплика B — на снимке до применения.
func newCatalogLagProbe(t *testing.T, suffix string) *catalogLagProbe {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)

	catRepo := kanamepg.NewCatalogRepo(pool)
	before, err := catRepo.ReadCatalogHalves(ctx)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: каталог читается до применения")
	snapBehind, err := catalog.NewSnapshot(before, catRepo, nil, nil)
	require.NoError(t, err)
	snapAhead, err := catalog.NewSnapshot(before, catRepo, nil, nil)
	require.NoError(t, err)

	rep, err := applierOver(t, pool).Apply(ctx, probeManifest(verdictAppliedResource(), probeResource(lagKeepRes, "get")))
	require.NoError(t, err, "ПРЕДПОСЫЛКА: манифест с новым типом применён")
	require.True(t, rep.Changed(), "ПРЕДПОСЫЛКА: применение завело строки (%s)", rep)
	require.NoError(t, snapAhead.Refresh(ctx), "ПРЕДПОСЫЛКА: реплика A обновила снимок")
	_, aheadKnows := snapAhead.Facts().FGAObjectType(verdictAppliedDotted)
	require.True(t, aheadKnows, "ПРЕДПОСЫЛКА: реплика A знает %s", verdictAppliedDotted)
	_, behindKnows := snapBehind.Facts().FGAObjectType(verdictAppliedDotted)
	require.False(t, behindKnows, "ПРЕДПОСЫЛКА: реплика B ещё не знает %s", verdictAppliedDotted)
	require.True(t, catalogTypeLive(t, ctx, pool, verdictAppliedDotted), "ПРЕДПОСЫЛКА: строка каталога %s жива", verdictAppliedDotted)

	ahead := reconcile.New(kanamepg.NewReconcileAdapter(pool, snapAhead), nil, snapAhead)
	behind := reconcile.New(kanamepg.NewReconcileAdapter(pool, snapBehind), nil, snapBehind)

	roleID := seedRulesRoleWith(t, ctx, fx.repo, fx.prj, suffix+"role", domain.Rules{lagRule()}, snapAhead.Facts())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, verdictAppliedDotted, lagObjectID, string(fx.prj), string(fx.accID), nil, time.Now())
	require.NoError(t, ahead.ReconcileBinding(ctx, bid))

	p := &catalogLagProbe{pool: pool, bid: bid, subj: "user:" + string(fx.member), behind: behind}
	st, ok := memberStatusOn(t, ctx, pool, bid, verdictAppliedDotted, lagObjectID)
	require.True(t, ok, "ПРЕДПОСЫЛКА: реплика A материализовала члена")
	require.Equal(t, string(domain.VerificationActive), st)
	p.ledger = ledgerRowsOn(t, ctx, pool, bid, verdictAppliedModel+":"+lagObjectID)
	require.Positive(t, p.ledger, "ПРЕДПОСЫЛКА: реестр члена есть")
	require.Positive(t, factsOn(t, ctx, pool, p.subj, verdictAppliedModel, lagObjectID), "ПРЕДПОСЫЛКА: прямой факт есть")
	return p
}

func catalogTypeLive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, dotted string) bool {
	t.Helper()
	var live bool
	err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM kaname.catalog_resource WHERE dotted = $1 AND live)`, dotted).Scan(&live)
	require.NoError(t, err)
	return live
}

// retireType — тип снимает применитель: манифест модуля больше его не объявляет.
func (p *catalogLagProbe) retireType(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rep, err := applierOver(t, p.pool).Apply(ctx, probeManifest(probeResource(lagKeepRes, "get")))
	require.NoError(t, err, "ПРЕДПОСЫЛКА: манифест без типа применён")
	require.Positive(t, rep.RetiredResources, "ПРЕДПОСЫЛКА: применитель снял ресурс (%s)", rep)
	require.False(t, catalogTypeLive(t, ctx, p.pool, verdictAppliedDotted), "ПРЕДПОСЫЛКА: строка каталога %s снята", verdictAppliedDotted)
}

// objectLeft — объект ушёл из зеркала: член выпадает по-настоящему.
func (p *catalogLagProbe) objectLeft(t *testing.T) {
	t.Helper()
	_, err := p.pool.Exec(context.Background(),
		`DELETE FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`, verdictAppliedDotted, lagObjectID)
	require.NoError(t, err)
}

func (p *catalogLagProbe) assertKept(t *testing.T, why string) {
	t.Helper()
	ctx := context.Background()
	st, ok := memberStatusOn(t, ctx, p.pool, p.bid, verdictAppliedDotted, lagObjectID)
	assert.True(t, ok, "%s: член снят — тип, не дошедший до снимка реплики, сочтён снятым", why)
	assert.Equal(t, string(domain.VerificationActive), st, "%s: статус члена", why)
	assert.Equal(t, p.ledger, ledgerRowsOn(t, ctx, p.pool, p.bid, verdictAppliedModel+":"+lagObjectID),
		"%s: реестр члена изменился", why)
	assert.Positive(t, factsOn(t, ctx, p.pool, p.subj, verdictAppliedModel, lagObjectID),
		"%s: прямой факт снят — доступ потерян на окно до обновления снимка", why)
}

func (p *catalogLagProbe) assertGone(t *testing.T, why string) {
	t.Helper()
	ctx := context.Background()
	members, ledger, facts := bindingResidue(t, ctx, p.pool, p.bid, p.subj, verdictAppliedModel, lagObjectID)
	assert.Zero(t, members, "%s: остались члены", why)
	assert.Zero(t, ledger, "%s: остались записи реестра", why)
	assert.Zero(t, facts, "%s: остался прямой факт — доступ без члена", why)
}

func TestCatalogLag_FullPassOnReplicaBehindKeepsTheMember(t *testing.T) {
	p := newCatalogLagProbe(t, "e937fk")
	require.NoError(t, p.behind.ReconcileBinding(context.Background(), p.bid))
	p.assertKept(t, "полный проход реплики, не знающей живого типа")
}

func TestCatalogLag_ObjectPassOnReplicaBehindKeepsTheMember(t *testing.T) {
	p := newCatalogLagProbe(t, "e937ok")
	require.NoError(t, p.behind.ReconcileObject(context.Background(), verdictAppliedDotted, lagObjectID))
	p.assertKept(t, "проход по объекту реплики, не знающей живого типа")
}

func TestCatalogLag_TwinRetiredType_FullPassRevokes(t *testing.T) {
	p := newCatalogLagProbe(t, "e937fr")
	p.retireType(t)
	require.NoError(t, p.behind.ReconcileBinding(context.Background(), p.bid))
	p.assertGone(t, "полный проход после снятия типа")
}

func TestCatalogLag_TwinRetiredType_ObjectPassRevokes(t *testing.T) {
	p := newCatalogLagProbe(t, "e937or")
	p.retireType(t)
	require.NoError(t, p.behind.ReconcileObject(context.Background(), verdictAppliedDotted, lagObjectID))
	p.assertGone(t, "проход по объекту после снятия типа")
}

func TestCatalogLag_TwinObjectLeft_FullPassRevokesOnReplicaBehind(t *testing.T) {
	p := newCatalogLagProbe(t, "e937fl")
	p.objectLeft(t)
	require.NoError(t, p.behind.ReconcileBinding(context.Background(), p.bid))
	p.assertGone(t, "полный проход реплики без типа, объект ушёл из зеркала")
}

func TestCatalogLag_TwinObjectLeft_ObjectPassRevokesOnReplicaBehind(t *testing.T) {
	p := newCatalogLagProbe(t, "e937ol")
	p.objectLeft(t)
	require.NoError(t, p.behind.ReconcileObject(context.Background(), verdictAppliedDotted, lagObjectID))
	p.assertGone(t, "проход по объекту реплики без типа, объект ушёл из зеркала")
}

// Поставляемый тип: строка каталога в базе жива, снимок реплики B собран без неё
// (catalogWithout, retired=false). Тот же предмет на типе, который заводит посев, а не
// применитель: проход реплики, не видящей тип, членов этого типа не снимает.
func TestCatalogLag_ShippedTypeOnReplicaBehindKeepsTheMember(t *testing.T) {
	p := newLedgerProbe(t, "e937sk", false)
	ctx := context.Background()
	before := ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace")
	require.NoError(t, p.b.ReconcileBinding(ctx, p.bid))
	st, ok := memberStatusOn(t, ctx, p.pool, p.bid, ledgerProbeType, "iRace")
	assert.True(t, ok, "член поставляемого типа снят репликой, не видящей тип в снимке")
	assert.Equal(t, string(domain.VerificationActive), st)
	assert.Equal(t, before, ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"), "реестр члена изменился")
	assert.Positive(t, factsOn(t, ctx, p.pool, p.subj, "compute_instance", "iRace"), "прямой факт снят")
	assert.Equal(t, relverdict.Allow, ledgerVerdict(t, ctx, p.pool, p.subj), "вердикт обязан остаться разрешением")
}
