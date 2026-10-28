// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_expiry_from_ledger_integration_test.go — снятие по сроку и выпадение члена
// снимают ВЕСЬ учтённый реестром набор, а не то, что видно в снимке каталога процесса
// (kaname#933).
//
// ПРЕДМЕТ. Кортежи члена снимались по ключу `<тип модели>:<id>`, а тип модели берётся
// из снимка каталога процесса. Если у типа члена в снимке нет живой строки (реплика с
// устаревшим снимком, тип снят), кортежи не снимались, а сам член удалялся — прямой
// факт оставался и давал доступ через ветвь прямых фактов вердикта, не смотрящую на
// живость выдачи.
//
// Две реплики на ОДНОЙ базе: A знает тип, B — нет. Выдачу материализует A, снимает B.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — те же шаги на A: зелёный и до, и после починки.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const ledgerProbeType = "compute.instance"

// catalogWithout — снимок каталога без строки типа. retired=true кладёт строку в СНЯТУЮ
// половину (тип снят применением манифеста), false — просто нет в снимке (реплика,
// не видящая тип).
func catalogWithout(t *testing.T, dotted string, retired bool) catalog.Source {
	t.Helper()
	live := seed.LiteralRows()
	var kept []catalog.ResourceRow
	var gone []catalog.ResourceRow
	for _, r := range live.Resources {
		if r.Module+"."+r.Resource == dotted {
			gone = append(gone, r)
			continue
		}
		kept = append(kept, r)
	}
	require.Len(t, gone, 1, "ПРЕДПОСЫЛКА: тип %s есть в каталоге литерала ровно один раз", dotted)
	var verbs []catalog.VerbRow
	for _, v := range live.Verbs {
		if v.Module+"."+v.Resource != dotted {
			verbs = append(verbs, v)
		}
	}
	h := catalog.Halves{Live: catalog.Rows{Modules: live.Modules, Resources: kept, Verbs: verbs}}
	if retired {
		h.Retired = catalog.Rows{Modules: live.Modules, Resources: gone}
	}
	f, err := catalog.NewFacts(h)
	require.NoError(t, err)
	return catalog.Fixed{F: f}
}

type ledgerProbe struct {
	pool *pgxpool.Pool
	bid  domain.AccessBindingID
	subj string
	a    *reconcile.Reconciler
	b    *reconcile.Reconciler
}

// newLedgerProbe — выдача материализована репликой A: член ACTIVE, реестр и факт есть.
func newLedgerProbe(t *testing.T, suffix string, retired bool) *ledgerProbe {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	a, adapter := newReconciler(pool)
	b := reconcile.New(adapter, nil, catalogWithout(t, ledgerProbeType, retired))
	bid, subj := seedRaceBinding(t, ctx, pool, fx, suffix, projectRoleFixture)
	// Цепь предков объекта — тем же входом, каким её пишет продукт: без указателя на
	// проект вердикт области объекта не видит, и прямой факт отказывает ещё до снятия.
	require.NoError(t, newRegisterUCWired(pool).Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + string(fx.prj), Relation: "parent", Object: "compute_instance:iRace",
		ParentProjectId: string(fx.prj), ParentAccountId: string(fx.accID),
		SourceVersion: timestamppb.New(time.Now().Add(time.Minute)),
	}))

	require.NoError(t, a.ReconcileBinding(ctx, bid))
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	require.Positive(t, members, "БЛИЗНЕЦ: реплика A материализовала члена")
	require.Positive(t, ledger, "БЛИЗНЕЦ: запись реестра есть")
	require.Positive(t, facts, "БЛИЗНЕЦ: прямой факт есть после свёртки")
	assert.Equal(t, relverdict.Allow, ledgerVerdict(t, ctx, pool, subj),
		"БЛИЗНЕЦ: до снятия вердикт — разрешение; факты: %v", factsOf(t, ctx, pool, subj))
	return &ledgerProbe{pool: pool, bid: bid, subj: subj, a: a, b: b}
}

func factsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subj string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT object_type||':'||object_id||'#'||relation||'@'||subject||' cond='||coalesce(condition_name,'')
	  FROM kaname.relation_fact WHERE subject = $1`, subj)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	return out
}

func ledgerVerdict(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subj string) relverdict.Verdict {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: subj, ObjectType: "compute_instance", ObjectID: "iRace", Relation: "editor",
	})
	require.NoError(t, err)
	return v
}

func (p *ledgerProbe) expireInPast(t *testing.T) {
	t.Helper()
	_, err := p.pool.Exec(context.Background(),
		`UPDATE kaname.access_bindings
		    SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'
		  WHERE id = $1`, string(p.bid))
	require.NoError(t, err, "ПРЕДПОСЫЛКА: срок выдачи сдвинут в прошлое")
}

func (p *ledgerProbe) assertNothingLeft(t *testing.T, why string) {
	t.Helper()
	ctx := context.Background()
	members, ledger, facts := bindingResidue(t, ctx, p.pool, p.bid, p.subj, "compute_instance", "iRace")
	assert.Zero(t, members, "%s: остались члены", why)
	assert.Zero(t, ledger, "%s: остались записи реестра", why)
	assert.Zero(t, facts, "%s: остался прямой факт — доступ без выдачи", why)
	assert.Equal(t, relverdict.Deny, ledgerVerdict(t, ctx, p.pool, p.subj), "%s: вердикт обязан быть отказом", why)
}

func TestExpireFromLedger_TwinSameReplicaExpiry(t *testing.T) {
	p := newLedgerProbe(t, "e933tw", false)
	p.expireInPast(t)
	require.NoError(t, p.a.ExpireBinding(context.Background(), p.bid))
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, context.Background(), p.pool, p.bid))
	p.assertNothingLeft(t, "истечение на реплике, знающей тип")
}

func TestExpireFromLedger_ReplicaWithoutTheTypeRevokesTheWholeLedger(t *testing.T) {
	p := newLedgerProbe(t, "e933st", false)
	p.expireInPast(t)
	require.NoError(t, p.b.ExpireBinding(context.Background(), p.bid))
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, context.Background(), p.pool, p.bid))
	p.assertNothingLeft(t, "истечение на реплике без типа в снимке")
}

func TestExpireFromLedger_RetiredTypeRevokesTheWholeLedger(t *testing.T) {
	p := newLedgerProbe(t, "e933rt", true)
	p.expireInPast(t)
	require.NoError(t, p.b.ExpireBinding(context.Background(), p.bid))
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, context.Background(), p.pool, p.bid))
	p.assertNothingLeft(t, "истечение после снятия типа из каталога")
}

// Выпадение члена из желаемого на реплике без типа в снимке: объект ушёл из зеркала,
// член выпал по-настоящему — и его кортежи снимаются по реестру, хотя ключа
// `<тип модели>:<id>` реплике собрать нечем. Тип при этом жив в строках каталога:
// одно отставание снимка члена не снимает (kaname#937,
// reconcile_catalog_lag_integration_test.go), снимает выпадение.
func TestFellOutMemberFromLedger_ReplicaWithoutTheType(t *testing.T) {
	p := newLedgerProbe(t, "e933fo", false)
	removeLedgerProbeObject(t, p.pool)
	require.NoError(t, p.b.ReconcileBinding(context.Background(), p.bid))
	p.assertNothingLeft(t, "член выпал из желаемого на реплике без типа")
}

// removeLedgerProbeObject — объект пробы ушёл из зеркала: член выдачи выпадает из
// желаемого по-настоящему, а не потому, что реплика не знает его типа.
func removeLedgerProbeObject(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`DELETE FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = 'iRace'`, ledgerProbeType)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: объект пробы снят с зеркала")
}
