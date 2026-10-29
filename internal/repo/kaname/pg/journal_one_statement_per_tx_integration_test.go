// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// journal_one_statement_per_tx_integration_test.go — транзакции, писавшие журнал
// прав несколькими операторами, кладут его ОДНИМ (kaname#617, перепись писателей
// журнала SD-942-617-1).
//
// ПРЕДМЕТ. Свёртка журнала в прямой факт берёт замки строк факта в общем порядке
// (объект, субъект, отношение) лишь внутри одного оператора; между операторами
// одной транзакции порядок — порядок вызовов писателя, и такая транзакция сходится
// в кольцо (40P01) с любым писателем, берущим те же факты в общем порядке.
//
// ЧЕМ СЧИТАЕТСЯ. Триггер счётчика в базе пробы (journalstmt) — число операторов
// вставки в журнал на транзакцию. Его собственная проба — первой: две вставки
// одной транзакцией дают два, одна — один. Без неё «один» у предмета был бы
// неотличим от счётчика, читающего «один» всегда.
//
// ПРЕДМЕТЫ ЗДЕСЬ — писатели слоя хранения со своей транзакцией: снятие ролей
// модуля применителем манифеста (по оператору на снятую роль) и посев модуля (по
// оператору на кортеж). Близнец каждого — тот же путь с ОДНИМ набором: один
// оператор на любой ревизии.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalstmt"
	"github.com/PRO-Robotech/kaname/internal/testsupport/rightsfixture"
)

// TestJournalStatementProbeCountsStatementsOfOneTransaction — собственная проба
// счётчика: две вставки одной транзакцией — два оператора, одна — один.
func TestJournalStatementProbeCountsStatementsOfOneTransaction(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, "j617p")
	probe := journalstmt.Install(t, ctx, pool)

	viewer := clients.RelationTuple{User: "user:" + string(fx.member), Relation: "viewer", Object: "project:" + string(fx.prj)}
	editor := clients.RelationTuple{User: "user:" + string(fx.member), Relation: "editor", Object: "project:" + string(fx.prjOth)}
	for _, tc := range []struct {
		name  string
		calls [][]clients.RelationTuple
		want  int
	}{
		{"два вызова", [][]clients.RelationTuple{{viewer}, {editor}}, 2},
		{"один вызов", [][]clients.RelationTuple{{viewer, editor}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe.Reset(t, ctx)
			tx, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(context.Background()) }()
			for _, call := range tc.calls {
				require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, call))
			}
			require.NoError(t, tx.Commit(ctx))
			c := probe.Count(t, ctx)
			assert.Equal(t, 1, c.Transactions, "одна транзакция писала журнал")
			assert.Equal(t, tc.want, c.MaxPerTx, "счётчик видит число операторов транзакции")
		})
	}
}

// retireWorld — роли модуля, выдачи участнику на снимаемые роли с
// материализованным ярусом на объекте проекта, счётчик операторов журнала.
type retireWorld struct {
	ctx     context.Context
	applier *moduleroles.Applier
	probe   *journalstmt.Probe
	keep    string
}

func newRetireWorld(t *testing.T, suffix string, gone ...string) *retireWorld {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	rec, _ := newReconciler(pool)
	w := &retireWorld{
		ctx:     ctx,
		applier: moduleroles.NewApplier(moduleroles.NewRepoTxRunner(fx.repo), rightsfixture.Export()),
		keep:    "compute.j617keep" + suffix + ".admin",
	}
	declared := append([]string{w.keep}, gone...)
	rep, err := w.applier.Apply(ctx, withdrawalManifest(t, "compute", declared...), moduleroles.BootActorID)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: объявленные роли модуля легли: %s", rep)
	seedMirrorRow(t, ctx, pool, "compute.instance", "i617"+suffix, string(fx.prj), string(fx.accID), nil, time.Now())
	subj := "user:" + string(fx.member)
	for _, name := range gone {
		bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, domain.SystemRoleID(domain.RoleName(name)),
			"project", string(fx.prj), domain.ScopeProject)
		require.NoError(t, rec.ReconcileBinding(ctx, bid), "ПРЕДПОСЫЛКА: выдача снимаемой роли %s материализована", name)
		require.Positive(t, memberLedgerRows(t, ctx, pool, bid), "ПРЕДПОСЫЛКА: реестр учёл выпущенное членами выдачи роли %s", name)
	}
	require.NotEmpty(t, subjectFactRelations(t, ctx, pool, subj, "compute_instance", "i617"+suffix),
		"ПРЕДПОСЫЛКА: выдачи снимаемых ролей дали прямой факт на объекте")
	w.probe = journalstmt.Install(t, ctx, pool)
	return w
}

// retireAllButKeep снимает применителем все роли модуля, кроме оставляемой.
func (w *retireWorld) retireAllButKeep(t *testing.T) journalstmt.Census {
	t.Helper()
	w.probe.Reset(t, w.ctx)
	rep, err := w.applier.Apply(w.ctx, withdrawalManifest(t, "compute", w.keep), moduleroles.BootActorID)
	require.NoError(t, err, "снятие ролей применителем: %s", rep)
	c := w.probe.Count(t, w.ctx)
	t.Logf("перепись журнала: транзакций %d, операторов %d, наибольшее на транзакцию %d", c.Transactions, c.Statements, c.MaxPerTx)
	require.Positive(t, c.Statements, "ПРЕДПОСЫЛКА: снятие ролей писало журнал")
	return c
}

func TestModuleRoleRetirementOfTwoRolesLaysItsJournalInOneStatement(t *testing.T) {
	skipShort(t)
	w := newRetireWorld(t, "r2", "compute.j617gone1r2.admin", "compute.j617gone2r2.admin")
	c := w.retireAllButKeep(t)
	assert.Equal(t, 1, c.MaxPerTx, "снятие двух ролей одним применением кладёт снятия доступа их членов одним оператором журнала")
}

func TestModuleRoleRetirementOfOneRoleLaysOneStatement(t *testing.T) {
	skipShort(t)
	w := newRetireWorld(t, "r1", "compute.j617gone1r1.admin")
	c := w.retireAllButKeep(t)
	assert.Equal(t, 1, c.MaxPerTx, "близнец: одна снятая роль — один оператор на любой ревизии")
}

// seedGrantOnlyManifest — манифест пробы посева без раздела вступлений: одна
// выдача, один кортеж журнала (близнец посева с выдачей и вступлением). Выводится
// из seedProbeManifest, а не пишется вторым литералом: имена посевной личности
// живут одним местом (перепись `seed-identity-names-its-own-service`).
func seedGrantOnlyManifest(t *testing.T) string {
	t.Helper()
	doc, joins, ok := strings.Cut(seedProbeManifest, "  joins:")
	require.True(t, ok && joins != "", "предпосылка: манифест пробы посева несёт раздел вступлений")
	return doc
}

func applySeedCounted(t *testing.T, doc string) journalstmt.Census {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	probe := journalstmt.Install(t, ctx, pool)
	m, err := manifest.Load([]byte(doc))
	require.NoError(t, err, "проба подаёт манифест, который разбор не принимает — вердикт беспредметен")
	probe.Reset(t, ctx)
	_, err = moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool)).ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	c := probe.Count(t, ctx)
	t.Logf("перепись журнала: транзакций %d, операторов %d, наибольшее на транзакцию %d", c.Transactions, c.Statements, c.MaxPerTx)
	require.Positive(t, c.Statements, "ПРЕДПОСЫЛКА: посев писал журнал")
	return c
}

func TestModuleSeedWithGrantAndJoinLaysItsJournalInOneStatement(t *testing.T) {
	skipShort(t)
	c := applySeedCounted(t, seedProbeManifest)
	assert.Equal(t, 1, c.MaxPerTx, "посев модуля кладёт выдачу и вступление одним оператором журнала")
}

func TestModuleSeedWithOneGrantLaysOneStatement(t *testing.T) {
	skipShort(t)
	c := applySeedCounted(t, seedGrantOnlyManifest(t))
	assert.Equal(t, 1, c.MaxPerTx, "близнец: один кортеж посева — один оператор на любой ревизии")
}
