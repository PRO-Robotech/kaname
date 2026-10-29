// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_lock_order_census_integration_test.go — пробы-близнецы переписи порядка
// захвата строк КАТАЛОГА (kaname#922) для пар без инверсии: применитель каталога
// против создания роли арендатора, правки роли арендатора и замка типов цели при
// создании выдачи (`LockLiveTargetTypes`). Двадцать ходов подряд, ноль взаимных
// блокировок. Инверсии переписи (I1–I3) и их снятие — catalog_projection_lock_order_integration_test.go,
// пара «применитель каталога × применитель ролей модуля» по своему модулю —
// catalog_applier_module_role_lock_order_integration_test.go (kaname#913).
//
// # Ход — задан ожиданием
//
// Держатель берёт ПОЗДНИЙ ресурс (`zzz`) ключевым замком. Применитель каталога
// встаёт на нём, уже держа строку модуля и ранний ресурс (`aaa`) `FOR UPDATE`.
// Сторона запускается и встаёт за применителем (на замках ровно двое — иначе
// стороны не встретились). Держатель откатывается. Сторона, берущая `zzz` раньше
// `aaa`, получила бы `zzz` (ключевой замок совместим с держателем) и встала бы на
// `aaa` — пара замкнулась бы в цикл. Сторона с порядком базы стоит на `aaa` и
// ничего из нужного применителю не держит.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// catalogTwinEnv — модуль пробы с ресурсами `aaa`, `zzz`, снимок каталога после
// применения и арендатор.
type catalogTwinEnv struct {
	pool    *pgxpool.Pool
	repo    *kanamepg.Repository
	install func() error
	snap    *catalog.Snapshot
	tenant  verdictTenant
	ops     operations.Repo
}

func newCatalogTwinEnv(t *testing.T) *catalogTwinEnv {
	t.Helper()
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	m := probeManifest(probeResource(crossEarlyName, "get"), probeResource(crossLateName, "get"))
	_, err := applier.Apply(ctx, m)
	require.NoError(t, err, "Дано: модуль %s с живыми ресурсами %s и %s", applierProbeModule, crossEarlyName, crossLateName)
	catRepo := kanamepg.NewCatalogRepo(pool)
	halves, err := catRepo.ReadCatalogHalves(ctx)
	require.NoError(t, err)
	snap, err := catalog.NewSnapshot(halves, catRepo, nil, nil)
	require.NoError(t, err)
	return &catalogTwinEnv{
		pool: pool, repo: kanamepg.New(pool, nil),
		install: func() error { _, aerr := applier.Apply(ctx, m); return aerr },
		snap:    snap, tenant: seedVerdictTenant(t, ctx, pool), ops: operations.NewRepo(pool, "kaname"),
	}
}

// twinRules — правило по обоим ресурсам, названным ПОЗДНИЙ первым.
func twinRules(verbs ...string) domain.Rules {
	return domain.Rules{{Module: applierProbeModule, Resources: []string{crossLateName, crossEarlyName}, Verbs: verbs}}
}

// raceCatalogTwin — двадцать ходов «применитель каталога против стороны».
func raceCatalogTwin(t *testing.T, env *catalogTwinEnv, name string, prepare func(i int) func(context.Context) error) {
	t.Helper()
	ctx := context.Background()
	before := deadlocksOf(t, ctx, env.pool)
	for i := 0; i < grantCensusRepeats; i++ {
		side := prepare(i)
		holder, err := env.pool.Begin(ctx)
		require.NoError(t, err)
		var held int
		require.NoError(t, holder.QueryRow(ctx, `SELECT count(*) FROM (
			SELECT 1 FROM kaname.catalog_resource WHERE dotted = $1 AND live FOR KEY SHARE) s`, crossLockLate).Scan(&held))
		require.Equalf(t, 1, held, "ПРЕДПОСЫЛКА хода %d: держатель взял %s", i, crossLockLate)

		ares := make(chan error, 1)
		go func() { ares <- env.install() }()
		metApplier := lockWaiters(ctx, env.pool, 1, grantCensusBudget)
		sres := make(chan error, 1)
		go func() { sres <- side(ctx) }()
		metSide := lockWaiters(ctx, env.pool, 2, grantCensusBudget)
		require.NoError(t, holder.Rollback(ctx))
		aerr, serr := awaitBoth(t, ares, sres, i)
		require.Truef(t, metApplier, "ход %d: применитель не встал за держателем (%v)", i, aerr)
		require.Truef(t, metSide, "ход %d: %s не встал за применителем — не встретились (%v)", i, name, serr)
		require.Falsef(t, isDeadlockOrAborted(aerr) || isDeadlockOrAborted(serr),
			"ход %d: взаимная блокировка: применитель=%v · %s=%v", i, aerr, name, serr)
		require.NoErrorf(t, aerr, "ход %d: применитель не дошёл до конца", i)
		require.NoErrorf(t, serr, "ход %d: %s не дошёл до конца", i, name)
	}
	flushStats(env.pool)
	delta := deadlocksOf(t, ctx, env.pool) - before
	t.Logf("применитель × %s: ходов %d · взаимных блокировок по счётчику базы %d", name, grantCensusRepeats, delta)
	require.Zerof(t, delta, "применитель × %s: база отметила взаимных блокировок %d", name, delta)
}

func TestCatalogLockOrderCensus_ApplierAgainstTenantRoleCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	env := newCatalogTwinEnv(t)
	uc := roleapp.NewCreateRoleUseCase(env.repo, env.ops, env.snap)
	raceCatalogTwin(t, env, "создание роли арендатора", func(i int) func(context.Context) error {
		return func(ctx context.Context) error {
			op, err := uc.Execute(declarerCtx(ctx, env.tenant.userID), domain.Role{
				AccountID: domain.AccountID(env.tenant.accountID), Name: domain.RoleName(fmt.Sprintf("p922c%02d", i)),
				Description: "проба kaname#922", Rules: twinRules("get"),
			})
			return awaitOpDone(ctx, env.ops, op, err)
		}
	})
}

func TestCatalogLockOrderCensus_ApplierAgainstTenantRoleUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	env := newCatalogTwinEnv(t)
	create := roleapp.NewCreateRoleUseCase(env.repo, env.ops, env.snap)
	update := roleapp.NewUpdateRoleUseCase(env.repo, env.ops, env.snap)
	raceCatalogTwin(t, env, "правка роли арендатора", func(i int) func(context.Context) error {
		ctx := context.Background()
		op, err := create.Execute(declarerCtx(ctx, env.tenant.userID), domain.Role{
			AccountID: domain.AccountID(env.tenant.accountID), Name: domain.RoleName(fmt.Sprintf("p922u%02d", i)),
			Description: "проба kaname#922",
			Rules:       domain.Rules{{Module: applierProbeModule, Resources: []string{crossLateName}, Verbs: []string{"get"}}},
		})
		require.NoErrorf(t, awaitOpDone(ctx, env.ops, op, err), "ПРЕДПОСЫЛКА хода %d: роль заведена", i)
		got, gerr := env.ops.Get(ctx, op.ID)
		require.NoError(t, gerr)
		roleID := roleIDOf(t, got)
		return func(ctx context.Context) error {
			uop, uerr := update.Execute(declarerCtx(ctx, env.tenant.userID), roleapp.UpdateRoleInput{
				ID: roleID, Rules: twinRules("get"), UpdateMask: []string{"rules"},
			})
			return awaitOpDone(ctx, env.ops, uop, uerr)
		}
	})
}

func TestCatalogLockOrderCensus_ApplierAgainstBindingTargetTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	env := newCatalogTwinEnv(t)
	raceCatalogTwin(t, env, "замок типов цели выдачи", func(int) func(context.Context) error {
		return func(ctx context.Context) error {
			return inWriteTx(ctx, env.repo, func(w kanamerepo.Writer) error {
				_, err := w.AccessBindingsW().LockLiveTargetTypes(ctx, []string{crossLockLate, crossLockEarly})
				return err
			})
		}
	})
}

// roleIDOf — id роли из метаданных операции создания: назначает его use-case.
func roleIDOf(t *testing.T, op *operations.Operation) domain.RoleID {
	t.Helper()
	var meta iamv1.CreateRoleMetadata
	require.NoError(t, op.Metadata.UnmarshalTo(&meta), "метаданные операции создания роли")
	require.NotEmpty(t, meta.GetRoleId(), "операция создания роли не назвала id роли")
	return domain.RoleID(meta.GetRoleId())
}
