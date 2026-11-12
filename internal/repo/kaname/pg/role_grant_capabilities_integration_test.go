// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Используется настоящая PG-фикстура пакета с миграциями, без подмены схемы.
func grantProjectionFixture(t *testing.T) (context.Context, *pgxpool.Pool, *kanamepg.Repository, domain.AccountID, domain.UserID) {
	t.Helper()
	if testing.Short() {
		t.Skip("needs Postgres")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)
	user := mustSeedUser(t, ctx, pool, "grant-projection")
	account := seedAccount(t, ctx, repo, "acc-grant-projection", user)
	return ctx, pool, repo, account.ID, user
}

func grantCreate(fp string) domain.GrantCapabilityRule {
	return domain.GrantCapabilityRule{RuleFP: strings.Repeat(fp, 64), Kind: domain.GrantCapabilityCreateBinding}
}
func grantBind(fp string, target domain.RoleID) domain.GrantCapabilityRule {
	return domain.GrantCapabilityRule{RuleFP: strings.Repeat(fp, 64), Kind: domain.GrantCapabilityBindRole, BoundRoleID: target}
}
func writeGrantProjection(t *testing.T, ctx context.Context, repo kanamerepo.Repository, owner domain.RoleID, specs []domain.GrantCapabilityRule) error {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	if err := w.RolesW().ReplaceGrantCapabilities(ctx, owner, specs); err != nil {
		return err
	}
	return w.Commit(ctx)
}
func grantProjectionRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner domain.RoleID) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT 'create:' || rule_fp FROM kaname.role_create_binding_rule WHERE role_id=$1
        UNION ALL SELECT 'bind:' || rule_fp || ':' || bound_role_id FROM kaname.role_bind_role_rule WHERE role_id=$1`, string(owner))
	require.NoError(t, err)
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var value string
		require.NoError(t, rows.Scan(&value))
		result = append(result, value)
	}
	require.NoError(t, rows.Err())
	return result
}
func expectedGrantRows(specs ...domain.GrantCapabilityRule) []string {
	out := []string{}
	for _, spec := range specs {
		if spec.Kind == domain.GrantCapabilityCreateBinding {
			out = append(out, "create:"+spec.RuleFP)
		} else {
			out = append(out, "bind:"+spec.RuleFP+":"+string(spec.BoundRoleID))
		}
	}
	return out
}

func TestGrantProjection_MixedReplaceClearAndUnion(t *testing.T) {
	ctx, pool, repo, account, _ := grantProjectionFixture(t)
	owner := seedAccountRole(t, ctx, pool, account, "grant_owner")
	target := seedAccountRole(t, ctx, pool, account, "grant_target")
	create, bind := grantCreate("a"), grantBind("b", target)
	require.NoError(t, writeGrantProjection(t, ctx, repo, owner, []domain.GrantCapabilityRule{create, bind, create, bind}))
	require.ElementsMatch(t, expectedGrantRows(create, bind), grantProjectionRows(t, ctx, pool, owner))
	// Владелец и целевая роль различаются: ошибочная запись владельца вместо
	// цели должна провалить проверку, хотя оба FK такую строку допускают.
	require.Empty(t, grantProjectionRows(t, ctx, pool, target))
	replacement := grantBind("c", target)
	require.NoError(t, writeGrantProjection(t, ctx, repo, owner, []domain.GrantCapabilityRule{replacement}))
	require.ElementsMatch(t, expectedGrantRows(replacement), grantProjectionRows(t, ctx, pool, owner))
	require.NoError(t, writeGrantProjection(t, ctx, repo, owner, nil))
	require.Empty(t, grantProjectionRows(t, ctx, pool, owner))
}

func TestGrantProjection_OwnerAndNamedTargetHaveIndependentLifecycles(t *testing.T) {
	ctx, pool, repo, account, _ := grantProjectionFixture(t)
	ownerA := seedAccountRole(t, ctx, pool, account, "grant_a")
	ownerB := seedAccountRole(t, ctx, pool, account, "grant_b")
	target := seedAccountRole(t, ctx, pool, account, "grant_target")
	other := seedAccountRole(t, ctx, pool, account, "grant_other")
	create, bind := grantCreate("a"), grantBind("b", target)
	unaffected := grantBind("c", other)
	require.NoError(t, writeGrantProjection(t, ctx, repo, ownerA, []domain.GrantCapabilityRule{create, bind}))
	require.NoError(t, writeGrantProjection(t, ctx, repo, ownerB, []domain.GrantCapabilityRule{create, bind, unaffected}))
	_, err := pool.Exec(ctx, `DELETE FROM kaname.roles WHERE id=$1`, string(ownerA))
	require.NoError(t, err)
	require.Empty(t, grantProjectionRows(t, ctx, pool, ownerA))
	require.ElementsMatch(t, expectedGrantRows(create, bind, unaffected), grantProjectionRows(t, ctx, pool, ownerB))
	_, err = pool.Exec(ctx, `DELETE FROM kaname.roles WHERE id=$1`, string(target))
	require.NoError(t, err)
	require.ElementsMatch(t, expectedGrantRows(create, unaffected), grantProjectionRows(t, ctx, pool, ownerB))
	var kept int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.roles WHERE id=ANY($1::text[])`, []string{string(ownerB), string(other)}).Scan(&kept))
	require.Equal(t, 2, kept)
}

func TestGrantProjection_MissingReferenceIsOpaqueAndRollbackKeepsBothProjections(t *testing.T) {
	ctx, pool, repo, account, _ := grantProjectionFixture(t)
	owner := seedAccountRole(t, ctx, pool, account, "grant_owner")
	target := seedAccountRole(t, ctx, pool, account, "grant_target")
	create, bind := grantCreate("a"), grantBind("b", target)
	require.NoError(t, writeGrantProjection(t, ctx, repo, owner, []domain.GrantCapabilityRule{create, bind}))
	missing := domain.RoleID(ids.NewID(domain.PrefixRole))
	err := writeGrantProjection(t, ctx, repo, owner, []domain.GrantCapabilityRule{grantCreate("c"), grantBind("d", missing)})
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.ErrorIs(t, err, iamerr.ErrReferenceMissing)
	require.NotContains(t, err.Error(), string(missing))
	require.NotContains(t, err.Error(), string(owner))
	require.NotContains(t, err.Error(), "role_bind_role_rule")
	var pgErr *pgconn.PgError
	require.False(t, errors.As(err, &pgErr))
	require.ElementsMatch(t, expectedGrantRows(create, bind), grantProjectionRows(t, ctx, pool, owner))
	// Явный откат успешной смешанной замены тоже должен удалить новые строки
	// и восстановить обе прежние проекции.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	require.NoError(t, w.RolesW().ReplaceGrantCapabilities(ctx, owner, []domain.GrantCapabilityRule{grantCreate("e"), grantBind("f", target)}))
	require.NoError(t, w.Rollback(ctx))
	require.ElementsMatch(t, expectedGrantRows(create, bind), grantProjectionRows(t, ctx, pool, owner))
}

func TestGrantProjection_ClosedShapeRejectsWithoutReplacingExistingRows(t *testing.T) {
	ctx, pool, repo, account, _ := grantProjectionFixture(t)
	owner := seedAccountRole(t, ctx, pool, account, "grant_owner")
	valid := grantCreate("a")
	require.NoError(t, writeGrantProjection(t, ctx, repo, owner, []domain.GrantCapabilityRule{valid}))
	invalid := []domain.GrantCapabilityRule{
		{},
		{RuleFP: valid.RuleFP, Kind: "future_kind"},
		{RuleFP: strings.Repeat("A", 64), Kind: domain.GrantCapabilityCreateBinding},
		{RuleFP: "a", Kind: domain.GrantCapabilityCreateBinding},
		{RuleFP: valid.RuleFP, Kind: domain.GrantCapabilityCreateBinding, BoundRoleID: owner},
		{RuleFP: valid.RuleFP, Kind: domain.GrantCapabilityBindRole},
		{RuleFP: valid.RuleFP, Kind: domain.GrantCapabilityBindRole, BoundRoleID: "*"},
	}
	for _, spec := range invalid {
		require.ErrorIs(t, writeGrantProjection(t, ctx, repo, owner, []domain.GrantCapabilityRule{valid, spec}), iamerr.ErrInvalidArg)
		require.ElementsMatch(t, expectedGrantRows(valid), grantProjectionRows(t, ctx, pool, owner))
	}
}

func TestGrantProjection_CarriersDefaultToVersionZeroAndRejectUnknownVersions(t *testing.T) {
	ctx, pool, repo, account, user := grantProjectionFixture(t)
	role := seedAccountRole(t, ctx, pool, account, "grant_owner")
	require.NoError(t, insertBinding(ctx, pool, role, user, "account", string(account)))
	var id string
	var version int16
	require.NoError(t, pool.QueryRow(ctx, `SELECT id, grant_capability_version FROM kaname.access_bindings WHERE role_id=$1`, string(role)).Scan(&id, &version))
	require.EqualValues(t, 0, version)
	for _, invalid := range []int{-1, 2} {
		_, err := pool.Exec(ctx, `UPDATE kaname.access_bindings SET grant_capability_version=$2 WHERE id=$1`, id, invalid)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code)
	}
	// Привязка из SQL-фикстуры сохраняет версию 0 после записи проекции.
	// Это проверка умолчания схемы, а не вызов продуктового writer.
	require.NoError(t, writeGrantProjection(t, ctx, repo, role, []domain.GrantCapabilityRule{grantCreate("a")}))
	require.NoError(t, pool.QueryRow(ctx, `SELECT grant_capability_version FROM kaname.access_bindings WHERE id=$1`, id).Scan(&version))
	require.EqualValues(t, 0, version)
}

// Откат снимает только новую проекцию; исходная роль и прежняя привязка живут.
// Повторное применение не включает управляющие права у сохранившейся привязки.
func TestGrantProjection_MigrationRoundTripKeepsLegacyCarrierInactive(t *testing.T) {
	ctx, pool, repo, account, user := grantProjectionFixture(t)
	role := seedAccountRole(t, ctx, pool, account, "grant_owner")
	require.NoError(t, insertBinding(ctx, pool, role, user, "account", string(account)))
	require.NoError(t, writeGrantProjection(t, ctx, repo, role, []domain.GrantCapabilityRule{grantCreate("a")}))
	db, err := sql.Open("pgx", pool.Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	// При первом старте kaname ещё не существует: журнал Goose создаётся в public.
	// После создания схемы неразмеченное имя у Provider создало бы пустой журнал
	// в kaname и ошибочно объявило установленную базу версией 0.
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithTableName("public.goose_db_version"))
	require.NoError(t, err)
	const version int64 = 20261112123000
	current, err := provider.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, version, current, "тест обязан снимать именно новую миграцию")
	down, err := provider.Down(ctx)
	require.NoError(t, err)
	require.Equal(t, version, down.Source.Version)
	var removed bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT
	    to_regclass('kaname.role_create_binding_rule') IS NULL AND
	    to_regclass('kaname.role_bind_role_rule') IS NULL AND
	    NOT EXISTS (SELECT 1 FROM information_schema.columns
	        WHERE table_schema='kaname' AND table_name='access_bindings'
	        AND column_name='grant_capability_version')`).Scan(&removed))
	require.True(t, removed)
	var kept int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_bindings
	    WHERE role_id=$1`, string(role)).Scan(&kept))
	require.Equal(t, 1, kept)
	up, err := provider.Up(ctx)
	require.NoError(t, err)
	require.Len(t, up, 1)
	require.Equal(t, version, up[0].Source.Version)
	var carrierVersion int16
	require.NoError(t, pool.QueryRow(ctx, `SELECT grant_capability_version
	    FROM kaname.access_bindings WHERE role_id=$1`, string(role)).Scan(&carrierVersion))
	require.EqualValues(t, 0, carrierVersion)
	require.Empty(t, grantProjectionRows(t, ctx, pool, role))
}
