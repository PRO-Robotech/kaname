// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func parentScopeReaderPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return ctx, pool
}

func TestRegistrationScopeReaderUsesCurrentOwningRowOnCallerTx(t *testing.T) {
	ctx, pool := parentScopeReaderPool(t)
	scene := registrationscene.Seed(t, ctx, pool)
	other := registrationscene.Seed(t, ctx, pool)
	const id = "parent-scope-same-tx"
	require.NoError(t, newRegisterUCWired(pool).Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "vpc_network:" + id, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}))
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	// Изменяется owning row в ещё не зафиксированной TX. Зеркало хранит старый
	// account; читатель обязан увидеть actual owner этой TX без nested pool read.
	_, err = tx.Exec(ctx, `UPDATE kaname.projects SET account_id=$2 WHERE id=$1`, scene.Project, other.Account)
	require.NoError(t, err)
	reader := kanamepg.NewRegistrationScopeReader()
	account, exists, err := reader.ProjectAccountTx(ctx, tx, scene.Project)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, other.Account, account)
	scope, err := reader.ContainerScopeTx(ctx, tx, "vpc_network", id)
	require.NoError(t, err)
	require.Equal(t, domain.ContainerScope{Registered: true, ProjectID: scene.Project, AccountID: other.Account}, scope)
	require.NoError(t, tx.Rollback(ctx))
	check, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = check.Rollback(c)
	}()
	scope, err = reader.ContainerScopeTx(ctx, check, "vpc_network", id)
	require.NoError(t, err)
	require.Equal(t, scene.Account, scope.AccountID)
}

func TestRegistrationScopeReaderBoundedCompletePointerPage(t *testing.T) {
	ctx, pool := parentScopeReaderPool(t)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	reader := kanamepg.NewRegistrationScopeReader()
	emitter := kanamepg.NewFGAOutboxEmitter()
	// Здесь предмет — reader page над настоящей проекцией журнала; это не
	// registration admission. Canonical объекты создаёт отдельная API проба.
	for i := 1; i <= 4; i++ {
		require.NoError(t, emitter.EmitWriteTx(ctx, tx, []service.RelationTuple{{User: fmt.Sprintf("project:p%d", i), Relation: "project", Object: "vpc_network:page"}}))
	}
	subjects, err := reader.BoundedPointerSubjectsTx(ctx, tx, "vpc_network", "page", []string{"project"})
	require.NoError(t, err)
	require.Equal(t, []string{"project:p1", "project:p2", "project:p3", "project:p4"}, subjects)
	none, err := reader.BoundedPointerSubjectsTx(ctx, tx, "vpc_network", "page", []string{"parent"})
	require.NoError(t, err)
	require.Empty(t, none)
	require.NoError(t, emitter.EmitWriteTx(ctx, tx, []service.RelationTuple{{User: "project:p5", Relation: "project", Object: "vpc_network:page"}}))
	subjects, err = reader.BoundedPointerSubjectsTx(ctx, tx, "vpc_network", "page", []string{"project"})
	require.ErrorIs(t, err, domain.ErrParentHierarchyInvalid)
	require.Nil(t, subjects, "sentinel не возвращает успешный усечённый список")
	legacy, err := reader.PointerSubjectsTx(ctx, tx, "vpc_network", "page", []string{"project"})
	require.NoError(t, err, "audit/cleanup reader сохраняет полный исторический набор")
	require.Equal(t, []string{"project:p1", "project:p2", "project:p3", "project:p4", "project:p5"}, legacy)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	subjects, err = reader.BoundedPointerSubjectsTx(cancelled, tx, "vpc_network", "page", []string{"project"})
	require.Error(t, err)
	require.Nil(t, subjects)
}
