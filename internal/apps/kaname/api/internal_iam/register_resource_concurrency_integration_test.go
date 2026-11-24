// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_concurrency_integration_test.go — SEC-C A-06 (запрет #10).
//
// Два одновременных вызова RegisterResource с одинаковым кортежем должны ОБА
// успеть (без утечки INTERNAL и паники). Кортеж владельца доставляется хотя бы раз через
// транзакционный outbox и выгрузчик: каждый вызов ставит свою строку outbox, а
// выгрузчик сворачивает дубли через FGA already_exists→ErrAlreadyApplied
// (fga_applier.go), получая ровно один действующий кортеж FGA. Проверяемый инвариант
// безопасности гонки: «одновременная постановка никогда не ошибается и не применяется дважды».
//
// Пропускается при `go test -short`.
package internal_iam_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

func TestRegisterResource_A06_ConcurrentRegisterIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	uc := internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalogfixture.Source()),
		kanamepg.NewRegistrationAudit(),
		kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"})

	// Проект, известный kaname: родителя регистрации kaname выводит сам
	// (kaname#982), и под выдуманным проектом регистрация отвергается.
	scene := registrationscene.Seed(t, ctx, pool)
	req := &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + scene.Project, Relation: "project", Object: "vpc_network:enp00000000000000002",
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = uc.Register(ctx, req)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent register #%d must succeed (idempotent, no INTERNAL leak)", i)
	}

	// Все N поставлены (хотя бы раз); выгрузчик идемпотентно сворачивает их.
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox
		  WHERE payload->>'object' = 'vpc_network:enp00000000000000002'`).Scan(&count))
	require.Equal(t, n, count, "each concurrent call enqueues its own outbox row")
}
