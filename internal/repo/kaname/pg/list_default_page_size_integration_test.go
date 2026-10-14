// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// list_default_page_size_integration_test.go — page_size=0 означает умолчание
// ПЛАТФОРМЫ (50) у каждого списка службы, а не своё число хранилища (kaname#604).
//
// Три списка (SAKeyService.List, UserTokenService.List,
// InternalSessionRevocationsService.ListByUser) назначали умолчание сами — 100,
// тогда как общий валидатор и остальные списки службы — 50.
//
// # НА КАКОЙ НЕВЕРНОЙ РЕАЛИЗАЦИИ ЭТИ ПРОБЫ БЫЛИ БЫ ЗЕЛЕНЫ — И ЧЕМ ЭТО ЗАКРЫТО
//
//   - «страница из 50» зелена, если строк в хранилище ровно 50 ⇒ строк кладётся
//     больше (seededRows), и близнец с явным page_size больше 50 обязан вернуть
//     больше 50 — иначе число 50 было бы свойством данных, а не умолчания;
//   - «страница из 50» зелена на хранилище, обрезающем страницу без признака
//     продолжения ⇒ проба требует непустой токен следующей страницы.
//
// Потолок удостоверений (посадка: человек 12, машина 24) меньше умолчания
// страницы, поэтому пробы двух списков удостоверений поднимают его тем же
// оператором, каким величину пишет пуск процесса (setCredLimit): умолчание
// страницы — свойство чтения, и оно обязано быть одним при любой посадке.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const (
	// platformDefaultPageSize — corevalidate.PageSize: 0 → 50.
	platformDefaultPageSize = 50
	// seededRows — больше умолчания платформы И больше explicitPageSize, чтобы
	// и умолчание, и близнец резали страницу, а не исчерпывали данные.
	seededRows = 61
	// explicitPageSize — близнец: явный размер больше умолчания.
	explicitPageSize = 60
)

func TestListDefaultPageSize_SAKeyList_ZeroMeansPlatformDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	// Потолок удостоверений машины (посадка, 24) меньше умолчания страницы:
	// без его подъёма список не дорастает до 51 строки и разницы 50/100 не видно.
	setCredLimit(t, ctx, pool, kindSACredential, seededRows)
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, "pg604sa")
	sid := seedSvcAccount(t, ctx, pool, accID, "pg604sa")
	repo := kanamepg.NewSAOAuthClientRepo(pool)
	for i := 0; i < seededRows; i++ {
		tx := mustBeginTx(t, ctx, pool)
		_, err := repo.Insert(ctx, tx, domain.ServiceAccountOAuthClient{
			CredentialKind:  domain.CredentialKindKeypair,
			ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
			SvaID:           domain.ServiceAccountID(sid),
			CreatedByUserID: domain.UserID(uid),
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}

	page, next, err := repo.List(ctx, domain.ServiceAccountID(sid), "", 0)
	require.NoError(t, err)
	require.Equal(t, platformDefaultPageSize, len(page), "page_size=0 обязан дать умолчание платформы")
	require.NotEmpty(t, next, "обрезанная страница обязана нести токен продолжения")

	twin, _, err := repo.List(ctx, domain.ServiceAccountID(sid), "", explicitPageSize)
	require.NoError(t, err)
	require.Equal(t, explicitPageSize, len(twin), "близнец: явный размер исполняется как есть")
}

func TestListDefaultPageSize_UserTokenList_ZeroMeansPlatformDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	// Потолок удостоверений человека (посадка, 12) меньше умолчания страницы.
	setCredLimit(t, ctx, pool, kindUserCredential, seededRows)
	uid := mustSeedUser(t, ctx, pool, "pg604ut")
	repo := kanamepg.NewUserOAuthClientRepo(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)
	for i := 0; i < seededRows; i++ {
		insertCredential(t, ctx, txb, repo, newUOC(uid, fmt.Sprintf("pg604-%d", i)))
	}

	page, next, err := repo.List(ctx, uid, "", 0)
	require.NoError(t, err)
	require.Equal(t, platformDefaultPageSize, len(page), "page_size=0 обязан дать умолчание платформы")
	require.NotEmpty(t, next, "обрезанная страница обязана нести токен продолжения")

	twin, _, err := repo.List(ctx, uid, "", explicitPageSize)
	require.NoError(t, err)
	require.Equal(t, explicitPageSize, len(twin), "близнец: явный размер исполняется как есть")
}

func TestListDefaultPageSize_SessionRevocationsListByUser_ZeroMeansPlatformDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid := mustSeedUser(t, ctx, pool, "pg604sr")
	repo := kanamepg.NewSessionRevocationRepo(pool)
	seedRevocations(t, ctx, repo, uid)

	page, next, err := repo.ListByUser(ctx, string(uid), 0, "")
	require.NoError(t, err)
	require.Equal(t, platformDefaultPageSize, len(page), "page_size=0 обязан дать умолчание платформы")
	require.NotEmpty(t, next, "обрезанная страница обязана нести токен продолжения")

	twin, _, err := repo.ListByUser(ctx, string(uid), explicitPageSize, "")
	require.NoError(t, err)
	require.Equal(t, explicitPageSize, len(twin), "близнец: явный размер исполняется как есть")
}

func seedRevocations(t *testing.T, ctx context.Context, repo *kanamepg.SessionRevocationRepo, uid domain.UserID) {
	t.Helper()
	for i := 0; i < seededRows; i++ {
		_, err := repo.RevokeWithAdmin(ctx, domain.SessionRevocation{
			TokenJTI:     fmt.Sprintf("pg604-%s-%03d", uid, i),
			Reason:       "force_logout",
			UserID:       uid,
			TTLExpiresAt: time.Now().Add(time.Hour),
		}, "")
		require.NoError(t, err)
	}
}
