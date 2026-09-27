// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_subject_cutoff_integration_test.go — выдача церемонии сверяется
// с отсечкой субъекта (`user_token_revocations.revoke_before`) на каждом из трёх
// своих ходов: выдаче кода, выборке кода к обмену и выборке токена обновления к
// обороту (задача PRO-Robotech/kaname#423, возврат ревью безопасности сборки 425).
//
// Правило то же, что у края на браузерной полосе: сессия, аутентифицированная НЕ
// ПОЗЖЕ отсечки, недействительна. Предъявление судит токены по отметке выпуска,
// и выпуск ПОСЛЕ отсечки из сессии, аутентифицированной ДО неё, предъявление
// пропустило бы, — поэтому отсечку обязана прочесть сама выдача.
//
// Отсечку кладёт продуктовый писатель (`UserTokenRevocationRepo.UpsertRevokeAll`),
// сессия и семейство при этом живы: так пишут её писатели, не снимающие сессий.
// У каждой клетки близнец в одно значение — отсечка РАНЬШЕ аутентификации сессии.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// sessionAuthenticatedAt — момент аутентификации сессии сцены.
func sessionAuthenticatedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext) time.Time {
	t.Helper()
	var at time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT authenticated_at FROM kaname.human_sessions WHERE id = $1`,
		sc.SessionID).Scan(&at))
	return at
}

// writeCutoff — отсечка субъекта сцены продуктовым писателем.
func writeCutoff(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext, at time.Time) {
	t.Helper()
	require.NoError(t, kanamepg.NewUserTokenRevocationRepo(pool).UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(sc.UserID), RevokeBefore: at, Reason: domain.RevokeReasonSecondFactorReset,
	}, ""), "отсечка субъекта")
}

// cutoffCells — отсечка после аутентификации сессии (предмет) и её близнец —
// отсечка раньше аутентификации.
var cutoffCells = []struct {
	name     string
	shift    time.Duration
	refusing bool
}{
	{"отсечка после аутентификации сессии", time.Second, true},
	{"близнец: отсечка раньше аутентификации сессии", -time.Second, false},
}

func TestCeremonyVaults_CodeIssuanceReadsTheSubjectCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for i, cell := range cutoffCells {
		t.Run(cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vcf1")
			v := kanamepg.NewCeremonyVaults(pool)
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			_, err := v.StoreAuthorizationCode(ctx, ceremonyDigest(0x7f0001+i),
				vaultCodeRecord(sc, "1", time.Now()))
			if cell.refusing {
				require.ErrorIs(t, err, domain.ErrCeremonySessionNotLive,
					"код выдан в сессии, аутентифицированной до отсечки субъекта: %v", err)
				var families int
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.token_families WHERE session_id = $1`,
					sc.SessionID).Scan(&families))
				require.Zero(t, families, "отказ выдачи оставил семейство")
				return
			}
			require.NoError(t, err, "близнец: выдача при отсечке раньше аутентификации")
		})
	}
}

func TestCeremonyVaults_CodeExchangeReadsTheSubjectCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for i, cell := range cutoffCells {
		t.Run(cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vcf2")
			v := kanamepg.NewCeremonyVaults(pool)
			sig := ceremonyDigest(0x7f0101 + i)
			storeVaultCode(t, ctx, v, sc, sig)
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			_, err := v.FetchAuthorizationCode(ctx, sig)
			if cell.refusing {
				require.ErrorIs(t, err, oauthceremony.ErrGrantNotFound,
					"код сессии, аутентифицированной до отсечки субъекта, выбран к обмену живым: %v", err)
				return
			}
			require.NoError(t, err, "близнец: код жив при отсечке раньше аутентификации")
		})
	}
}

func TestCeremonyVaults_RefreshRotationReadsTheSubjectCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for i, cell := range cutoffCells {
		t.Run(cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vcf3")
			v := kanamepg.NewCeremonyVaults(pool)
			code := ceremonyDigest(0x7f0201 + i)
			storeVaultCode(t, ctx, v, sc, code)
			rt := ceremonyDigest(0x7f0301 + i)
			_, err := kanamepg.NewOAuthCeremonyRepo(pool).ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
				CodeDigest: code, RefreshTokenDigest: rt, RefreshTokenTTL: time.Hour,
			})
			require.NoError(t, err, "посев живого токена обновления")
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			_, err = v.FetchRefreshToken(ctx, rt)
			if cell.refusing {
				require.ErrorIs(t, err, oauthceremony.ErrGrantNotFound,
					"токен обновления сессии, аутентифицированной до отсечки субъекта, выбран к обороту живым: %v", err)
				return
			}
			require.NoError(t, err, "близнец: токен обновления жив при отсечке раньше аутентификации")
		})
	}
}
