// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_decisive_write_cutoff_integration_test.go — отсечку субъекта
// судят РЕШАЮЩИЕ условные записи обмена и оборота, а не только чтения перед
// ними (задача PRO-Robotech/kaname#423, возврат ревью схемы сборки 425, N1).
//
// Движок читает код (токен обновления) до записи, и отсечка, зафиксированная
// МЕЖДУ чтением и записью, прежде чтением не виделась, а записью не судилась:
// погашение и оборот проходили, и выпуск после отсечки из сессии,
// аутентифицированной до неё, предъявление пропустило бы. Поэтому у каждой
// клетки чередование одно: чтение (живо) → отсечка зафиксирована продуктовым
// писателем → решающая запись.
//
// Отказ по отсечке — «записи нет» (ErrGrantNotFound у порта,
// ErrCeremonySubjectCutOff у записи слоя доступа), а не повтор: повтор
// отзывает семейство, и журнал назвал бы атакой отзыв доступа. И не
// «условие и разбор разошлись»: разбор нуля строк знает эту причину.
//
// У каждой клетки близнец в одно значение — отсечка РАНЬШЕ аутентификации
// сессии: та же запись проходит.

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

// requireCodeNotConsumedNorFamilyRevoked — отказ по отсечке ничего не записал:
// код не погашен, семейство не отозвано (повтор отозвал бы его).
func requireCodeNotConsumedNorFamilyRevoked(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sig string) {
	t.Helper()
	var consumed, revoked bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT c.deactivated_at IS NOT NULL, f.revoked_at IS NOT NULL
		  FROM kaname.authorization_codes c JOIN kaname.token_families f ON f.id = c.family_id
		 WHERE c.code_digest = $1`, sig).Scan(&consumed, &revoked))
	require.False(t, consumed, "отказ по отсечке погасил код")
	require.False(t, revoked, "отказ по отсечке отозвал семейство — разобран как повтор")
}

// requireRefreshNotRotatedNorFamilyRevoked — то же для токена обновления.
func requireRefreshNotRotatedNorFamilyRevoked(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rt string) {
	t.Helper()
	var rotated, revoked bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT t.deactivated_at IS NOT NULL, f.revoked_at IS NOT NULL
		  FROM kaname.refresh_tokens t JOIN kaname.token_families f ON f.id = t.family_id
		 WHERE t.token_digest = $1`, rt).Scan(&rotated, &revoked))
	require.False(t, rotated, "отказ по отсечке обернул токен обновления")
	require.False(t, revoked, "отказ по отсечке отозвал семейство — разобран как повтор")
}

// seedLiveRefresh — живой токен обновления первого поколения сцены.
func seedLiveRefresh(t *testing.T, ctx context.Context, pool *pgxpool.Pool, v *kanamepg.CeremonyVaults,
	sc domain.CeremonyContext, code, rt string) {
	t.Helper()
	storeVaultCode(t, ctx, v, sc, code)
	_, err := kanamepg.NewOAuthCeremonyRepo(pool).ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest: code, RefreshTokenDigest: rt, RefreshTokenTTL: time.Hour,
	})
	require.NoError(t, err, "посев живого токена обновления")
}

func TestCeremonyVaults_CodeConsumptionJudgesACutoffCommittedAfterTheRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	lanes := []struct {
		name      string
		inRequest bool
	}{
		{"в единице запроса обмена", true},
		{"своей транзакцией слоя доступа", false},
	}
	for li, lane := range lanes {
		for i, cell := range cutoffCells {
			t.Run(lane.name+"/"+cell.name, func(t *testing.T) {
				ctx, pool := catalogPool(t)
				sc := ceremonyScene(t, ctx, pool, "vdw1")
				v := kanamepg.NewCeremonyVaults(pool)
				sig := ceremonyDigest(0x7f0401 + 0x10*li + i)
				storeVaultCode(t, ctx, v, sc, sig)

				_, err := v.FetchAuthorizationCode(ctx, sig)
				require.NoError(t, err, "предпосылка: код жив при чтении")
				writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

				consumeCtx, settle := ctx, func(context.Context) error { return nil }
				if lane.inRequest {
					consumeCtx, settle = v.OpenRequest(ctx)
				}
				out, err := v.ConsumeAuthorizationCode(consumeCtx, sig)
				require.NoError(t, settle(ctx), "урегулирование запроса")
				if cell.refusing {
					require.ErrorIsf(t, err, oauthceremony.ErrGrantNotFound,
						"погашение после зафиксированной отсечки прошло либо отказало не отсутствием записи: "+
							"строк %d, отказ %v", out.Rows(), err)
					requireCodeNotConsumedNorFamilyRevoked(t, ctx, pool, sig)
					return
				}
				require.NoError(t, err, "близнец: погашение при отсечке раньше аутентификации")
				require.EqualValues(t, 1, out.Rows(), "близнец: погашение не затронуло строку кода")
			})
		}
	}
}

func TestCeremonyVaults_RotationLockJudgesACutoffCommittedAfterTheRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for i, cell := range cutoffCells {
		t.Run(cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vdw2")
			v := kanamepg.NewCeremonyVaults(pool)
			rt := ceremonyDigest(0x7f0501 + i)
			seedLiveRefresh(t, ctx, pool, v, sc, ceremonyDigest(0x7f0511+i), rt)

			g, err := v.FetchRefreshToken(ctx, rt)
			require.NoError(t, err, "предпосылка: токен обновления жив при чтении")
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			uctx, err := v.Begin(ctx)
			require.NoError(t, err)
			out, err := v.RotateRefreshToken(uctx, g.GrantID, rt)
			require.NoError(t, v.Rollback(uctx), "откат единицы работы")
			if cell.refusing {
				require.ErrorIsf(t, err, oauthceremony.ErrGrantNotFound,
					"замок оборота после зафиксированной отсечки взят либо отказал не отсутствием записи: "+
						"строк %d, отказ %v", out.Rows(), err)
				requireRefreshNotRotatedNorFamilyRevoked(t, ctx, pool, rt)
				return
			}
			require.NoError(t, err, "близнец: замок оборота при отсечке раньше аутентификации")
			require.EqualValues(t, 1, out.Rows(), "близнец: замок оборота не взял строку")
		})
	}
}

func TestCeremonyVaults_RotationWriteJudgesACutoffCommittedAfterTheLock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for i, cell := range cutoffCells {
		t.Run(cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vdw3")
			v := kanamepg.NewCeremonyVaults(pool)
			rt := ceremonyDigest(0x7f0601 + i)
			seedLiveRefresh(t, ctx, pool, v, sc, ceremonyDigest(0x7f0611+i), rt)

			g, err := v.FetchRefreshToken(ctx, rt)
			require.NoError(t, err, "предпосылка: токен обновления жив при чтении")
			uctx, err := v.Begin(ctx)
			require.NoError(t, err)
			locked, err := v.RotateRefreshToken(uctx, g.GrantID, rt)
			require.NoError(t, err, "предпосылка: замок оборота взят до отсечки")
			require.EqualValues(t, 1, locked.Rows(), "предпосылка: замок оборота взял строку")

			// Писатель отсечки строки токена не трогает и замка оборота не ждёт.
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			grant := oauthceremony.GrantRecord{
				GrantID: g.GrantID, ClientID: sc.ClientID, GrantedScopes: sc.Scope,
				Session: oauthceremony.SessionRecord{Subject: sc.UserID, SessionID: sc.SessionID,
					ExpiresAt: map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindRefresh: time.Now().Add(time.Hour)}},
			}
			out, err := v.StoreRefreshToken(uctx, ceremonyDigest(0x7f0621+i), "", grant)
			require.NoError(t, v.Rollback(uctx), "откат единицы работы")
			if cell.refusing {
				require.ErrorIsf(t, err, oauthceremony.ErrGrantNotFound,
					"оборот после зафиксированной отсечки записан либо отказал не отсутствием записи: "+
						"строк %d, отказ %v", out.Rows(), err)
				requireRefreshNotRotatedNorFamilyRevoked(t, ctx, pool, rt)
				return
			}
			require.NoError(t, err, "близнец: оборот при отсечке раньше аутентификации")
			require.EqualValues(t, 1, out.Rows(), "близнец: оборот не записан")
		})
	}
}

// Обмен и оборот слоя доступа исполняют ТЕ ЖЕ операторы, и их разбор нуля
// строк обязан знать отсечку: без неё ноль строк у живой строки в сроке
// разбирался бы как «условие и разбор разошлись».
func TestOAuthCeremonyRepo_ExchangeAndRotationNameTheSubjectCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for i, cell := range cutoffCells {
		t.Run("обмен кода/"+cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vdw4")
			v := kanamepg.NewCeremonyVaults(pool)
			sig := ceremonyDigest(0x7f0701 + i)
			storeVaultCode(t, ctx, v, sc, sig)
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			_, err := kanamepg.NewOAuthCeremonyRepo(pool).ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
				CodeDigest: sig, RefreshTokenDigest: ceremonyDigest(0x7f0711 + i), RefreshTokenTTL: time.Hour,
			})
			if cell.refusing {
				require.ErrorIsf(t, err, domain.ErrCeremonySubjectCutOff,
					"обмен кода сессии, аутентифицированной до отсечки, прошёл либо отказал не отсечкой: %v", err)
				requireCodeNotConsumedNorFamilyRevoked(t, ctx, pool, sig)
				return
			}
			require.NoError(t, err, "близнец: обмен при отсечке раньше аутентификации")
		})
		t.Run("оборот токена обновления/"+cell.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			sc := ceremonyScene(t, ctx, pool, "vdw5")
			v := kanamepg.NewCeremonyVaults(pool)
			rt := ceremonyDigest(0x7f0801 + i)
			seedLiveRefresh(t, ctx, pool, v, sc, ceremonyDigest(0x7f0811+i), rt)
			writeCutoff(t, ctx, pool, sc, sessionAuthenticatedAt(t, ctx, pool, sc).Add(cell.shift))

			_, err := kanamepg.NewOAuthCeremonyRepo(pool).RotateRefreshToken(ctx, kanamepg.RefreshRotation{
				PresentedDigest: rt, SuccessorDigest: ceremonyDigest(0x7f0821 + i), TTL: time.Hour,
			})
			if cell.refusing {
				require.ErrorIsf(t, err, domain.ErrCeremonySubjectCutOff,
					"оборот токена сессии, аутентифицированной до отсечки, прошёл либо отказал не отсечкой: %v", err)
				requireRefreshNotRotatedNorFamilyRevoked(t, ctx, pool, rt)
				return
			}
			require.NoError(t, err, "близнец: оборот при отсечке раньше аутентификации")
		})
	}
}
