// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_vaults_integration_test.go — хранилища церемонии фундамента над
// записью 357 (`oauth_ceremony_vaults.go`, задача PRO-Robotech/kaname#423) там,
// где сквозные пробы LINE-A-1 (`cmd/kaname`) предмета не видят:
//
//   - уровень гранта — СНИМОК: шаг вверх в сессии после выдачи кода его не
//     меняет (у сессии уровень подвижен);
//   - единица запроса: погашение переживает откат выдачи, а одновременное
//     погашение того же кода СТОИТ на строке, пока опередивший не закрепит
//     выдачу, — отзыв отставшего не может лечь раньше записи выпуска;
//   - что невыразимо в схеме, отвергается, а не отвечается нулём: снятие живого
//     токена обновления, оборот вне единицы работы.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// vaultCodeRecord — запись кода так, как её кладёт движок: грант, привязка
// PKCE, срок кода от церемонии.
func vaultCodeRecord(sc domain.CeremonyContext, acr string, authAt time.Time) oauthceremony.AuthorizationCodeRecord {
	return oauthceremony.AuthorizationCodeRecord{
		Grant: oauthceremony.GrantRecord{
			GrantID:       sc.FamilyID,
			ClientID:      sc.ClientID,
			GrantedScopes: append([]string(nil), sc.Scope...),
			Form:          map[string][]string{"redirect_uri": {"https://app.example.test/cb"}},
			Session: oauthceremony.SessionRecord{
				Subject: sc.UserID, SessionID: sc.SessionID, ACR: acr, AuthTime: authAt,
				ExpiresAt: map[oauthceremony.TokenKind]time.Time{
					oauthceremony.TokenKindAuthorizationCode: time.Now().Add(time.Minute),
				},
			},
		},
		ProofKey: oauthceremony.ProofKeyBinding{Challenge: ceremonyChallenge, Method: oauthceremony.ProofKeyMethodS256},
	}
}

func storeVaultCode(t *testing.T, ctx context.Context, v *kanamepg.CeremonyVaults, sc domain.CeremonyContext, sig string) {
	t.Helper()
	out, err := v.StoreAuthorizationCode(ctx, sig, vaultCodeRecord(sc, "1", time.Now()))
	require.NoError(t, err, "посев кода")
	require.True(t, out.Declared())
	require.EqualValues(t, 1, out.Rows(), "посев кода затронул не одну строку")
}

// Уровень гранта — снимок на выдаче: шаг вверх в той же сессии после выдачи
// кода уровень кода не меняет. Близнец — момент аутентификации, который у
// сессии неподвижен и потому читается у неё.
func TestCeremonyVaults_CodeCarriesTheLevelOfItsIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	sc := ceremonyScene(t, ctx, pool, "vxa1")
	v := kanamepg.NewCeremonyVaults(pool)
	sig := ceremonyDigest(0x7a0001)
	storeVaultCode(t, ctx, v, sc, sig)

	_, err := pool.Exec(ctx, `
		UPDATE kaname.human_sessions SET assurance_level = '2', presented_methods = ARRAY['password','totp']
		 WHERE id = $1`, sc.SessionID)
	require.NoError(t, err, "шаг вверх в сессии")

	rec, err := v.FetchAuthorizationCode(ctx, sig)
	require.NoError(t, err)
	require.Equal(t, "1", rec.Grant.Session.ACR, "уровень кода взят у сессии, а не у снимка выдачи")
	require.Equal(t, sc.FamilyID, rec.Grant.GrantID)
	require.Equal(t, sc.UserID, rec.Grant.Session.Subject)
	require.Equal(t, sc.SessionID, rec.Grant.Session.SessionID)
	require.Equal(t, oauthceremony.ProofKeyMethodS256, rec.ProofKey.Method)

	var authAt, sessionExpiry time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT authenticated_at, expires_at FROM kaname.human_sessions WHERE id = $1`,
		sc.SessionID).Scan(&authAt, &sessionExpiry))
	require.True(t, rec.Grant.Session.AuthTime.Equal(authAt), "момент аутентификации не момент сессии")
	bound := rec.Grant.Session.NotAfter[oauthceremony.TokenKindRefresh]
	require.False(t, bound.IsZero(), "граница семейства не названа")
	require.False(t, bound.After(sessionExpiry), "граница семейства %s позже срока сессии %s", bound, sessionExpiry)
}

// Погашение переживает откат выдачи: единица работы откатывается к точке за
// погашением, урегулирование закрепляет погашение — код погашен (повтор узнаётся
// по записи), второе погашение — ноль строк. Близнец — непогашенный код жив.
func TestCeremonyVaults_ConsumptionSurvivesARefusedIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	sc := ceremonyScene(t, ctx, pool, "vxb1")
	v := kanamepg.NewCeremonyVaults(pool)
	sig := ceremonyDigest(0x7a0002)
	storeVaultCode(t, ctx, v, sc, sig)

	_, err := v.FetchAuthorizationCode(ctx, sig)
	require.NoError(t, err, "близнец: непогашенный код жив")

	reqCtx, settle := v.OpenRequest(ctx)
	out, err := v.ConsumeAuthorizationCode(reqCtx, sig)
	require.NoError(t, err)
	require.EqualValues(t, 1, out.Rows(), "погашение затронуло не одну строку")
	unitCtx, err := v.Begin(reqCtx)
	require.NoError(t, err)
	require.NoError(t, v.Rollback(unitCtx), "откат выдачи")
	require.NoError(t, settle(ctx), "урегулирование запроса")

	rec, err := v.FetchAuthorizationCode(ctx, sig)
	require.ErrorIs(t, err, oauthceremony.ErrAuthorizationCodeConsumed, "код после отказа выдачи не погашен")
	require.Equal(t, sc.FamilyID, rec.Grant.GrantID, "погашенный код отдан без гранта — отзывать нечего")
	n, err := kanamepg.NewOAuthCeremonyRepo(pool).ConsumeAuthorizationCode(ctx, sig)
	require.NoError(t, err)
	require.Zero(t, n, "код погашен дважды")
}

// awaitLockWaiterOrReturn — процесс, стоящий на замке оператором с фрагментом
// fragment, — либо возврат того, кто обязан был стоять (returned непуст).
// Ожидание доказывается состоянием движка, а не паузой; возврат до отпускания
// замка — исход предмета, а не «сцена не построена».
func awaitLockWaiterOrReturn(t *testing.T, ctx context.Context, observer *pgxpool.Pool, fragment string,
	returned func() bool,
) (pid int, returnedFirst bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := observer.QueryRow(ctx, `
			SELECT pid FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock' AND position($1 in query) > 0
			 ORDER BY pid LIMIT 1`, fragment).Scan(&pid)
		if err == nil {
			return pid, false
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			require.NoError(t, err, "наблюдатель замков")
		}
		if returned() {
			return 0, true
		}
		if time.Now().After(deadline) {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: никто не встал на замке оператором «%s» и никто не вернулся за 15 с", fragment)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Одновременное погашение того же кода СТОИТ на строке, пока опередивший не
// закрепит выдачу целиком — запись выпуска и первый токен обновления, — и лишь
// потом получает ноль строк. Отзыв отставшего поэтому не ложится раньше записи
// выпуска опередившего (замер до правки: из 8 одновременных обменов опередивший
// падал отказом порта).
func TestCeremonyVaults_ConcurrentConsumptionWaitsForTheWinnersIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	sc := ceremonyScene(t, ctx, pool, "vxc1")
	v := kanamepg.NewCeremonyVaults(pool)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	sig := ceremonyDigest(0x7a0003)
	storeVaultCode(t, ctx, v, sc, sig)

	reqCtx, settle := v.OpenRequest(ctx)
	out, err := v.ConsumeAuthorizationCode(reqCtx, sig)
	require.NoError(t, err)
	require.EqualValues(t, 1, out.Rows())

	type consumed struct {
		rows int64
		err  error
	}
	loser := make(chan consumed, 1)
	go func() {
		n, err := repo.ConsumeAuthorizationCode(ctx, sig)
		loser <- consumed{n, err}
	}()
	waiter, returnedFirst := awaitLockWaiterOrReturn(t, ctx, pool, "UPDATE kaname.authorization_codes",
		func() bool { return len(loser) > 0 })
	if returnedFirst {
		got := <-loser
		t.Fatalf("отставший вернулся (строк %d, отказ %v), не дождавшись выдачи опередившего: погашение "+
			"закреплено раньше выдачи, и отзыв отставшего может лечь раньше записи выпуска", got.rows, got.err)
	}

	// Выдача опередившего — в транзакции запроса: запись выпуска и пара.
	jti := "tok" + ceremonyPad("vxc1")
	issued := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, repo.RecordAccessToken(reqCtx, jti, sc.FamilyID, issued, issued.Add(10*time.Minute)))
	unitCtx, err := v.Begin(reqCtx)
	require.NoError(t, err)
	stored, err := v.StoreAccessToken(unitCtx, jti, oauthceremony.GrantRecord{GrantID: sc.FamilyID})
	require.NoError(t, err)
	require.EqualValues(t, 1, stored.Rows(), "запись выпуска не лежит в семействе гранта")
	grant := oauthceremony.GrantRecord{
		GrantID: sc.FamilyID, ClientID: sc.ClientID, GrantedScopes: sc.Scope,
		Session: oauthceremony.SessionRecord{Subject: sc.UserID, SessionID: sc.SessionID,
			ExpiresAt: map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindRefresh: time.Now().Add(time.Hour)}},
	}
	_, err = v.StoreRefreshToken(unitCtx, ceremonyDigest(0x7a0103), jti, grant)
	require.NoError(t, err, "первый токен обновления")

	var stillWaiting bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = $1`,
		waiter).Scan(&stillWaiting))
	require.True(t, stillWaiting, "отставший перестал ждать до закрепления выдачи опередившего")

	require.NoError(t, v.Commit(unitCtx), "закрепление выдачи")
	require.NoError(t, settle(ctx))

	select {
	case got := <-loser:
		require.NoError(t, got.err)
		require.Zero(t, got.rows, "отставший погасил уже погашенный код")
	case <-time.After(30 * time.Second):
		t.Fatal("отставший не завершился после закрепления выдачи опередившего")
	}
	var tokens int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.refresh_tokens WHERE family_id = $1`,
		sc.FamilyID).Scan(&tokens))
	require.Equal(t, 1, tokens, "выдача опередившего не закреплена")
}

// Невыразимое в схеме отвергается, а не отвечается нулём: снятие ЖИВОГО токена
// обновления (его снимает отзыв семейства) и оборот вне единицы работы. Близнец —
// снятие токена, которого нет, — законный ноль.
func TestCeremonyVaults_WhatTheSchemaCannotExpressIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	sc := ceremonyScene(t, ctx, pool, "vxd1")
	v := kanamepg.NewCeremonyVaults(pool)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	code := ceremonyDigest(0x7a0004)
	storeVaultCode(t, ctx, v, sc, code)
	live := ceremonyDigest(0x7a0104)
	_, err := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest: code, RefreshTokenDigest: live, RefreshTokenTTL: time.Hour,
	})
	require.NoError(t, err, "посев живого токена обновления")

	out, err := v.DropRefreshToken(ctx, ceremonyDigest(0x7a0999))
	require.NoError(t, err, "близнец: снятие несуществующего")
	require.Zero(t, out.Rows())

	_, err = v.DropRefreshToken(ctx, live)
	require.Error(t, err, "снятие живого токена ответило исходом, а не отказом")

	_, err = v.RotateRefreshToken(ctx, sc.FamilyID, live)
	require.Error(t, err, "оборот вне единицы работы исполнен")

	var active bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT active FROM kaname.refresh_tokens WHERE token_digest = $1`,
		live).Scan(&active))
	require.True(t, active, "отвергнутые вызовы тронули живой токен")
}
