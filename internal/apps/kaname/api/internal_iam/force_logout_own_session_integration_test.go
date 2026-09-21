// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_own_session_integration_test.go — ПРИНУДИТЕЛЬНЫЙ ВЫХОД СНИМАЕТ
// НАШУ СЕССИЮ ВХОДА (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ, И ПОЧЕМУ ОТСЕЧКИ НЕ ХВАТАЕТ
//
// `ForceLogout` пишет ОТСЕЧКУ субъекта (`user_token_revocations.revoke_before`)
// и снимает сессию входа у ВНЕШНЕГО поставщика. На посадке `own` поставщика нет,
// а сессия входа — НАША строка (`human_sessions`), и её не трогает ничто.
//
// Отсечка эту строку не покрывает, и это сказано в самом продукте: резолв
// сессии (`internal/apps/kaname/api/humansession/resolve.go`) объявляет
// «Отсечку не применяет» и судит строку по трём признакам — снята · истекла ·
// личность неактивна. Значит после принудительного выхода носитель, выданный
// ДО него, продолжает резолвиться, и человек, которого распорядитель вывел,
// работает дальше. Это брешь, а не неудобство.
//
// Проба судит НАБЛЮДАЕМОЕ: тот же носитель, тем же резолвом, до и после.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ СТОИТ РЯДОМ
//
// Без него «после выхода сессии нет» зеленело бы на сломанной фикстуре —
// на носителе, который не резолвился и ДО выхода. Поэтому тот же резолв
// спрашивается до вызова и обязан ответить «сессия есть».

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// ownPostureForceLogoutHandler — обработчик, собранный КАК ЕГО СОБИРАЕТ КОРЕНЬ
// на посадке `own`: отсечка, операция, страж — и снятие НАШИХ записей сессии
// входа. Чужой поставщик не провязан: его на этой посадке нет вовсе, и выбор
// корня проверяется отдельно (`cmd/kaname/force_logout_teardown_wiring_test.go`).
func ownPostureForceLogoutHandler(t *testing.T, pool *pgxpool.Pool) *internaliam.Handler {
	t.Helper()
	return internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(pool)).
		WithAdminChecker(allowAdmin{}).
		WithOperations(operations.NewRepo(pool, "kaname")).
		WithOwnSessions(kanamepg.NewHumanSessionRepo(pool))
}

// ownSessionBearerDigest — свёртка носителя в форме, которую держит
// `human_sessions_bearer_digest_check`. Значение фикстуры, не секрет.
const ownSessionBearerDigest = "5f2b1c9d4e6a8b0c2d4e6f8a0b1c3d5e7f9a1b3c5d7e9f0a2b4c6d8e0f1a3b5c"

// seedOwnLoginSession кладёт ЖИВУЮ запись сессии входа ТЕМ ЖЕ писателем,
// которым её кладёт полоса входа: фикстура не имеет права быть снисходительнее
// продукта, иначе проба судит собственную вольность.
func seedOwnLoginSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	uid domain.UserID, digest string,
) domain.HumanSessionID {
	t.Helper()
	repo := kanamepg.NewHumanSessionRepo(pool)
	w, err := repo.Writer(ctx)
	require.NoError(t, err, "открыть транзакцию записи сессии")
	defer func() { _ = w.Rollback(ctx) }()

	at := time.Now().UTC().Add(-time.Minute)
	s := domain.HumanSession{
		ID:               domain.HumanSessionID(ids.NewHyphenID("hss")),
		UserID:           uid,
		AuthenticatedAt:  at,
		LastPresentedAt:  at,
		ExpiresAt:        at.Add(12 * time.Hour),
		AssuranceLevel:   "1",
		PresentedMethods: []string{"password"},
	}
	require.NoError(t, w.InsertSession(ctx, s, domain.BearerDigest(digest)), "положить сессию")
	require.NoError(t, w.Commit(ctx), "зафиксировать сессию")
	return s.ID
}

// TestIntegration_ForceLogoutEndsOurOwnLoginSession — после принудительного
// выхода наша сессия входа больше не резолвится.
func TestIntegration_ForceLogoutEndsOurOwnLoginSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)
	seedOwnLoginSession(t, ctx, pool, uid, ownSessionBearerDigest)

	sessions := kanamepg.NewHumanSessionRepo(pool)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до выхода тот же носитель резолвится.
	_, reason, err := sessions.Resolve(ctx, domain.BearerDigest(ownSessionBearerDigest), time.Now().UTC())
	require.NoError(t, err, "резолв сессии до выхода")
	require.Equal(t, humansession.SessionFound, reason,
		"фикстура не создала живой сессии — отрицание ниже зеленело бы на пустом месте")

	_, err = h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err, "принудительный выход")

	// ПРЕДМЕТ: после выхода тот же носитель сессии не даёт.
	_, reason, err = sessions.Resolve(ctx, domain.BearerDigest(ownSessionBearerDigest), time.Now().UTC())
	require.NoError(t, err, "резолв сессии после выхода")
	require.NotEqual(t, humansession.SessionFound, reason,
		"принудительный выход НЕ снял нашу сессию входа: носитель, выданный до "+
			"выхода, резолвится дальше. Отсечка субъекта эту строку не покрывает — "+
			"резолв её не применяет by construction")
	require.Equal(t, humansession.NoSessionEnded, reason,
		"сессия обязана отвечать «снята», а не «истекла» или «личность неактивна»: "+
			"причина отказа — выход, и журнал строки обязан это нести")
}
