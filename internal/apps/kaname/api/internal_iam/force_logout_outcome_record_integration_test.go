// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_outcome_record_integration_test.go — ДОЛГОВРЕМЕННАЯ ЗАПИСЬ
// ПРИНУДИТЕЛЬНОГО ВЫХОДА НЕСЁТ ЕГО ИСХОД, А НЕ ТОЛЬКО НАМЕРЕНИЕ (задача
// kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Событие `iam.session.force_logout` — долговременная запись привилегированного
// действия над чужими сессиями. Исход этого действия на посадке `own` — ЧИСЛО
// снятых записей сессии входа. Запись, не несущая его, наблюдает «сняли три» и
// «снимать было нечем» одинаково, и регрессия, при которой снятие перестало
// доходить, в ней не видна.
//
// Утверждается ТРИ исхода, и все три различимы в самой записи:
//
//   - сняты две живые записи → запись говорит «снято» и называет два;
//   - живых записей нет → запись говорит «снято» и называет НОЛЬ: ноль — законный
//     исход, а не отказ, и отличим он от отказа не отсутствием числа, а словом;
//   - снятие отказало → отсечка остаётся (она защитна сама по себе), живая
//     запись сессии цела, а запись события говорит «снятие не состоялось» и
//     числа не несёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ВЫЗВАН ОТКАЗ СНЯТИЯ — БАЗОЙ, НА НАСТОЯЩЕМ ПУТИ
//
// Отказ приходит от ТОЙ ЖЕ базы, на ТОМ ЖЕ операторе снятия, которым снимает
// обработчик, собранный как его собирает корень: пробе заводится триггер,
// отвергающий отметку окончания записи сессии. Подставной исполнитель здесь
// был бы негоден — предмет в том, что именно ложится в базу, когда снятие
// отказало, а подделка этого не различает. База у каждой пробы своя (клон
// шаблона), и триггер за её пределы не выходит.

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Свёртки носителей двух живых сессий одного человека — в форме, которую держит
// `human_sessions_bearer_digest_check`. Значения фикстуры, не секреты.
const (
	outcomeSessionDigestA = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
	outcomeSessionDigestB = "f9e8d7c6b5a4938271605f4e3d2c1b0af9e8d7c6b5a4938271605f4e3d2c1b0a"
)

// forceLogoutRecords — все записи события принудительного выхода о субъекте,
// в порядке появления. Числа читаются как `json.Number`: «два» здесь — точное
// значение, а не приближение с плавающей точкой.
func forceLogoutRecords(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uid domain.UserID) []map[string]any {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event_payload::text FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'subject_id' = $2
		 ORDER BY created_at, id`,
		kanamepg.SessionAuditEventForceLogout, string(uid))
	require.NoError(t, err, "чтение записей события")
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw string
		require.NoError(t, rows.Scan(&raw))
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.UseNumber()
		var payload map[string]any
		require.NoError(t, dec.Decode(&payload), "состав записи события: %s", raw)
		out = append(out, payload)
	}
	require.NoError(t, rows.Err())
	return out
}

// requireOneForceLogoutRecord — ровно одна запись события о субъекте. Две
// записи одного вызова значили бы, что намерение и исход легли порознь, и
// читатель журнала снова получал бы от одного акта два разных утверждения.
func requireOneForceLogoutRecord(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uid domain.UserID) map[string]any {
	t.Helper()
	records := forceLogoutRecords(t, ctx, pool, uid)
	require.Len(t, records, 1,
		"один принудительный выход обязан оставить РОВНО ОДНУ запись события: %v", records)
	return records[0]
}

// requireLiveBefore — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до выхода носитель резолвится.
// Без него «после выхода сессии нет» зеленело бы на сломанной фикстуре.
func requireLiveBefore(t *testing.T, ctx context.Context, sessions *kanamepg.HumanSessionRepo, digest string) {
	t.Helper()
	_, reason, err := sessions.Resolve(ctx, domain.BearerDigest(digest), time.Now().UTC())
	require.NoError(t, err, "резолв сессии до выхода")
	require.Equal(t, humansession.SessionFound, reason,
		"фикстура не создала живой сессии — утверждения ниже судили бы пустое место")
}

func resolveReason(t *testing.T, ctx context.Context, sessions *kanamepg.HumanSessionRepo, digest string) humansession.NoSessionReason {
	t.Helper()
	_, reason, err := sessions.Resolve(ctx, domain.BearerDigest(digest), time.Now().UTC())
	require.NoError(t, err, "резолв сессии после выхода")
	return reason
}

// TestIntegration_ForceLogoutRecordsHowManyOwnSessionsItEnded — две живые
// сессии → в долговременной записи «снято» и число два.
func TestIntegration_ForceLogoutRecordsHowManyOwnSessionsItEnded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)
	seedOwnLoginSession(t, ctx, pool, uid, outcomeSessionDigestA)
	seedOwnLoginSession(t, ctx, pool, uid, outcomeSessionDigestB)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	requireLiveBefore(t, ctx, sessions, outcomeSessionDigestA)
	requireLiveBefore(t, ctx, sessions, outcomeSessionDigestB)

	_, err := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err, "принудительный выход")

	// Запись обязана говорить то, что случилось в базе, — поэтому сперва
	// утверждается само случившееся.
	require.Equal(t, humansession.NoSessionEnded, resolveReason(t, ctx, sessions, outcomeSessionDigestA))
	require.Equal(t, humansession.NoSessionEnded, resolveReason(t, ctx, sessions, outcomeSessionDigestB))

	record := requireOneForceLogoutRecord(t, ctx, pool, uid)
	require.Equal(t, "ended", record["session_teardown"],
		"запись события не называет исхода снятия: «сняли» и «не дошло» в ней "+
			"неразличимы, а читает её именно расследование — состав: %v", record)
	require.Equal(t, json.Number("2"), record["sessions_ended"],
		"запись события обязана назвать ЧИСЛО снятых записей сессии — сняты две: %v", record)
}

// TestIntegration_ForceLogoutWithNoLiveSessionRecordsZeroAsAnOutcome — живых
// сессий нет → в записи «снято» и ноль, и это отличимо от отказа.
func TestIntegration_ForceLogoutWithNoLiveSessionRecordsZeroAsAnOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)

	_, err := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err, "выход того, у кого нет живой сессии, — законный исход, а не отказ")

	record := requireOneForceLogoutRecord(t, ctx, pool, uid)
	require.Equal(t, "ended", record["session_teardown"],
		"ноль снятых обязан читаться как исход «снято», а не как отказ: %v", record)
	require.Equal(t, json.Number("0"), record["sessions_ended"],
		"ноль обязан быть НАЗВАН числом: отсутствие числа — признак того, что "+
			"снятие не дошло, и слить их значит вернуть ту же неразличимость: %v", record)
}

// TestIntegration_ForceLogoutWhoseTeardownFailsKeepsTheCutoffAndRecordsTheFailure
// — ЧАСТИЧНЫЙ ИСХОД: снятие отказало. Отсечка остаётся, живая запись сессии
// цела, распорядитель получает отказ, а запись события говорит «снятие не
// состоялось» и числа не несёт.
func TestIntegration_ForceLogoutWhoseTeardownFailsKeepsTheCutoffAndRecordsTheFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)
	seedOwnLoginSession(t, ctx, pool, uid, outcomeSessionDigestA)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	requireLiveBefore(t, ctx, sessions, outcomeSessionDigestA)

	// Снятие отвергает база: отметка окончания записи сессии не принимается.
	_, err := pool.Exec(ctx, `
		CREATE FUNCTION kaname.probe_refuse_session_end() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'probe: ending a login session is refused';
		END $$`)
	require.NoError(t, err, "функция отказа снятия")
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER probe_refuse_session_end
		BEFORE UPDATE OF ended_at ON kaname.human_sessions
		FOR EACH ROW EXECUTE FUNCTION kaname.probe_refuse_session_end()`)
	require.NoError(t, err, "триггер отказа снятия")

	_, err = h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.Error(t, err, "неснятая сессия не имеет права читаться как состоявшийся выход")
	require.Equal(t, codes.Unavailable, status.Code(err))

	// Отказ пришёл от снятия, и снятия не было: запись сессии жива.
	require.Equal(t, humansession.SessionFound, resolveReason(t, ctx, sessions, outcomeSessionDigestA),
		"фикстура не вызвала отказа снятия — утверждения о частичном исходе ниже "+
			"судили бы полный")

	// Отсечка остаётся: обе её записи на месте.
	var cutoffs, minted int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`,
		string(uid)).Scan(&cutoffs))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1`,
		string(uid)).Scan(&minted))
	require.Equal(t, 1, cutoffs, "отсечка субъекта обязана остаться: она защитна сама по себе")
	require.Equal(t, 1, minted, "вторая запись отсечки обязана остаться вместе с первой")

	record := requireOneForceLogoutRecord(t, ctx, pool, uid)
	require.Equal(t, "failed", record["session_teardown"],
		"снятие отказало, а запись события этого не говорит: в долговременной записи "+
			"частичный исход неотличим от полного — состав: %v", record)
	_, carriesCount := record["sessions_ended"]
	require.False(t, carriesCount,
		"запись несостоявшегося снятия не имеет права нести число снятых: %v", record)
}
