// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// cutoff_writers_write_both_integration_test.go — КАЖДЫЙ ПИСАТЕЛЬ ОТСЕЧКИ
// КЛАДЁТ ОБЕ ЗАПИСИ, и снятие сессии отзывает выданное в ней (kaname#313).
//
// Записей отсечки две, и судят по ним РАЗНЫЕ читатели. Путь снятия доступа,
// дошедший до одной и не дошедший до второй, снимает доступ наполовину и
// выглядит исполненным целиком.
//
// Пробы судят наблюдаемое ТОЙ ЖЕ функцией решения, которой судит поверхность.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// bearerClaims — состав утверждений личного носителя в ТОЙ форме, в какой его
// получает поверхность: числовые отметки приходят `float64` после разбора JSON.
func bearerClaims(sub string, issued time.Time) jwt.MapClaims {
	return jwt.MapClaims{"sub": sub, "iat": float64(issued.Unix())}
}

// TestIntegration_LoginLaneCutoffWriterWritesBothRecords — писатель отсечки
// ПОЛОСЫ ВХОДА (выход, смена пароля, восстановление, сброс второго фактора)
// снимает доступ и на предъявлении, а не только на выдаче.
func TestIntegration_LoginLaneCutoffWriterWritesBothRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "bwrec")
	authority := kanamepg.NewMintedTokenRevocationRepo(pool)
	issued := time.Now().UTC().Add(-time.Minute)
	claims := bearerClaims(scene.UserID, issued)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до отсечки носитель принимается.
	revoked, err := tokenrevocation.Revoked(ctx, authority, claims)
	require.NoError(t, err)
	require.False(t, revoked, "носитель отозван ДО отсечки — отрицание ниже беспредметно")

	// Отсечку кладёт писатель ПОЛОСЫ ВХОДА, той же дверью, что и все прочие.
	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID:       domain.UserID(scene.UserID),
		RevokeBefore: time.Now().UTC(),
		Reason:       domain.RevokeReasonLogout,
	}, domain.UserID(scene.UserID)))
	require.NoError(t, w.Commit(ctx))

	// ПРЕДМЕТ: тот же носитель предъявлением больше не проходит.
	revoked, err = tokenrevocation.Revoked(ctx, authority, claims)
	require.NoError(t, err)
	require.True(t, revoked,
		"писатель отсечки полосы входа положил ОДНУ запись из двух: доступ снят на "+
			"выдаче и НЕ снят на предъявлении — прежний носитель продолжает "+
			"аутентифицировать вызовы")
}

// TestIntegration_EndingOtherSessionsRevokesTheirFamilies — снятие ПРОЧИХ
// сессий (смена пароля, снятие второго фактора, завершение восстановления)
// отзывает выданное в них.
//
// Ротацию обновляющего токена останавливает РОВНО отзыв семейства: запрос
// ротации не читает ни отметку окончания сессии, ни одну из отсечек. Значит
// сессия, снятая без отзыва, снята только в записи.
func TestIntegration_EndingOtherSessionsRevokesTheirFamilies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "endsf")
	ceremony := kanamepg.NewOAuthCeremonyRepo(pool)
	require.NoError(t, ceremony.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          ceremonyDigest(7101),
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}))
	_, err = ceremony.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest:         ceremonyDigest(7101),
		RefreshTokenDigest: ceremonyDigest(7102),
		RefreshTokenTTL:    time.Hour,
	})
	require.NoError(t, err)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до снятия обновляющий токен РОТИРУЕТСЯ.
	_, err = ceremony.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
		PresentedDigest: ceremonyDigest(7102),
		SuccessorDigest: ceremonyDigest(7103),
		TTL:             time.Hour,
	})
	require.NoError(t, err, "до снятия ротация обязана проходить — иначе отрицание ниже беспредметно")

	// ПРЕДМЕТ: снять ПРОЧИЕ сессии (сохраняемой сессии у этой личности нет,
	// поэтому снимается посевная) — тем же путём, каким это делает смена пароля.
	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	n, err := w.EndOtherSessions(ctx, domain.UserID(scene.UserID),
		domain.HumanSessionID("hs-keep-none-0000"), time.Now().UTC(),
		domain.RevokeReasonPasswordChange)
	require.NoError(t, err)
	require.Equal(t, 1, n, "снята обязана быть посевная сессия")
	require.NoError(t, w.Commit(ctx))

	// Преемник, выданный ротацией, больше не ротируется: семейство отозвано.
	_, err = ceremony.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
		PresentedDigest: ceremonyDigest(7103),
		SuccessorDigest: ceremonyDigest(7104),
		TTL:             time.Hour,
	})
	require.Error(t, err,
		"после снятия сессии обновляющий токен ПРОДОЛЖАЕТ ротироваться в свежие: "+
			"снятие записи ротацию не останавливает, её останавливает только отзыв семейства")

	var revokedReason *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`,
		scene.FamilyID).Scan(&revokedReason))
	require.NotNil(t, revokedReason, "семейство снятой сессии не отозвано")
	require.Equal(t, string(domain.FamilyRevokedBySessionEnd), *revokedReason)
}

// TestIntegration_EndingOneSessionRevokesItsFamily — снятие ОДНОЙ записи по
// идентификатору отзывает выданное в ней.
//
// Живой вызывающий этого пути — СОБСТВЕННЫЙ ВЫХОД ЧЕЛОВЕКА, и ни одна из
// соседних проб его не судила: набор проб повторял слепое пятно кода — обе
// судили методы, снимающие НЕСКОЛЬКО записей, и третьего не видели.
func TestIntegration_EndingOneSessionRevokesItsFamily(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "endne")
	ceremony := kanamepg.NewOAuthCeremonyRepo(pool)
	require.NoError(t, ceremony.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          ceremonyDigest(8201),
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}))
	_, err = ceremony.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest:         ceremonyDigest(8201),
		RefreshTokenDigest: ceremonyDigest(8202),
		RefreshTokenTTL:    time.Hour,
	})
	require.NoError(t, err)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до выхода ротация ПРОХОДИТ.
	_, err = ceremony.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
		PresentedDigest: ceremonyDigest(8202),
		SuccessorDigest: ceremonyDigest(8203),
		TTL:             time.Hour,
	})
	require.NoError(t, err, "до выхода ротация обязана проходить — иначе отрицание беспредметно")

	// ПРЕДМЕТ: человек выходит САМ — тем же оператором, каким его выводит выход.
	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	ended, err := w.EndSession(ctx, domain.HumanSessionID(scene.SessionID),
		time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.True(t, ended, "запись обязана быть снята этим вызовом")
	require.NoError(t, w.Commit(ctx))

	_, err = ceremony.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
		PresentedDigest: ceremonyDigest(8203),
		SuccessorDigest: ceremonyDigest(8204),
		TTL:             time.Hour,
	})
	require.Error(t, err,
		"после СОБСТВЕННОГО выхода человека обновляющий токен продолжает ротироваться "+
			"в свежие: запись помечена окончённой, а выданное в ней живо")

	var revokedReason *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`,
		scene.FamilyID).Scan(&revokedReason))
	require.NotNil(t, revokedReason, "семейство снятой записи не отозвано")
	require.Equal(t, string(domain.FamilyRevokedBySessionEnd), *revokedReason)
}

// TestIntegration_RepeatedEndSessionDoesNotRewriteTheReason — повторное снятие
// ничего не снимает и причину отзыва не переписывает.
//
// Без этой оси отзыв можно было бы поставить безусловно, и проигравший гонку
// переписал бы причину победителя.
func TestIntegration_RepeatedEndSessionDoesNotRewriteTheReason(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "endrp")
	sessions := kanamepg.NewHumanSessionRepo(pool)

	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	first, err := w.EndSession(ctx, domain.HumanSessionID(scene.SessionID),
		time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.True(t, first)
	require.NoError(t, w.Commit(ctx))

	w2, err := sessions.Writer(ctx)
	require.NoError(t, err)
	second, err := w2.EndSession(ctx, domain.HumanSessionID(scene.SessionID),
		time.Now().UTC(), domain.RevokeReasonPasswordChange)
	require.NoError(t, err)
	require.False(t, second, "повторное снятие обязано не снимать ничего")
	require.NoError(t, w2.Commit(ctx))
}

// TestIntegration_LosingCutoffDoesNotRewriteReasonAndActor — отброшенный момент
// не переносит НИ В ОДНУ из двух записей ни причины, ни актора.
//
// Расхождение это оживает ровно тогда, когда обе записи кладутся одной дверью:
// полоса входа несёт СВОЙ момент, он бывает раньше стоящего, а администратор —
// текущий. Без замка запись, по которой судит авторитет отзыва НА ПУТИ ЗАПРОСА,
// назвала бы неверного принявшего решение.
func TestIntegration_LosingCutoffDoesNotRewriteReasonAndActor(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "ckrsn")
	repo := kanamepg.NewUserTokenRevocationRepo(pool)
	admin := domain.UserID(scene.UserID)

	// Стоящая отсечка — ПОЗДНИЙ момент, причина и актор распорядителя.
	late := time.Now().UTC()
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(scene.UserID), RevokeBefore: late,
		Reason: "admin-force-logout",
	}, admin))

	// Проигравшая — РАННИЙ момент, причина и актор полосы входа.
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(scene.UserID), RevokeBefore: late.Add(-time.Hour),
		Reason: domain.RevokeReasonLogout,
	}, domain.UserID(scene.UserID)))

	// ОБЕ записи обязаны сохранить причину стоящего момента.
	for _, q := range []struct{ name, sql string }{
		{"отсечка субъекта",
			`SELECT reason FROM kaname.user_token_revocations WHERE user_id = $1`},
		{"отсечка предъявления",
			`SELECT reason FROM kaname.minted_token_revocations WHERE subject = $1`},
	} {
		var reason string
		require.NoError(t, pool.QueryRow(ctx, q.sql, scene.UserID).Scan(&reason), q.name)
		require.Equal(t, "admin-force-logout", reason,
			"%s: отброшенный момент переписал причину стоящего — строка называет "+
				"неверного принявшего решение", q.name)
	}
}

// TestIntegration_PoolDoorIsAtomicToo — дверь на ПУЛОВОМ исполнителе кладёт обе
// записи одной транзакцией, а негодный вход отвергает ДО первой записи.
//
// На пуле два оператора суть два автокоммита, и между ними существует
// наблюдаемое состояние «одна запись без другой». Путь этот сегодня без
// прод-вызывающих — тем важнее, что обещание двери и её дело совпадают: латентный
// путь оживает тихо.
func TestIntegration_PoolDoorIsAtomicToo(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "pdknr")
	repo := kanamepg.NewUserTokenRevocationRepo(pool)

	// НЕГОДНЫЙ ВХОД: решившего нет и причины нет — имя механизма не выводится.
	// Отказ обязан прийти ДО первой записи.
	err = repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: "", RevokeBefore: time.Now().UTC(),
	}, "")
	require.Error(t, err, "негодный вход обязан быть отвергнут")

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = ''`).Scan(&rows))
	require.Zero(t, rows, "отвергнутый вход оставил ПЕРВУЮ запись: проверки стоят "+
		"после исполнения, и половина записывается прежде отказа")

	// ГОДНЫЙ ВХОД на том же пуловом исполнителе: обе записи на месте.
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(scene.UserID), RevokeBefore: time.Now().UTC(),
		Reason: domain.RevokeReasonLogout,
	}, domain.UserID(scene.UserID)))

	for _, q := range []struct{ name, sql string }{
		{"отсечка субъекта", `SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`},
		{"отсечка предъявления", `SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1`},
	} {
		var n int
		require.NoError(t, pool.QueryRow(ctx, q.sql, scene.UserID).Scan(&n), q.name)
		require.Equal(t, 1, n, "%s не положена пуловой дверью", q.name)
	}
}
