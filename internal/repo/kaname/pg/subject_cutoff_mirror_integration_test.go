// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// subject_cutoff_mirror_integration_test.go — ПЕРВАЯ ЗАПИСЬ ОТСЕЧКИ ВСЕГДА
// ДОХОДИТ ДО ВТОРОЙ, и держит это схема, а не пакет (kaname#336; приёмка
// `docs/engineering/acceptance/subject-cutoff-writes-both-records-under-one-lock.md`,
// стадия S2, сценарии KN-SCL-07…12).
//
// Go-дверь `upsertSubjectCutoff` кладёт обе записи сама, но писатель на голом
// SQL мимо неё клал одну. Зеркало — триггер на первой записи: её вставка или
// изменение той же транзакцией пишет вторую под тем же замком по моменту.
//
// Направление одно (Р2): вторая запись первую НЕ пишет — иначе блокировка,
// обратимое состояние, стала бы необратимой отсечкой (KN-SCL-09). Снятие не
// зеркалится (Р3, KN-SCL-12).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// putFirstRecord кладёт первую запись голым SQL — мимо Go-двери. `decider`
// пустой — NULL.
func putFirstRecord(ctx context.Context, pool *pgxpool.Pool, user string, before time.Time, reason, decider string) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.user_token_revocations (user_id, revoke_before, reason, revoked_by_user_id)
		 VALUES ($1, $2, $3, NULLIF($4, ''))`, user, before, reason, decider)
	return err
}

// KN-SCL-07 — запись первой строки голым SQL кладёт вторую.
func TestSubjectCutoff_KN_SCL_07_BareFirstRecordWritesTheSecond(t *testing.T) {
	ctx, pool := cutoffPool(t)
	u := cutoffPerson(t, ctx, pool, "scl07u")
	v := cutoffPerson(t, ctx, pool, "scl07v")
	at := time.Now().UTC().Truncate(time.Microsecond)

	// Решивший — механизм: человека за решением нет.
	require.NoError(t, putFirstRecord(ctx, pool, u, at, domain.RevokeReasonLogout, ""))
	requireRowEqual(t, readSecondRecord(t, ctx, pool, u), at, domain.RevokeReasonLogout, "kaname:logout",
		"вставка первой записи голым SQL не положила вторую")

	// Близнец по правилу решившего: человек назван — он и решивший.
	require.NoError(t, putFirstRecord(ctx, pool, v, at, domain.RevokeReasonAdminForceLogout, "usr-admin-x"))
	requireRowEqual(t, readSecondRecord(t, ctx, pool, v), at, domain.RevokeReasonAdminForceLogout, "usr-admin-x",
		"вторая запись не назвала решившим человека из первой")

	// Изменение первой записи голым SQL доходит до второй.
	later := at.Add(time.Minute)
	_, err := pool.Exec(ctx,
		`UPDATE kaname.user_token_revocations SET revoke_before = $2, reason = $3 WHERE user_id = $1`,
		u, later, domain.RevokeReasonPasswordChange)
	require.NoError(t, err)
	requireRowEqual(t, readSecondRecord(t, ctx, pool, u), later, domain.RevokeReasonPasswordChange, "kaname:password-change",
		"изменение первой записи голым SQL не дошло до второй")
}

// KN-SCL-08 — запись первой строки, которую вторая не принимает, не ложится вовсе.
func TestSubjectCutoff_KN_SCL_08_FirstRecordTheSecondRefusesDoesNotLand(t *testing.T) {
	ctx, pool := cutoffPool(t)
	u := cutoffPerson(t, ctx, pool, "scl08")
	// `kaname:` + 122 знака = 129 при пределе решившего второй записи 128.
	reason := strings.Repeat("r", 122)

	err := putFirstRecord(ctx, pool, u, time.Now().UTC(), reason, "")
	require.Error(t, err, "первая запись легла, хотя вторая её решившего не принимает")
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "отказ обязан прийти от базы: %v", err)
	require.Equal(t, "23514", pgErr.Code, "код отказа")

	require.False(t, readFirstRecord(t, ctx, pool, u).Present, "первая запись легла одна")
	require.False(t, readSecondRecord(t, ctx, pool, u).Present, "вторая запись легла")
}

// KN-SCL-09 — запись второй строки первую не пишет: блокировка остаётся обратимой.
func TestSubjectCutoff_KN_SCL_09_SecondRecordNeverWritesTheFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	f := newAssertionFixture(t)
	ctx := context.Background()
	u := f.user
	clientID, _ := seedAssertionClientOfKind(t, f, domain.AssertionClientUser)
	w := cutoffPerson(t, ctx, f.pool, "scl09w")

	// Блокировка и возврат — тем оператором, которым их делает продукт.
	blockPerson(t, ctx, f.pool, u)
	tag, err := f.pool.Exec(ctx,
		`UPDATE kaname.users SET invite_status = 'ACTIVE' WHERE id = $1 AND invite_status = 'BLOCKED'`, u)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "возврат в ACTIVE обязан состояться")
	deactivateOwner(t, f, domain.AssertionClientServiceAccount, "")
	removeClient(t, f, domain.AssertionClientUser, clientID)
	putSecondRecord(t, ctx, f.pool, w, time.Now().UTC(), "seed-second", "usr-seed-second")

	for _, subject := range []string{u, f.sva, clientID, w} {
		require.True(t, readSecondRecord(t, ctx, f.pool, subject).Present, "второй записи %s нет", subject)
	}
	require.Equal(t, ownerGoneReason, readSecondRecord(t, ctx, f.pool, u).Reason)
	require.Equal(t, ownerGoneReason, readSecondRecord(t, ctx, f.pool, f.sva).Reason)
	require.Equal(t, clientRemovalReason, readSecondRecord(t, ctx, f.pool, clientID).Reason)

	for _, person := range []string{u, w} {
		require.False(t, readFirstRecord(t, ctx, f.pool, person).Present,
			"вторая запись положила первую у %s: блокировка стала необратимой отсечкой", person)
	}
	cutoff, ok, err := kanamepg.NewUserTokenRevocationRepo(f.pool).RevokedBefore(ctx, u)
	require.NoError(t, err)
	require.False(t, ok, "у разблокированного человека есть отсечка")
	require.True(t, cutoff.IsZero())
}

// KN-SCL-10 — Go-дверь не меняет видимого и не упирается в зеркало.
func TestSubjectCutoff_KN_SCL_10_DoorStaysVisiblyTheSameUnderTheMirror(t *testing.T) {
	ctx, pool := cutoffPool(t)
	repo := kanamepg.NewUserTokenRevocationRepo(pool)

	rounds := map[string]func(u string, c domain.UserTokenRevocation) error{
		"pool": func(u string, c domain.UserTokenRevocation) error {
			return repo.UpsertRevokeAll(ctx, c, domain.UserID(u))
		},
		"tx": func(u string, c domain.UserTokenRevocation) error {
			tx, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := repo.UpsertRevokeAllTx(ctx, tx, c, domain.UserID(u)); err != nil {
				return err
			}
			return tx.Commit(ctx)
		},
	}
	for name, write := range rounds {
		t.Run(name, func(t *testing.T) {
			u := cutoffPerson(t, ctx, pool, "scl10"+name)
			at := time.Now().UTC().Truncate(time.Microsecond)
			require.NoError(t, write(u, domain.UserTokenRevocation{
				UserID: domain.UserID(u), RevokeBefore: at, Reason: domain.RevokeReasonLogout,
			}))
			requireRowEqual(t, readFirstRecord(t, ctx, pool, u), at, domain.RevokeReasonLogout, u, "первая запись двери")
			requireRowEqual(t, readSecondRecord(t, ctx, pool, u), at, domain.RevokeReasonLogout, u,
				"вторая запись двери: решивший переписан на имя механизма либо строк две")

			// Проигравший момент не меняет ни одной из двух — и зеркальной тоже.
			require.NoError(t, write(u, domain.UserTokenRevocation{
				UserID: domain.UserID(u), RevokeBefore: at.Add(-time.Hour), Reason: domain.RevokeReasonPasswordChange,
			}))
			requireRowEqual(t, readFirstRecord(t, ctx, pool, u), at, domain.RevokeReasonLogout, u,
				"проигравший момент переписал первую запись")
			requireRowEqual(t, readSecondRecord(t, ctx, pool, u), at, domain.RevokeReasonLogout, u,
				"проигравший момент переписал вторую запись")
		})
	}
}

// KN-SCL-11 — дверь и блокировка одного человека параллельно.
//
// Форма — `concurrent-integration-test`: 20 раундов, в каждом две горутины на
// одного человека. Утверждается завершение обеих (ни `40P01`, ни иной ошибки) и
// значения строк по замку. Момент блокировки берётся у её же транзакции
// (`RETURNING now()`), поэтому «больший из двух» сверяется числом, а не
// угадывается.
func TestSubjectCutoff_KN_SCL_11_DoorAndBlockRaceOnOnePerson(t *testing.T) {
	ctx, pool := cutoffPool(t)
	repo := kanamepg.NewUserTokenRevocationRepo(pool)
	const rounds = 20
	doorWon, blockWon := 0, 0
	for i := 0; i < rounds; i++ {
		u := cutoffPerson(t, ctx, pool, "scl11r"+string(rune('a'+i)))
		var (
			wg              sync.WaitGroup
			doorErr, blkErr error
			doorAt, blockAt time.Time
			start           = make(chan struct{})
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			doorAt = time.Now().UTC().Truncate(time.Microsecond)
			doorErr = repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
				UserID: domain.UserID(u), RevokeBefore: doorAt, Reason: domain.RevokeReasonLogout,
			}, domain.UserID(u))
		}()
		go func() {
			defer wg.Done()
			<-start
			blkErr = pool.QueryRow(ctx,
				`UPDATE kaname.users SET invite_status = 'BLOCKED'
				  WHERE id = $1 AND invite_status = 'ACTIVE' RETURNING now()`, u).Scan(&blockAt)
		}()
		close(start)
		wg.Wait()
		require.NoError(t, doorErr, "раунд %d: дверь", i)
		require.NoError(t, blkErr, "раунд %d: блокировка", i)

		requireRowEqual(t, readFirstRecord(t, ctx, pool, u), doorAt, domain.RevokeReasonLogout, u,
			"раунд "+string(rune('a'+i))+": первая запись не та, что положила дверь")
		second := readSecondRecord(t, ctx, pool, u)
		switch {
		case doorAt.After(blockAt):
			doorWon++
			requireRowEqual(t, second, doorAt, domain.RevokeReasonLogout, u, "вторая запись: стоит момент двери")
		case blockAt.After(doorAt):
			blockWon++
			requireRowEqual(t, second, blockAt, ownerGoneReason, ownerGoneDecider, "вторая запись: стоит момент блокировки")
		default:
			require.True(t, second.Before.Equal(doorAt), "равные моменты: момент")
		}
	}
	t.Logf("раундов %d: момент двери стоит в %d, момент блокировки — в %d", rounds, doorWon, blockWon)
}

// cutoffMember заводит аккаунт с владельцем и ещё одного ЧЛЕНА — не владельца,
// без привязок субъекта: его строку `kaname.users` снять можно
// (`accounts_owner_fk` держит только владельца).
func cutoffMember(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tag string) string {
	t.Helper()
	owner := "usr" + ceremonyPad(tag+"o")
	member := "usr" + ceremonyPad(tag+"m")
	account := "acc" + ceremonyPad(tag)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'owner', $5, 'ACTIVE'),
		       ($4, $6, $7, 'member', $5, 'ACTIVE')`,
		owner, "ext-"+tag+"-o", tag+"-o@example.invalid",
		member, account, "ext-"+tag+"-m", tag+"-m@example.invalid")
	require.NoError(t, err, "посев людей %s", tag)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, owner)
	require.NoError(t, err, "посев аккаунта %s", tag)
	seedWayIn(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	return member
}

// KN-SCL-12 — удаление не зеркалится.
func TestSubjectCutoff_KN_SCL_12_RemovalIsNotMirrored(t *testing.T) {
	ctx, pool := cutoffPool(t)
	repo := kanamepg.NewUserTokenRevocationRepo(pool)
	grace := tokenpolicy.MaxTokenTTL + tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack

	u := cutoffPerson(t, ctx, pool, "scl12u")
	old := time.Now().UTC().Add(-(grace + time.Hour)).Truncate(time.Microsecond)
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(u), RevokeBefore: old, Reason: domain.RevokeReasonLogout,
	}, domain.UserID(u)))

	w := cutoffMember(t, ctx, pool, "scl12w")
	fresh := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(w), RevokeBefore: fresh, Reason: domain.RevokeReasonLogout,
	}, domain.UserID(w)))

	removed, _, err := kanamepg.NewMintedTokenRevocationRepo(pool).SweepStaleCutoffs(ctx, grace, sweepBatch)
	require.NoError(t, err)
	require.Positive(t, removed, "уборка не сняла ничего — утверждение ниже беспредметно")
	tag, err := pool.Exec(ctx, `DELETE FROM kaname.users WHERE id = $1`, w)
	require.NoError(t, err, "снятие члена аккаунта обязано пройти")
	require.EqualValues(t, 1, tag.RowsAffected())

	require.False(t, readSecondRecord(t, ctx, pool, u).Present, "уборка не сняла вторую запись")
	requireRowEqual(t, readFirstRecord(t, ctx, pool, u), old, domain.RevokeReasonLogout, u,
		"снятие второй записи унесло первую")
	require.False(t, readFirstRecord(t, ctx, pool, w).Present, "каскад не снял первую запись")
	requireRowEqual(t, readSecondRecord(t, ctx, pool, w), fresh, domain.RevokeReasonLogout, w,
		"каскад первой записи унёс вторую")
}
