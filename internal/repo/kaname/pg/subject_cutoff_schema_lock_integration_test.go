// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// subject_cutoff_schema_lock_integration_test.go — СХЕМНЫЕ ПИСАТЕЛИ ВТОРОЙ
// ЗАПИСИ ОТСЕЧКИ стоят под тем же замком по моменту, что и Go-дверь
// (kaname#335; приёмка `docs/engineering/acceptance/subject-cutoff-writes-both-records-under-one-lock.md`,
// стадия S1, сценарии KN-SCL-01…06 и 19).
//
// Пишут вторую запись (`kaname.minted_token_revocations`) двое: Go-дверь и две
// функции схемы, которые зовут четыре триггера — снятие клиента двух видов,
// отключение учётки, уход человека из `ACTIVE`. Момент монотонен у всех, а
// причина и решивший у схемных писателей переписывались БЕЗУСЛОВНО: проигравший
// момент переносил на стоящую запись своё имя решившего.
//
// У каждого отрицания есть близнец, отличающийся ровно стоящим моментом: без него
// отрицание проходило бы на функции, которая не пишет ничего.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// Значения схемных писателей — дословно из их определений; «Тогда» близнецов
// сверяет именно их.
const (
	clientRemovalReason  = "client key revoked: registry row removed"
	clientRemovalDecider = "kaname:client-key-revoked"
	ownerGoneReason      = "owner is no longer active"
	ownerGoneDecider     = "kaname:owner-deactivated"
)

// cutoffRow — строка записи отсечки, прочитанная по ключу. `Decider` первой
// записи бывает NULL — тогда `DeciderSet` ложно.
type cutoffRow struct {
	Present    bool
	Before     time.Time
	Reason     string
	Decider    string
	DeciderSet bool
}

// readSecondRecord читает вторую запись отсечки субъекта.
func readSecondRecord(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject string) cutoffRow {
	t.Helper()
	var r cutoffRow
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1`, subject).Scan(&n))
	require.LessOrEqual(t, n, 1, "у субъекта %s больше одной второй записи", subject)
	if n == 0 {
		return r
	}
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoke_before, reason, revoked_by FROM kaname.minted_token_revocations WHERE subject = $1`,
		subject).Scan(&r.Before, &r.Reason, &r.Decider))
	r.Present, r.DeciderSet = true, true
	return r
}

// readFirstRecord читает первую запись отсечки человека.
func readFirstRecord(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user string) cutoffRow {
	t.Helper()
	var r cutoffRow
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`, user).Scan(&n))
	require.LessOrEqual(t, n, 1, "у человека %s больше одной первой записи", user)
	if n == 0 {
		return r
	}
	var by *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoke_before, reason, revoked_by_user_id FROM kaname.user_token_revocations WHERE user_id = $1`,
		user).Scan(&r.Before, &r.Reason, &by))
	r.Present = true
	if by != nil {
		r.Decider, r.DeciderSet = *by, true
	}
	return r
}

// putSecondRecord кладёт вторую запись голым SQL — мимо любого писателя
// продукта: сцена задаёт стоящее значение, а не испытывает писателя.
func putSecondRecord(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject string, before time.Time, reason, decider string) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
		 VALUES ($1, $2, $3, $4)`, subject, before, reason, decider)
	require.NoError(t, err, "посев второй записи %s", subject)
}

// requireRowEqual сверяет строку с ожидаемой тройкой. Момент сравнивается до
// микросекунды — точность хранения.
func requireRowEqual(t *testing.T, got cutoffRow, before time.Time, reason, decider, why string) {
	t.Helper()
	require.True(t, got.Present, "%s: записи нет", why)
	require.True(t, got.Before.Equal(before.Truncate(time.Microsecond)),
		"%s: момент %s, ожидался %s", why, got.Before.UTC(), before.Truncate(time.Microsecond).UTC())
	require.Equal(t, reason, got.Reason, "%s: причина", why)
	require.True(t, got.DeciderSet, "%s: решивший пуст (NULL)", why)
	require.Equal(t, decider, got.Decider, "%s: решивший", why)
}

// cutoffPool — база в контейнере, миграции до головы, `kaname` в пути поиска.
func cutoffPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return ctx, pool
}

// cutoffPerson заводит человека в `ACTIVE` и его аккаунт (он — владелец).
// Строки ссылаются друг на друга, внешние ключи отложенные — одна транзакция.
func cutoffPerson(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tag string) string {
	t.Helper()
	user := "usr" + ceremonyPad(tag+"u")
	account := "acc" + ceremonyPad(tag)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, email_verified_at)
		VALUES ($1, $2, $3, $4, 'cutoff', 'ACTIVE', now())`,
		user, account, "ext-"+tag, tag+"@example.invalid")
	require.NoError(t, err, "посев человека %s", tag)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, user)
	require.NoError(t, err, "посев аккаунта %s", tag)
	require.NoError(t, tx.Commit(ctx))
	return user
}

// blockPerson переводит человека из `ACTIVE` в `BLOCKED` тем оператором,
// которым это делает продукт (`userWriter.SetInviteStatus`).
func blockPerson(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user string) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.users SET invite_status = 'BLOCKED' WHERE id = $1 AND invite_status = 'ACTIVE'`, user)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "переход из ACTIVE обязан состояться ровно один раз")
}

// clientRemovalScene — живой клиент вида `kind` и стоящая вторая запись по нему
// со сдвигом `standing` от текущего момента. Возвращает идентификатор клиента.
func clientRemovalScene(t *testing.T, kind domain.AssertionClientKind, standing time.Duration) (assertionFixture, string, time.Time) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	f := newAssertionFixture(t)
	clientID, _ := seedAssertionClientOfKind(t, f, kind)
	before := time.Now().UTC().Add(standing)
	putSecondRecord(t, context.Background(), f.pool, clientID, before, "seed-late", "usr-seed-late")
	return f, clientID, before
}

// removeClient удаляет строку клиента названного вида.
func removeClient(t *testing.T, f assertionFixture, kind domain.AssertionClientKind, clientID string) {
	t.Helper()
	table := map[domain.AssertionClientKind]string{
		domain.AssertionClientUser:           "kaname.user_oauth_clients",
		domain.AssertionClientServiceAccount: "kaname.service_account_oauth_clients",
	}[kind]
	require.NotEmpty(t, table, "вид клиента вне закрытого словаря: %q", kind)
	tag, err := f.pool.Exec(context.Background(), `DELETE FROM `+table+` WHERE id = $1`, clientID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "строка клиента обязана быть снята ровно одна")
}

var bothClientKinds = []domain.AssertionClientKind{domain.AssertionClientUser, domain.AssertionClientServiceAccount}

// KN-SCL-01 — снятие клиента с моментом раньше стоящего не меняет стоящую запись.
func TestSubjectCutoff_KN_SCL_01_LosingClientRemovalKeepsTheStandingRecord(t *testing.T) {
	for _, kind := range bothClientKinds {
		t.Run(string(kind), func(t *testing.T) {
			f, clientID, before := clientRemovalScene(t, kind, time.Hour)
			removeClient(t, f, kind, clientID)
			requireRowEqual(t, readSecondRecord(t, context.Background(), f.pool, clientID),
				before, "seed-late", "usr-seed-late",
				"проигравшее снятие клиента переписало стоящую запись")
		})
	}
}

// KN-SCL-02 — близнец 01: снятие клиента с моментом позже стоящего берёт свои значения.
func TestSubjectCutoff_KN_SCL_02_WinningClientRemovalTakesItsOwnValues(t *testing.T) {
	for _, kind := range bothClientKinds {
		t.Run(string(kind), func(t *testing.T) {
			f, clientID, before := clientRemovalScene(t, kind, -time.Hour)
			removeClient(t, f, kind, clientID)
			got := readSecondRecord(t, context.Background(), f.pool, clientID)
			require.True(t, got.Present)
			require.True(t, got.Before.After(before), "момент не сдвинут на момент снятия")
			require.Equal(t, clientRemovalReason, got.Reason)
			require.Equal(t, clientRemovalDecider, got.Decider)
		})
	}
}

// KN-SCL-03 — равные моменты: стоит последняя запись.
func TestSubjectCutoff_KN_SCL_03_EqualInstantsLastWriteStands(t *testing.T) {
	for _, kind := range bothClientKinds {
		t.Run(string(kind), func(t *testing.T) {
			if testing.Short() {
				t.Skip("integration: нужен Postgres в контейнере")
			}
			f := newAssertionFixture(t)
			clientID, _ := seedAssertionClientOfKind(t, f, kind)
			table := map[domain.AssertionClientKind]string{
				domain.AssertionClientUser:           "kaname.user_oauth_clients",
				domain.AssertionClientServiceAccount: "kaname.service_account_oauth_clients",
			}[kind]
			ctx := context.Background()
			tx, err := f.pool.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, `INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
				VALUES ($1, now(), 'seed-equal', 'usr-seed-equal')`, clientID)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `DELETE FROM `+table+` WHERE id = $1`, clientID)
			require.NoError(t, err)
			require.NoError(t, tx.Commit(ctx))

			got := readSecondRecord(t, ctx, f.pool, clientID)
			require.True(t, got.Present)
			require.Equal(t, clientRemovalReason, got.Reason, "на равных стоит последняя запись")
			require.Equal(t, clientRemovalDecider, got.Decider, "на равных стоит последняя запись")
		})
	}
}

// KN-SCL-04 — отключение учётки с моментом раньше стоящего не меняет стоящую запись.
func TestSubjectCutoff_KN_SCL_04_LosingServiceAccountDeactivationKeepsTheStandingRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	f := newAssertionFixture(t)
	before := time.Now().UTC().Add(time.Hour)
	putSecondRecord(t, context.Background(), f.pool, f.sva, before, "seed-late", "usr-seed-late")
	deactivateOwner(t, f, domain.AssertionClientServiceAccount, "")
	requireRowEqual(t, readSecondRecord(t, context.Background(), f.pool, f.sva),
		before, "seed-late", "usr-seed-late",
		"проигравшее отключение учётки переписало стоящую запись")
}

// KN-SCL-05 — близнец 04: отключение учётки с моментом позже стоящего берёт свои значения.
func TestSubjectCutoff_KN_SCL_05_WinningServiceAccountDeactivationTakesItsOwnValues(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	f := newAssertionFixture(t)
	before := time.Now().UTC().Add(-time.Hour)
	putSecondRecord(t, context.Background(), f.pool, f.sva, before, "seed-late", "usr-seed-late")
	deactivateOwner(t, f, domain.AssertionClientServiceAccount, "")
	got := readSecondRecord(t, context.Background(), f.pool, f.sva)
	require.True(t, got.Present)
	require.True(t, got.Before.After(before), "момент не сдвинут на момент отключения")
	require.Equal(t, ownerGoneReason, got.Reason)
	require.Equal(t, ownerGoneDecider, got.Decider)
}

// personBlockScene — человек с отсечкой, положенной ДВЕРЬЮ со сдвигом
// `standing`, и затем переведённый в BLOCKED.
func personBlockScene(t *testing.T, tag string, standing time.Duration) (context.Context, *pgxpool.Pool, string, time.Time) {
	t.Helper()
	ctx, pool := cutoffPool(t)
	user := cutoffPerson(t, ctx, pool, tag)
	before := time.Now().UTC().Add(standing)
	require.NoError(t, kanamepg.NewUserTokenRevocationRepo(pool).UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(user), RevokeBefore: before, Reason: domain.RevokeReasonAdminForceLogout,
	}, domain.UserID("usr-admin-z")))
	blockPerson(t, ctx, pool, user)
	return ctx, pool, user, before
}

// KN-SCL-06 — блокировка человека с моментом раньше стоящего не меняет вторую запись.
func TestSubjectCutoff_KN_SCL_06_LosingPersonBlockKeepsTheStandingRecord(t *testing.T) {
	ctx, pool, user, before := personBlockScene(t, "scl06", time.Hour)
	requireRowEqual(t, readSecondRecord(t, ctx, pool, user),
		before, domain.RevokeReasonAdminForceLogout, "usr-admin-z",
		"проигравшая блокировка переписала вторую запись")
	requireRowEqual(t, readFirstRecord(t, ctx, pool, user),
		before, domain.RevokeReasonAdminForceLogout, "usr-admin-z",
		"первая запись тронута блокировкой")
}

// KN-SCL-19 — близнец 06: блокировка человека с моментом позже стоящего берёт свои значения.
func TestSubjectCutoff_KN_SCL_19_WinningPersonBlockTakesItsOwnValues(t *testing.T) {
	ctx, pool, user, before := personBlockScene(t, "scl19", -time.Hour)
	got := readSecondRecord(t, ctx, pool, user)
	require.True(t, got.Present)
	require.True(t, got.Before.After(before), "момент не сдвинут на момент блокировки")
	require.Equal(t, ownerGoneReason, got.Reason)
	require.Equal(t, ownerGoneDecider, got.Decider)
	requireRowEqual(t, readFirstRecord(t, ctx, pool, user),
		before, domain.RevokeReasonAdminForceLogout, "usr-admin-z",
		"первая запись тронута блокировкой")
}
