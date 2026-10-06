// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_admission_schema_integration_test.go — схема почты личности на ленте
// notify (задача kaname#484, полоса F1 маршрута kacho#2917; приёмка NTF-2,
// сценарий NTF2-44; замысел §6 «Схема БД», З11, З12, З14, З16, З18, З24).
//
// # Предмет
//
// Почта kaname уходит строкой ленты `notify`, а окно адресата считается по
// хранимым моментам. Инварианты этих таблиц держит база, а не код:
//
//   - момент окна не существует без строки ленты своей транзакции — `feed_id
//     NOT NULL` и непустой (CX2-32);
//   - якорь окна не снимается, пока у ключа есть момент или ожидающая запись
//     регистрации — внешние ключи `ON DELETE RESTRICT` (CX2-35 (а));
//   - код однозначно указывает запись адреса — `UNIQUE (address_digest,
//     code_digest)` (CX2-33);
//   - у счёта актов приглашения внешних ключей НЕТ: удаление аккаунта счёт не
//     уменьшает (CX2-21);
//   - акт «с письмом» несёт строку ленты, акт без письма — нет;
//   - живой код у человека один — частичный `UNIQUE` (З12);
//   - одно событие аудита — не больше одной строки на (шаблон, адресат) (И11).
//
// Каждое отрицание стоит в паре с законным близнецом, отличающимся ОДНИМ фактом:
// иначе отказ базы был бы неотличим от отказа, вызванного формой самой пробы.
//
// # Чего здесь нет и почему
//
// Утверждение NTF2-44 «таблицы `kaname.invite_mail_outbox` нет» здесь НЕ стоит.
// Таблицы очереди и окон прежней почты читает и пишет живой код службы
// (отправитель, транзакция окна, репозитории кодов, реестр уборки); их снятие —
// фаза сужения, и она садится одним изменением с переписью этих потребителей
// (замысел З6, полоса S8). Здесь — фаза расширения: лента и новые таблицы.
package migrations_test

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// mailAdmissionMigration — файл, заводящий таблицы почты личности. Имя стоит
// литералом: мир «база перед миграцией» строится остановкой цепи на версии
// перед ним, и переезд файла в другую версию обязан ронять пробу.
const mailAdmissionMigration = "20261006151313_mail_admission_moments_and_one_live_recovery_code.sql"

// kanameFeedTable — таблица ленты kaname, как её называет corelib notify/feed
// для префикса `kaname.kaname` (схема kaname, служба kaname).
const kanameFeedTable = "kaname_notification_outbox"

func mailAdmissionVersion(t *testing.T) int64 {
	t.Helper()
	head, _, ok := strings.Cut(mailAdmissionMigration, "_")
	require.True(t, ok, "имя файла без версии: %s", mailAdmissionMigration)
	v, err := strconv.ParseInt(head, 10, 64)
	require.NoError(t, err)
	return v
}

// mwOpen — пустая база службы.
func mwOpen(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	return db
}

// mwHead — база, накатанная всей цепью службы. Несущее утверждение о предмете
// (файл в цепи) идёт ПОСЛЕ построения мира: пробы красны им, а не поломкой
// контейнера.
func mwHead(t *testing.T) *sql.DB {
	t.Helper()
	db := mwOpen(t)
	require.NoError(t, goose.Up(db, "."), "цепь службы обязана накатываться на пустую базу")
	_, err := fs.Stat(migrations.FS, mailAdmissionMigration)
	require.NoError(t, err, "миграции почты личности нет в цепи службы (%s)", mailAdmissionMigration)
	return db
}

// mwSQLState — код отказа базы; пустая строка — отказа базы не было.
func mwSQLState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func mwDigest(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func mwAnchor(t *testing.T, db *sql.DB, purpose string) []byte {
	t.Helper()
	key := mwDigest(t)
	_, err := db.Exec(`INSERT INTO kaname.mail_windows (purpose, key_digest, created_at) VALUES ($1, $2, now())`, purpose, key)
	require.NoError(t, err)
	return key
}

func mwMoment(db *sql.DB, purpose string, key []byte, feedID any) error {
	_, err := db.Exec(`INSERT INTO kaname.mail_window_letters (id, purpose, key_digest, kind, at, feed_id)
		VALUES ($1, $2, $3, 'progression', now(), $4)`, ids.NewID("mwl"), purpose, key, feedID)
	return err
}

func mwPending(db *sql.DB, key, address, code []byte) error {
	_, err := db.Exec(`INSERT INTO kaname.pending_registrations
		(id, key_digest, address_digest, password_hash, password_probe, code_digest, created_at, expires_at)
		VALUES ($1, $2, $3, 'hash', $4, $5, now(), now() + interval '1 hour')`,
		ids.NewID("prg"), key, address, address, code)
	return err
}

func mwInviteAct(db *sql.DB, lettered bool, feedID any) error {
	_, err := db.Exec(`INSERT INTO kaname.invite_acts (id, account_id, kind, key_digest, at, lettered, feed_id)
		VALUES ($1, $2, 'invite', $3, now(), $4, $5)`,
		ids.NewID("iac"), ids.NewID(domain.PrefixAccount), make([]byte, 32), lettered, feedID)
	return err
}

// TestIntegration_NTF2_44_FeedTableIsCreatedByTheChain — вторая половина NTF2-44,
// сторона «таблица ленты есть»: после всей цепи на пустой базе лента kaname
// существует. Контроль в другую сторону — таблицы ленты нет на версии перед
// первой миграцией ленты, иначе «завела цепь» было бы неотличимо от «лежало».
func TestIntegration_NTF2_44_FeedTableIsCreatedByTheChain(t *testing.T) {
	db := mwOpen(t)
	require.NoError(t, goose.UpTo(db, ".", 1), "базовая миграция обязана накатываться")
	require.False(t, regclassPresent(t, db, kanameFeedTable), "лента есть уже в базовой миграции — контроль не различает")

	require.NoError(t, goose.Up(db, "."))
	require.True(t, regclassPresent(t, db, kanameFeedTable),
		"после всей цепи таблицы ленты kaname.%s нет: kaname нечем ставить письма в ленту notify", kanameFeedTable)
	for _, aux := range []string{"kaname_notification_window", "kaname_notification_contrib"} {
		require.True(t, regclassPresent(t, db, aux), "после всей цепи нет таблицы ленты kaname.%s", aux)
	}
}

// TestIntegration_MailWindowMomentCarriesItsFeedRow — момент окна без строки
// ленты своей транзакции невыразим (CX2-32): NULL и пустая строка отвергнуты,
// близнец с идентификатором строки ленты проходит.
func TestIntegration_MailWindowMomentCarriesItsFeedRow(t *testing.T) {
	db := mwHead(t)
	key := mwAnchor(t, db, "recovery")

	require.NoError(t, mwMoment(db, "recovery", key, "ntf-feed-row-1"), "законный момент обязан записываться")
	require.Equal(t, "23502", mwSQLState(mwMoment(db, "recovery", key, nil)), "момент без строки ленты (NULL) обязан отвергаться базой")
	require.Equal(t, "23514", mwSQLState(mwMoment(db, "recovery", key, "")), "момент с пустым feed_id обязан отвергаться базой")
}

// TestIntegration_CX2_35_AnchorWithALiveMomentOrRecordCannotBeRemoved — снятие
// якоря с живым моментом или ожидающей записью отвергает база (RESTRICT, не
// CASCADE). Близнец — якорь без зависимых строк снимается.
func TestIntegration_CX2_35_AnchorWithALiveMomentOrRecordCannotBeRemoved(t *testing.T) {
	db := mwHead(t)
	del := func(purpose string, key []byte) error {
		_, err := db.Exec(`DELETE FROM kaname.mail_windows WHERE purpose = $1 AND key_digest = $2`, purpose, key)
		return err
	}

	withMoment := mwAnchor(t, db, "verification")
	require.NoError(t, mwMoment(db, "verification", withMoment, "ntf-feed-row-2"))
	require.Equal(t, "23503", mwSQLState(del("verification", withMoment)), "якорь с живым моментом снят — уборка уменьшила окно")

	withRecord := mwAnchor(t, db, "registration")
	require.NoError(t, mwPending(db, withRecord, mwDigest(t), mwDigest(t)))
	require.Equal(t, "23503", mwSQLState(del("registration", withRecord)), "якорь с ожидающей записью снят")

	bare := mwAnchor(t, db, "recovery")
	require.NoError(t, del("recovery", bare), "якорь без моментов и записей обязан сниматься")
	var left int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.mail_windows WHERE key_digest = $1`, bare).Scan(&left))
	require.Zero(t, left)
}

// TestIntegration_CX2_33_CodePointsToOneAddressRecord — вторая запись адреса с
// тем же code_digest отвергнута; близнец — тот же адрес с другим кодом проходит.
func TestIntegration_CX2_33_CodePointsToOneAddressRecord(t *testing.T) {
	db := mwHead(t)
	key := mwAnchor(t, db, "registration")
	address, code := mwDigest(t), mwDigest(t)

	require.NoError(t, mwPending(db, key, address, code))
	require.NoError(t, mwPending(db, key, address, mwDigest(t)), "тот же адрес с другим кодом — законная вторая запись")
	require.Equal(t, "23505", mwSQLState(mwPending(db, key, address, code)), "вторая запись адреса с тем же кодом обязана отвергаться")
}

// TestIntegration_InviteActLetteredCarriesItsFeedRow — акт «с письмом» без строки
// ленты и акт «без письма» со строкой ленты отвергнуты; близнецы проходят.
func TestIntegration_InviteActLetteredCarriesItsFeedRow(t *testing.T) {
	db := mwHead(t)

	require.NoError(t, mwInviteAct(db, true, "ntf-feed-row-3"))
	require.NoError(t, mwInviteAct(db, false, nil))
	require.Equal(t, "23514", mwSQLState(mwInviteAct(db, true, nil)), "акт с письмом без feed_id обязан отвергаться")
	require.Equal(t, "23514", mwSQLState(mwInviteAct(db, false, "ntf-feed-row-4")), "акт без письма с feed_id обязан отвергаться")
	require.Equal(t, "23514", mwSQLState(mwInviteAct(db, true, "")), "акт с письмом и пустым feed_id обязан отвергаться")
}

// TestIntegration_CX2_21_InviteActsHaveNoForeignKeys — у счёта актов внешних
// ключей 0 по pg_constraint. Контроль — тот же запрос видит внешний ключ
// mail_window_letters: ноль означает «нет ключей», а не «запрос их не видит».
func TestIntegration_CX2_21_InviteActsHaveNoForeignKeys(t *testing.T) {
	db := mwHead(t)
	fks := func(table string) int {
		var n int
		require.NoError(t, db.QueryRow(`
			SELECT count(*) FROM pg_constraint
			 WHERE contype = 'f' AND conrelid = to_regclass('kaname.' || $1)`, table).Scan(&n))
		return n
	}
	require.Equal(t, 1, fks("mail_window_letters"), "контроль: запрос обязан видеть внешний ключ моментов на якорь")
	require.Zero(t, fks("invite_acts"), "у invite_acts есть внешний ключ — удаление аккаунта уменьшит счёт приглашений (CX2-21)")

	// Удаление аккаунта счёт не трогает ни при каком состоянии: акт на аккаунт,
	// которого в базе нет, записывается.
	require.NoError(t, mwInviteAct(db, false, nil))
}

// TestIntegration_OneLiveCodePerPerson — частичные UNIQUE живого кода
// отвергают вторую живую строку у обоих видов кода; близнец — вторая строка при
// применённой (recovery) либо вытесненной (verification) первой проходит.
func TestIntegration_OneLiveCodePerPerson(t *testing.T) {
	db := mwHead(t)
	uid := seedOwner(t, db, "mw1")
	now := time.Now().UTC()
	digestHex := func() string { return hex.EncodeToString(mwDigest(t)) }

	recovery := func(consumed bool) error {
		var consumedAt any
		if consumed {
			consumedAt = now
		}
		_, err := db.Exec(`INSERT INTO kaname.recovery_codes (id, user_id, code_digest, issued_at, expires_at, consumed_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, ids.NewID("rcd"), uid, digestHex(), now, now.Add(time.Hour), consumedAt)
		return err
	}
	require.NoError(t, recovery(true))
	require.NoError(t, recovery(false), "живой код при применённом прежнем — законен")
	require.Equal(t, "23505", mwSQLState(recovery(false)), "второй живой код восстановления обязан отвергаться")

	verification := func(superseded bool) error {
		var supersededAt any
		if superseded {
			supersededAt = now
		}
		_, err := db.Exec(`INSERT INTO kaname.email_verification_codes
			(id, user_id, email, code_digest, issued_at, expires_at, superseded_at)
			VALUES ($1, $2, 'mw1@example.invalid', $3, $4, $5, $6)`, ids.NewID("evc"), uid, digestHex(), now, now.Add(time.Hour), supersededAt)
		return err
	}
	require.NoError(t, verification(true))
	require.NoError(t, verification(false), "живой код при вытесненном прежнем — законен")
	require.Equal(t, "23505", mwSQLState(verification(false)), "второй живой код подтверждения обязан отвергаться")

	// Код восстановления кончается одним способом: применённый не вытесняется.
	_, err := db.Exec(`UPDATE kaname.recovery_codes SET superseded_at = consumed_at WHERE user_id = $1 AND consumed_at IS NOT NULL`, uid)
	require.Equal(t, "23514", mwSQLState(err), "код с двумя концами обязан отвергаться")
}

// TestIntegration_LiveRecoveryCodesAreNarrowedToTheLatestOnApply — база перед
// миграцией несёт у человека два живых кода восстановления (гонка двух запросов
// при прежнем коде). Накат оставляет живым самый поздний, прежний помечает
// вытесненным; у другого человека с одним живым кодом ничего не меняется.
func TestIntegration_LiveRecoveryCodesAreNarrowedToTheLatestOnApply(t *testing.T) {
	db := mwOpen(t)
	before := mailAdmissionVersion(t) - 1
	require.NoError(t, goose.UpTo(db, ".", before))
	require.False(t, regclassPresent(t, db, "mail_windows"), "якорь окна есть уже на версии %d — остановка пришлась не туда", before)

	twice, once := seedOwner(t, db, "mw2"), seedOwner(t, db, "mw3")
	base := time.Now().UTC().Add(-time.Minute)
	insert := func(uid, id string, issued time.Time) {
		_, err := db.Exec(`INSERT INTO kaname.recovery_codes (id, user_id, code_digest, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5)`, id, uid, hex.EncodeToString(mwDigest(t)), issued, issued.Add(time.Hour))
		require.NoError(t, err)
	}
	insert(twice, "rc-older", base)
	insert(twice, "rc-latest", base.Add(time.Second))
	insert(once, "rc-only", base)

	require.NoError(t, goose.UpTo(db, ".", mailAdmissionVersion(t)), "накат обязан проходить на базе с двумя живыми кодами")

	live := func(id string) bool {
		var superseded sql.NullTime
		require.NoError(t, db.QueryRow(`SELECT superseded_at FROM kaname.recovery_codes WHERE id = $1`, id).Scan(&superseded))
		return !superseded.Valid
	}
	require.False(t, live("rc-older"), "прежний живой код обязан стать вытесненным")
	require.True(t, live("rc-latest"), "самый поздний код обязан остаться живым")
	require.True(t, live("rc-only"), "единственный живой код другого человека тронут")
}

// TestIntegration_MailAdmissionSchemaKeepsItsSmallerInvariants — метка
// устройства уникальна и убирается по моменту выдачи; строка извещения
// безопасности одна на (событие, шаблон, адресат).
func TestIntegration_MailAdmissionSchemaKeepsItsSmallerInvariants(t *testing.T) {
	db := mwHead(t)
	uid := seedOwner(t, db, "mw4")
	label := mwDigest(t)
	device := func(l []byte) error {
		_, err := db.Exec(`INSERT INTO kaname.trusted_devices (id, user_id, label_digest, issued_at) VALUES ($1, $2, $3, now())`,
			ids.NewID("tdv"), uid, l)
		return err
	}
	require.NoError(t, device(label))
	require.NoError(t, device(mwDigest(t)), "вторая метка с другим значением — законна")
	require.Equal(t, "23505", mwSQLState(device(label)), "метка с тем же значением обязана отвергаться")

	var issuedIdx int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM pg_indexes WHERE schemaname = 'kaname'
		AND tablename = 'trusted_devices' AND indexdef LIKE '%(issued_at)%'`).Scan(&issuedIdx))
	require.Equal(t, 1, issuedIdx, "уборке меток по сроку нужен индекс по issued_at")

	notice := func(template string) (int64, error) {
		res, err := db.Exec(`INSERT INTO kaname.security_notice_ledger (audit_event_id, template, recipient_user_id, created_at)
			VALUES ('aud-1', $1, $2, now()) ON CONFLICT DO NOTHING`, template, uid)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	n, err := notice("password-changed")
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	n, err = notice("password-changed")
	require.NoError(t, err)
	require.EqualValues(t, 0, n, "второе извещение по тому же событию и адресату обязано быть отброшено")
	n, err = notice("second-factor-removed")
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "другой шаблон того же события — законная строка")
}

// TestIntegration_MailAdmissionMigrationRollsBackAndForward — откат снимает
// ровно свой предмет, повторный накат проходит.
func TestIntegration_MailAdmissionMigrationRollsBackAndForward(t *testing.T) {
	db := mwHead(t)
	own := mailAdmissionVersion(t)
	require.NoError(t, goose.DownTo(db, ".", own-1))
	for _, table := range []string{"mail_windows", "mail_window_letters", "pending_registrations",
		"invite_acts", "trusted_devices", "security_notice_ledger"} {
		require.False(t, regclassPresent(t, db, table), "откат оставил kaname.%s", table)
	}
	var col int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'kaname' AND table_name = 'recovery_codes' AND column_name = 'superseded_at'`).Scan(&col))
	require.Zero(t, col, "откат оставил recovery_codes.superseded_at")
	require.True(t, regclassPresent(t, db, "recovery_codes"), "откат обязан снять только свой предмет")

	require.NoError(t, goose.Up(db, "."), "цепь обязана накатываться снова")
	require.True(t, regclassPresent(t, db, "mail_windows"))
}
