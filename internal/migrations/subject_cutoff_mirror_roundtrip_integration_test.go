// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_cutoff_mirror_roundtrip_integration_test.go — НАКАТ ЗЕРКАЛА ОТСЕЧКИ
// ПРИВОДИТ ЛЕЖАЩИЕ СТРОКИ; ОТКАТ И ПОВТОРНЫЙ НАКАТ СХОДЯТСЯ (kaname#336;
// приёмка `docs/engineering/acceptance/subject-cutoff-writes-both-records-under-one-lock.md`,
// KN-SCL-13, решения Р4 и Р5).
//
// Сцена сеется на версии, ПРЕДШЕСТВУЮЩЕЙ предмету: только там можно положить
// первую запись без второй — после наката это делает невозможным само зеркало.
// Утверждается состояние строк после каждого шага, а не прохождение шагов:
// пустой `Down` тоже «проходит».

package migrations_test

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// subjectCutoffMirrorVersion — версия предмета, ЧИСЛОМ: положение в каталоге
// меняется с каждой следующей миграцией, число — нет.
const subjectCutoffMirrorVersion int64 = 20261003202945

// sclRow — строка записи отсечки: момент, причина, решивший (у первой записи
// NULL читается пустой строкой с признаком `null`).
type sclRow struct {
	present bool
	before  time.Time
	reason  string
	decider string
	null    bool
}

func sclSecond(t *testing.T, db *sql.DB, subject string) sclRow {
	t.Helper()
	var r sclRow
	err := db.QueryRow(`SELECT revoke_before, reason, revoked_by FROM kaname.minted_token_revocations WHERE subject = $1`,
		subject).Scan(&r.before, &r.reason, &r.decider)
	if err == sql.ErrNoRows {
		return r
	}
	require.NoError(t, err)
	r.present = true
	r.before = r.before.UTC()
	return r
}

func sclFirst(t *testing.T, db *sql.DB, user string) sclRow {
	t.Helper()
	var r sclRow
	var by sql.NullString
	err := db.QueryRow(`SELECT revoke_before, reason, revoked_by_user_id FROM kaname.user_token_revocations WHERE user_id = $1`,
		user).Scan(&r.before, &r.reason, &by)
	if err == sql.ErrNoRows {
		return r
	}
	require.NoError(t, err)
	r.present, r.decider, r.null = true, by.String, !by.Valid
	r.before = r.before.UTC()
	return r
}

func sclPutFirst(t *testing.T, db *sql.DB, user string, at time.Time, reason, decider string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO kaname.user_token_revocations (user_id, revoke_before, reason, revoked_by_user_id)
		VALUES ($1, $2, $3, NULLIF($4, ''))`, user, at, reason, decider)
	require.NoError(t, err, "посев первой записи %s", user)
}

func sclPutSecond(t *testing.T, db *sql.DB, subject string, at time.Time, reason, decider string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
		VALUES ($1, $2, $3, $4)`, subject, at, reason, decider)
	require.NoError(t, err, "посев второй записи %s", subject)
}

func sclFunctionDefs(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, fn := range []string{"kaname.minted_cutoff_on_client_removal()", "kaname.minted_cutoff_on_owner_deactivation()"} {
		var def string
		require.NoError(t, db.QueryRow(`SELECT pg_get_functiondef($1::regprocedure)`, fn).Scan(&def))
		out[fn] = def
	}
	return out
}

func requireSclRow(t *testing.T, got sclRow, at time.Time, reason, decider, why string) {
	t.Helper()
	require.True(t, got.present, "%s: записи нет", why)
	require.True(t, got.before.Equal(at), "%s: момент %s, ожидался %s", why, got.before, at)
	require.Equal(t, reason, got.reason, "%s: причина", why)
	require.Equal(t, decider, got.decider, "%s: решивший", why)
}

// KN-SCL-13 — накат приводит лежащие строки; откат и повторный накат сходятся.
func TestSubjectCutoff_KN_SCL_13_ApplyConvergesRowsAndTheRoundTripHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", subjectCutoffMirrorVersion-1))
	pre, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Less(t, pre, subjectCutoffMirrorVersion, "сцена обязана сеяться ДО предмета")

	// Люди A…G — члены одного аккаунта; учётка S в нём же.
	people := map[string]string{}
	for _, k := range []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "O"} {
		people[k] = "usr" + "scl13" + "00000000000" + k
	}
	account := "acc" + "scl13" + "000000000000"
	sva := "sva" + "scl13" + "000000000000"
	tx, err := db.Begin()
	require.NoError(t, err)
	for k, id := range people {
		_, err = tx.Exec(`INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
			VALUES ($1, $2, $3, 'scl13', $4, 'ACTIVE')`, id, "ext-scl13-"+k, "scl13-"+k+"@example.invalid", account)
		require.NoError(t, err)
	}
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, 'acc-scl13', $2)`, account, people["O"])
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	_, err = db.Exec(`INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, 'scl13-sva')`, sva, account)
	require.NoError(t, err)

	t1 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	t3 := t2.Add(time.Hour)
	t4 := t3.Add(time.Hour)
	A, B, C, D, E := people["A"], people["B"], people["C"], people["D"], people["E"]

	sclPutFirst(t, db, A, t1, "logout", "") // (а) только первая
	sclPutFirst(t, db, B, t2.Add(time.Minute), "password-change", "usr-admin-b")
	sclPutSecond(t, db, B, t2, "logout", "kaname:logout") // (б) вторая отстаёт
	sclPutFirst(t, db, C, t3, "logout", "")
	sclPutSecond(t, db, C, t3.Add(time.Minute), "owner is no longer active", "kaname:owner-deactivated") // (в) вторая впереди
	sclPutFirst(t, db, D, t4, "logout", "")
	sclPutSecond(t, db, D, t4, "password-change", "kaname:password-change")               // (г) равные моменты
	sclPutSecond(t, db, E, t4, "owner is no longer active", "kaname:owner-deactivated")   // (д) только вторая
	sclPutSecond(t, db, sva, t4, "owner is no longer active", "kaname:owner-deactivated") // (е) учётка
	// (ж) только первая, решившего нет, а причина длинная — так писал писатель
	// до двери #313. Имя механизма `'kaname:' || reason` у причины в 122 знака
	// заняло бы 129 при пределе второй записи 128: приведение не может назвать
	// решившим его и называет общий механизм отсечки, причину перенося целиком.
	// Отказ здесь отверг бы накат ЦЕЛИКОМ — ни одна строка не была бы приведена.
	// Близнец (з) — причина в 121 знак: имя в 128 знаков ложится, выводится из
	// причины, как у (а).
	H, I := people["H"], people["I"]
	longReason := strings.Repeat("r", 122)
	edgeReason := strings.Repeat("e", 121)
	sclPutFirst(t, db, H, t1, longReason, "") // (ж) имя механизма не помещается
	sclPutFirst(t, db, I, t1, edgeReason, "") // (з) имя механизма ровно на пределе
	require.False(t, sclSecond(t, db, A).present, "посылка сцены: до предмета зеркала нет")

	defsBefore := sclFunctionDefs(t, db)

	// ── НАКАТ ──
	require.NoError(t, goose.UpTo(db, ".", subjectCutoffMirrorVersion))
	v, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, subjectCutoffMirrorVersion, v, "миграции предмета в каталоге нет")

	wantAfter := func(why string) {
		requireSclRow(t, sclSecond(t, db, A), t1, "logout", "kaname:logout", why+": (а) вторая из первой")
		requireSclRow(t, sclSecond(t, db, B), t2.Add(time.Minute), "password-change", "usr-admin-b", why+": (б) вторая догнала первую")
		requireSclRow(t, sclSecond(t, db, H), t1, longReason, "kaname:subject-cutoff", why+": (ж) длинная причина, общий механизм")
		requireSclRow(t, sclSecond(t, db, I), t1, edgeReason, "kaname:"+edgeReason, why+": (з) имя механизма на пределе")
		requireSclRow(t, sclSecond(t, db, C), t3.Add(time.Minute), "owner is no longer active", "kaname:owner-deactivated", why+": (в) не тронута")
		requireSclRow(t, sclSecond(t, db, D), t4, "password-change", "kaname:password-change", why+": (г) не тронута")
		requireSclRow(t, sclSecond(t, db, E), t4, "owner is no longer active", "kaname:owner-deactivated", why+": (д) не тронута")
		requireSclRow(t, sclSecond(t, db, sva), t4, "owner is no longer active", "kaname:owner-deactivated", why+": (е) не тронута")
		require.False(t, sclFirst(t, db, E).present, why+": (д) первая запись появилась")
		require.False(t, sclFirst(t, db, sva).present, why+": (е) первая запись появилась")
		requireSclRow(t, sclFirst(t, db, B), t2.Add(time.Minute), "password-change", "usr-admin-b", why+": (б) первая тронута")
	}
	wantAfter("после наката")

	// ── ОТКАТ ──
	require.NoError(t, goose.DownTo(db, ".", subjectCutoffMirrorVersion-1), "откат обязан проходить")
	v, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Less(t, v, subjectCutoffMirrorVersion)
	require.Equal(t, defsBefore, sclFunctionDefs(t, db), "откат не вернул прежние определения функций")
	F := people["F"]
	sclPutFirst(t, db, F, t1, "logout", "")
	require.False(t, sclSecond(t, db, F).present, "после отката зеркало осталось")
	wantAfter("после отката")

	// ── ПОВТОРНЫЙ НАКАТ ──
	require.NoError(t, goose.UpTo(db, ".", subjectCutoffMirrorVersion), "повторный накат обязан проходить")
	wantAfter("после повторного наката")
	G := people["G"]
	sclPutFirst(t, db, G, t2, "logout", "")
	requireSclRow(t, sclSecond(t, db, G), t2, "logout", "kaname:logout", "после повторного наката зеркала нет")
}
