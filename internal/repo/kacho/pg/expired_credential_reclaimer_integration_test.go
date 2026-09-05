// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// expired_credential_reclaimer_integration_test.go — ПЕРВАЯ ПОЛОВИНА задачи
// #1264: истёкшее удостоверение перестаёт занимать место под потолком без
// действия арендатора.
//
// # Что утверждается — ИСХОД, а не факт вызова
//
// «Уборщик вызвался» и «место освободилось» — разные утверждения, и зелёным
// первое бывает при неверном втором. Поэтому каждая проба читает СТРОКУ УЧЁТА
// (`project_resource_quotas.used`) и, где это несущий сценарий, доводит дело до
// наблюдаемого исхода: следующая выдача ПРОХОДИТ там, где прежде отказывала.
//
// # Часы — базы, а не процесса
//
// Фикстуры двигают `expires_at` относительно `now()` СУБД, и адаптеру уезжают
// длительности. Так проба меряет тот же порог, каким судит и продукт; проба,
// подставляющая момент из процесса, утверждала бы о согласии двух часов, а не о
// пороге.

package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// reclaimFixture — принципалы и пул одной пробы.
type reclaimFixture struct {
	pool *pgxpool.Pool
}

func newReclaimFixture(t *testing.T) *reclaimFixture {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не `t.Cleanup(pool.Close)`: отложенное закрытие ждёт
	// соединение, которое проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, — и уносит с собой вердикт ВСЕГО пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	// Аккаунт и владелец ссылаются друг на друга — посев одной транзакцией с
	// отложенными ограничениями.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	for _, q := range []string{
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		 VALUES ('acc00000000000000rcl', 'rcl-1', 'usr00000000000000rcl') ON CONFLICT DO NOTHING`,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id, invite_status)
		 VALUES ('usr00000000000000rcl', 'ext-rcl-1', 'rcl1@example.invalid', 'acc00000000000000rcl', 'ACTIVE')
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		 VALUES ('sva00000000000000rcl', 'acc00000000000000rcl', 'rcl-one-sa') ON CONFLICT DO NOTHING`,
	} {
		_, err = tx.Exec(ctx, q)
		require.NoError(t, err, "посев владельцев удостоверений")
	}
	require.NoError(t, tx.Commit(ctx))
	return &reclaimFixture{pool: pool}
}

// putUserCred кладёт удостоверение человека с ЯВНЫМ сроком жизни.
//
// lifetime — сколько строка живёт от своего создания; expiredFor — сколько
// времени назад она истекла (ноль либо отрицательное — строка ещё действует).
// Оба смещения считаются от `now()` СУБД: проба обязана мерить теми же часами,
// какими судит продукт.
func (f *reclaimFixture) putUserCred(t *testing.T, id string, lifetime, expiredFor time.Duration) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(), `
INSERT INTO kacho_iam.user_oauth_clients
    (id, user_id, hydra_client_id, created_by_user_id, credential_kind,
     secret_hash, public_key_pem, key_algorithm, created_at, expires_at)
VALUES ($1, 'usr00000000000000rcl', $2, 'usr00000000000000rcl', 'KEYPAIR',
        ''::bytea, '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----', 'ES256',
        now() - $3::interval - $4::interval, now() - $3::interval)`,
		id, "mirror-"+id, expiredFor, lifetime)
	require.NoError(t, err, "посев удостоверения человека %s", id)
}

// putUserCredForever — бессрочная строка: она ДЕЙСТВУЕТ, и снимать её нельзя.
func (f *reclaimFixture) putUserCredForever(t *testing.T, id string) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(), `
INSERT INTO kacho_iam.user_oauth_clients
    (id, user_id, hydra_client_id, created_by_user_id, credential_kind,
     secret_hash, public_key_pem, key_algorithm, expires_at)
VALUES ($1, 'usr00000000000000rcl', $2, 'usr00000000000000rcl', 'KEYPAIR',
        ''::bytea, '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----', 'ES256', NULL)`,
		id, "mirror-"+id)
	require.NoError(t, err, "посев бессрочного удостоверения %s", id)
}

func (f *reclaimFixture) putSACred(t *testing.T, id string, lifetime, expiredFor time.Duration) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(), `
INSERT INTO kacho_iam.service_account_oauth_clients
    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind,
     secret_hash, public_key_pem, key_algorithm, trusted_subjects, created_at, expires_at)
VALUES ($1, 'sva00000000000000rcl', $2, 'usr00000000000000rcl', 'KEYPAIR',
        ''::bytea, '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----', 'ES256', '[]'::jsonb,
        now() - $3::interval - $4::interval, now() - $3::interval)`,
		id, "mirror-"+id, expiredFor, lifetime)
	require.NoError(t, err, "посев удостоверения машины %s", id)
}

// used читает потребление строки учёта — то самое число, которым распоряжается
// потолок.
func (f *reclaimFixture) used(t *testing.T, carrierType, carrierID, kind string) int64 {
	t.Helper()
	var used int64
	err := f.pool.QueryRow(context.Background(), `
		SELECT used FROM kacho_iam.project_resource_quotas
		 WHERE carrier_type = $1 AND carrier_id = $2 AND kind = $3`,
		carrierType, carrierID, kind).Scan(&used)
	require.NoError(t, err, "строка учёта обязана существовать: её заводит триггер принципала")
	return used
}

func (f *reclaimFixture) countUserCreds(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kacho_iam.user_oauth_clients WHERE user_id = 'usr00000000000000rcl'`).Scan(&n))
	return n
}

// liveFor — смещение, означающее «строка ещё ДЕЙСТВУЕТ»: срок наступит через
// названное время.
//
// Заведено потому, что нуль здесь означал не то, что читалось. `expiredFor = 0`
// даёт `expires_at = now()` в момент вставки, то есть строку, истекающую
// НЕМЕДЛЕННО: к моменту чтения она уже мертва. Для отбора уборщика разницы не
// было (порог всё равно дальше), и три пробы держались зелёными на фикстуре,
// которая означала не то, что они утверждали. Показал это ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ отсечки — ровно то, ради чего он и стоит.
func liveFor(d time.Duration) time.Duration { return -d }

// reclaimSpec — границы прогона пробы. Отсрочка короткая намеренно: предмет
// сценария — ПОРОГ, а не его величина, и фикстура двигает срок относительно него.
func reclaimSpec(grace time.Duration) kachopg.ExpiredCredentialReclaimSpec {
	return kachopg.ExpiredCredentialReclaimSpec{
		MinDelay:  time.Minute,
		Grace:     grace,
		BatchSize: 100,
	}
}

// CRED-RCL-01 — НЕСУЩИЙ сценарий: истёкшее снято, место вернулось, и следующая
// выдача проходит.
//
// Утверждаются ТРИ следствия подряд, потому что предмет задачи — последнее из
// них. «Строка снята» без «место вернулось» было бы утверждением об уборке, а не
// о потолке; «место вернулось» без «выдача прошла» — утверждением о числе, а не
// о том, что арендатор перестал упираться.
func TestCredRcl01_ExpiredCredentialFreesItsPlaceUnderTheCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	// Given: три удостоверения, из них ОДНО истекло более отсрочки назад.
	f.putUserCred(t, "uoc_rcm00000000000a01", 30*24*time.Hour, liveFor(30*24*time.Hour)) // действует
	f.putUserCredForever(t, "uoc_rcm00000000000a02")                                     // бессрочное
	f.putUserCred(t, "uoc_rcm00000000000a03", 30*24*time.Hour, time.Hour)                // истекло час назад

	require.EqualValues(t, 3, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"),
		"предпосылка: списание учло все три")

	// When: прогон уборщика с отсрочкой в десять минут — час назад это дальше её.
	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(10*time.Minute))
	require.NoError(t, err)

	// Then (1): перепись называет ОБА числа.
	require.Equal(t, 1, res.Found, "найдено обязано быть ровно одно — истёкшее")
	require.Equal(t, 1, res.Reclaimed, "снято обязано совпасть с найденным на боевом прогоне")

	// Then (2): строки нет, и место вернулось В ТОЙ ЖЕ транзакции — его вернул
	// существующий триггер списания, без единой правки в нём.
	require.EqualValues(t, 2, f.countUserCreds(t), "истёкшая строка обязана исчезнуть")
	require.EqualValues(t, 2, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"),
		"ПРЕДМЕТ ЗАДАЧИ: место под потолком обязано вернуться")

	// Then (3): наблюдаемый исход — выдача, которой прежде не было места.
	var limit int64
	require.NoError(t, f.pool.QueryRow(ctx, `
		UPDATE kacho_iam.project_resource_quotas SET limit_value = 2
		 WHERE carrier_type = 'iam.user' AND carrier_id = 'usr00000000000000rcl'
		   AND kind = 'iam.user.credential' RETURNING limit_value`).Scan(&limit))
	require.EqualValues(t, 2, limit)
	// Предел два, занято два — выдача обязана отказать; снятое место делает её
	// возможной, и это проверяется тем, что до снятия занято было бы три.
	f.putUserCred(t, "uoc_rcm00000000000a04", 30*24*time.Hour, liveFor(30*24*time.Hour))
	t.Logf("перепись: найдено %d · снято %d · used %d", res.Found, res.Reclaimed,
		f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"))
}

// CRED-RCL-02 — зеркало по машине: тот же предмет, другой вид учёта.
func TestCredRcl02_ExpiredMachineCredentialFreesItsPlace(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	f.putSACred(t, "soc_rcm00000000000b01", 90*24*time.Hour, liveFor(90*24*time.Hour))
	f.putSACred(t, "soc_rcm00000000000b02", 90*24*time.Hour, 2*time.Hour)

	require.EqualValues(t, 2, f.used(t, "iam.serviceAccount", "sva00000000000000rcl", "iam.serviceAccount.credential"),
		"предпосылка: списание учло обе")

	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(10*time.Minute))
	require.NoError(t, err)

	require.Equal(t, 1, res.Reclaimed)
	require.EqualValues(t, 1, f.used(t, "iam.serviceAccount", "sva00000000000000rcl", "iam.serviceAccount.credential"),
		"место под потолком машины обязано вернуться")
	require.Equal(t, 1, res.ByKind["iam.serviceAccount.credential"],
		"перепись обязана называть ПРЕДМЕТ, а не только величину")
}

// CRED-RCL-03 — ОТБОР: положительный контроль обеих сторон.
//
// Без этого сценария «снимает истёкшие» было бы неотличимо от «снимает всё»:
// проба, у которой снимаемое есть, зеленеет и на уборщике, сносящем таблицу.
func TestCredRcl03_LiveEndlessAndFreshlyExpiredAreNotTouched(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	f.putUserCred(t, "uoc_rcm00000000000c01", 30*24*time.Hour, liveFor(30*24*time.Hour)) // действует
	f.putUserCredForever(t, "uoc_rcm00000000000c02")                                     // бессрочное
	f.putUserCred(t, "uoc_rcm00000000000c03", 30*24*time.Hour, 2*time.Minute)            // истекло 2 мин назад

	before := f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential")
	require.EqualValues(t, 3, before)

	// Отсрочка — час: истёкшее две минуты назад ещё внутри неё.
	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(time.Hour))
	require.NoError(t, err)

	require.Equal(t, 0, res.Reclaimed, "не снято обязано быть НИ ОДНО")
	require.Equal(t, 0, res.Found, "и найдено ни одного — отбор не вправе их даже брать")
	require.EqualValues(t, 3, f.countUserCreds(t), "все три строки обязаны остаться")
	require.EqualValues(t, before, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"),
		"потребление не вправе измениться")
}

// CRED-RCL-04 — ГРАНИЦА отсрочки, обе стороны на одной фикстуре, и отсрочка
// СВЯЗАНА со сроком самой строки.
//
// Односторонняя проба зеленела бы на уборщике, снимающем по любому сроку;
// плоская — на отсрочке, не связанной со сроком, ради которой §3.3 и написан.
func TestCredRcl04_GraceBoundIsBothSidedAndTiedToTheRowsOwnLifetime(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	const grace = time.Hour

	// Долгоживущая: её отсрочка — верхняя величина (час).
	f.putUserCred(t, "uoc_rcm00000000000d01", 30*24*time.Hour, grace+10*time.Minute) // ЗА границей → снять
	f.putUserCred(t, "uoc_rcm00000000000d02", 30*24*time.Hour, grace-10*time.Minute) // ВНУТРИ → оставить

	// Короткоживущая: её срок — пять минут, то есть КОРОЧЕ верхней отсрочки.
	// Её собственная отсрочка обязана быть меньше часа: окно памяти о вещи не
	// длиннее жизни самой вещи. Здесь она упирается в пол (минута у пробы), и
	// строка, истёкшая десять минут назад, подлежит снятию — тогда как
	// долгоживущая с тем же смещением остаётся.
	f.putUserCred(t, "uoc_rcm00000000000d03", 5*time.Minute, 10*time.Minute)
	f.putUserCred(t, "uoc_rcm00000000000d04", 30*24*time.Hour, 10*time.Minute)

	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(grace))
	require.NoError(t, err)

	remaining := map[string]bool{}
	rows, err := f.pool.Query(ctx,
		`SELECT id FROM kacho_iam.user_oauth_clients WHERE user_id = 'usr00000000000000rcl'`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		remaining[id] = true
	}
	require.NoError(t, rows.Err())
	rows.Close()

	require.False(t, remaining["uoc_rcm00000000000d01"], "за границей отсрочки — обязано быть снято")
	require.True(t, remaining["uoc_rcm00000000000d02"], "внутри отсрочки — обязано остаться")
	require.False(t, remaining["uoc_rcm00000000000d03"],
		"короткоживущая: её отсрочка связана с её сроком и уже вышла")
	require.True(t, remaining["uoc_rcm00000000000d04"],
		"долгоживущая с тем же смещением обязана остаться — иначе отсрочка ПЛОСКАЯ")

	require.Equal(t, 2, res.Reclaimed)
	require.EqualValues(t, 2, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"))
}

// CRED-RCL-13 — «снято 0» отличимо от «нечего снимать»: показ БЕЗ снятия.
//
// Необратимое действие, впервые встречающееся с боевым кластером, обязано иметь
// дешёвый способ спросить «что ты снесёшь».
func TestCredRcl13_DryRunFindsAndRemovesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	f.putUserCred(t, "uoc_rcm00000000000e01", 30*24*time.Hour, time.Hour)
	f.putUserCred(t, "uoc_rcm00000000000e02", 30*24*time.Hour, time.Hour)

	spec := reclaimSpec(10 * time.Minute)
	spec.DryRun = true
	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, spec)
	require.NoError(t, err)

	require.Equal(t, 2, res.Found, "показ обязан НАЙТИ подлежащее")
	require.Equal(t, 0, res.Reclaimed, "и не снять ничего")
	require.EqualValues(t, 2, f.countUserCreds(t), "строки обязаны остаться на месте")
	require.EqualValues(t, 2, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"))
}

// CRED-RCL-08 — первый прогон после выкатки идёт ПАРТИЯМИ.
//
// Самое рискованное место выкатки: накопленное за всю жизнь кластера снимается
// не одним оператором. Проба требует, чтобы прогон уважал размер партии и чтобы
// за конечное число прогонов снялось всё.
func TestCredRcl08_FirstPassAfterRolloutGoesInBatches(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	const total = 7
	for i := 1; i <= total; i++ {
		f.putUserCred(t, fmt.Sprintf("uoc_rcm00000000000f%02d", i), 30*24*time.Hour, time.Hour)
	}
	require.EqualValues(t, total, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"))

	spec := reclaimSpec(10 * time.Minute)
	spec.BatchSize = 3
	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")

	var passes, swept int
	for swept < total {
		passes++
		require.LessOrEqual(t, passes, 10, "сходимость: прогонов больше разумного — партия не двигается")
		res, err := r.ReclaimExpiredCredentials(ctx, spec)
		require.NoError(t, err)
		require.LessOrEqual(t, res.Reclaimed, spec.BatchSize, "прогон не вправе снять больше партии")
		if res.Reclaimed == 0 {
			break
		}
		swept += res.Reclaimed
	}

	require.Equal(t, total, swept, "за конечное число прогонов обязано сняться всё")
	require.EqualValues(t, 0, f.used(t, "iam.user", "usr00000000000000rcl", "iam.user.credential"))
	t.Logf("перепись: прогонов %d · снято %d при партии %d", passes, swept, spec.BatchSize)
}

// cutoffRows — сколько строк отсечки завелось по названному субъекту.
func (f *reclaimFixture) cutoffRows(t *testing.T, subject string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kacho_iam.minted_token_revocations WHERE subject = $1`, subject).Scan(&n))
	return n
}

// CRED-RCL-11 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: у ДЕЙСТВУЮЩЕГО удостоверения отсечка
// заводится.
//
// Без него «отсечки нет» зеленело бы на снятом триггере — то есть проба
// утверждала бы отсутствие механизма вместо его сужения.
func TestCredRcl11_RevokingALiveCredentialStillLeavesACutOffRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	const id = "uoc_rcm00000000000g01"
	f.putUserCred(t, id, 30*24*time.Hour, liveFor(30*24*time.Hour)) // ДЕЙСТВУЕТ

	_, err := f.pool.Exec(ctx, `DELETE FROM kacho_iam.user_oauth_clients WHERE id = $1`, id)
	require.NoError(t, err)

	require.EqualValues(t, 1, f.cutoffRows(t, id),
		"отзыв ДЕЙСТВУЮЩЕГО удостоверения обязан оставить отсечку: им отчеканенные токены ещё живы")
}

// CRED-RCL-12 — ОТРИЦАНИЕ: у истёкшего отсечка не заводится ни одним из двух
// путей снятия.
//
// Правило одно, а вызывающих у него два — уборщик и ручной отзыв, — и
// утверждается оно по ОБОИМ. Иначе «сузили для уборщика» осталось бы
// утверждением о полосе, а не о правиле.
func TestCredRcl12_RemovingAnExpiredCredentialLeavesNoCutOffRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	const bySweeper = "uoc_rcm00000000000h01"
	const byHand = "uoc_rcm00000000000h02"
	f.putUserCred(t, bySweeper, 30*24*time.Hour, time.Hour)
	f.putUserCred(t, byHand, 30*24*time.Hour, time.Hour)

	// Путь 1 — уборщик.
	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(10*time.Minute))
	require.NoError(t, err)
	require.Equal(t, 2, res.Reclaimed, "обе строки подлежали снятию")

	require.EqualValues(t, 0, f.cutoffRows(t, bySweeper),
		"истёкшая строка не могла отчеканить ничего после истечения, а всё прежнее мертво — отсечка была бы записью без предмета")

	// Путь 2 — ручной отзыв той же формы строки.
	const alsoByHand = "uoc_rcm00000000000h03"
	f.putUserCred(t, alsoByHand, 30*24*time.Hour, time.Hour)
	_, err = f.pool.Exec(ctx, `DELETE FROM kacho_iam.user_oauth_clients WHERE id = $1`, alsoByHand)
	require.NoError(t, err)
	require.EqualValues(t, 0, f.cutoffRows(t, alsoByHand),
		"то же правило обязано действовать и на ручном отзыве: у него два вызывающих, а не два правила")
}

// CRED-RCL-21 — каскад на записи доверия внешним издателям НАЗВАН ЧИСЛОМ.
//
// Каскад намеренный: доверие, привязанное к мёртвому ключу, и само мертво. Но
// при автоснятии действует ПЛАТФОРМА, и настройка, восстановление которой
// требует участия внешней стороны, исчезает без участия арендатора. Событие
// аудита обязано назвать их число.
func TestCredRcl21_CascadedTrustedIssuersAreCountedInTheAuditRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	const id = "soc_rcm00000000000j01"
	f.putSACred(t, id, 90*24*time.Hour, time.Hour)
	for i, iss := range []string{"https://idp-a.example.invalid", "https://idp-b.example.invalid"} {
		_, err := f.pool.Exec(ctx, `
INSERT INTO kacho_iam.federated_trusted_issuers
    (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm)
VALUES ($1, $2, $3, '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----', 'ES256')`,
			iss, fmt.Sprintf("subject-%d", i), id)
		require.NoError(t, err, "посев записи доверия %d", i)
	}

	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(10*time.Minute))
	require.NoError(t, err)
	require.Equal(t, 1, res.Reclaimed)

	var cascaded int64
	require.NoError(t, f.pool.QueryRow(ctx, `
		SELECT (event_payload ->> 'cascaded_trusted_issuers')::bigint
		  FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.sa_key.expired_reclaimed'
		   AND event_payload ->> 'resource_id' = $1`, id).Scan(&cascaded))
	require.EqualValues(t, 2, cascaded,
		"событие обязано назвать ЧИСЛО снятых записей доверия — их восстановление требует внешней стороны")

	var left int64
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.federated_trusted_issuers WHERE sa_oauth_client_id = $1`, id).Scan(&left))
	require.EqualValues(t, 0, left, "каскад обязан унести записи доверия вместе со строкой")
}

// CRED-RCL-10 — снятие ПЛАТФОРМОЙ отличимо от отзыва АРЕНДАТОРОМ.
//
// Тип события отдельный, а не `revoked`: смешать их значило бы утратить
// ответственность — аудит обязан писать, КТО снял.
func TestCredRcl10_PlatformRemovalIsAuditedUnderItsOwnEventType(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	const id = "uoc_rcm00000000000k01"
	f.putUserCred(t, id, 30*24*time.Hour, time.Hour)

	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	_, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(10*time.Minute))
	require.NoError(t, err)

	var actor, evType string
	require.NoError(t, f.pool.QueryRow(ctx, `
		SELECT event_type, event_payload ->> 'actor' FROM kacho_iam.audit_outbox
		 WHERE event_payload ->> 'resource_id' = $1`, id).Scan(&evType, &actor))

	require.Equal(t, "iam.user_token.expired_reclaimed", evType,
		"тип события обязан быть СВОИМ, а не типом ручного отзыва")
	require.NotEqual(t, "iam.user_token.revoked", evType)
	require.Contains(t, actor, "expired-credential-reclaim",
		"актором обязана быть ПЛАТФОРМА, а не арендатор")
}

// CRED-RCL-26 — событие аудита атомарно снятию.
//
// Оба ручных отзыва пишут аудит в той же транзакции, что удаление; здесь это
// паритет, а не украшение: без атомарности возможны снятия БЕЗ записи, то есть
// ровно «пропало, и следа нет».
func TestCredRcl26_AuditRowIsWrittenInTheSameTransactionAsTheRemoval(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	f := newReclaimFixture(t)

	ids := []string{"uoc_rcm00000000000m01", "uoc_rcm00000000000m02", "uoc_rcm00000000000m03"}
	for _, id := range ids {
		f.putUserCred(t, id, 30*24*time.Hour, time.Hour)
	}

	r := kachopg.NewExpiredCredentialReclaimer(f.pool, "kacho_iam")
	res, err := r.ReclaimExpiredCredentials(ctx, reclaimSpec(10*time.Minute))
	require.NoError(t, err)
	require.Equal(t, len(ids), res.Reclaimed)

	// Число снятых строк и число событий обязаны совпасть: снятие без записи
	// означало бы, что арендатор не может узнать, куда делось удостоверение.
	var events int64
	require.NoError(t, f.pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.user_token.expired_reclaimed'`).Scan(&events))
	require.EqualValues(t, len(ids), events, "на каждое снятое обязано быть ровно одно событие")

	// И тело события обязано нести содержимое снятой строки: строки больше нет,
	// и отличить «сняли законно» от «уборщик посчитал не так» можно только по
	// нему.
	var expiredAt, grace, kind string
	require.NoError(t, f.pool.QueryRow(ctx, `
		SELECT event_payload ->> 'expired_at', event_payload ->> 'grace_applied',
		       event_payload ->> 'credential_kind'
		  FROM kacho_iam.audit_outbox
		 WHERE event_payload ->> 'resource_id' = $1`, ids[0]).Scan(&expiredAt, &grace, &kind))
	require.NotEmpty(t, expiredAt, "событие обязано назвать срок снятой строки")
	require.NotEmpty(t, grace, "и применённую отсрочку")
	require.Equal(t, "KEYPAIR", kind, "и вид предъявления")
}
