// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_liveness_integration_test.go — ЖИВОСТЬ, СПРОШЕННАЯ ПО
// ИДЕНТИФИКАТОРУ, СОВПАДАЕТ С ЖИВОСТЬЮ, СПРОШЕННОЙ ПО СЕКРЕТУ (задача #1450).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА СРАВНИВАЕТ ДВЕ ПОЛОСЫ, А НЕ ПРОВЕРЯЕТ КАЖДУЮ ОТДЕЛЬНО
//
// Полос теперь две: предъявитель спрашивает секретом, открытое соединение —
// идентификатором. Проба каждой по отдельности требует знать, каким ответ
// ДОЛЖЕН быть, — а это и есть спорный вопрос. Сравнение полос спрашивает
// другое: решал ли кто-нибудь, что они различаются. На это ответ есть всегда.
//
// Расхождение здесь стоит дорого и в обе стороны: полоса идентификатора,
// оказавшись СТРОЖЕ, закрывала бы живые соединения; оказавшись МЯГЧЕ — не
// закрывала бы отозванные, то есть возвращала бы ровно тот дефект, ради
// которого вопрос и заведён.
//
// ─────────────────────────────────────────────────────────────────────────────
// СВЕРЯЮТСЯ ВСЕ ПОЛОСЫ, А ПЕРЕЧЕНЬ ПОЛОС ВЫВОДИТСЯ ИЗ СХЕМЫ
//
// Полос удостоверения две — личность и служебная учётка, — и у каждой СВОЙ
// предикат живости, объявленный отдельно: состояние владельца у них разное
// (приглашение против выключателя). Значит и разъезжаются они порознь: сверка
// одной полосы о второй не утверждает НИЧЕГО.
//
// Перечень носителей секретного удостоверения не выписывается, а спрашивается у
// схемы: носитель — таблица, несущая и вид удостоверения, и его хеш. Третий
// носитель, заведённый позже без своей полосы здесь, обязан стать находкой, а не
// невидимостью.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕПИСЬ ПЕЧАТАЕТ ОБЕ ВЕЛИЧИНЫ
//
// «Полосы согласны» из нуля осмотренных состояний неотличимо от «полосы
// согласны» из шестнадцати. Печатаются и число полос, и число состояний, и
// число живых состояний; пустой перечень — отказ. Одно число скрыло бы ровно
// тот случай, ради которого проба и переписана: полос две, а сверялась одна.

package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// basicCredLane — ПОЛОСА УДОСТОВЕРЕНИЯ, сверяемая на каждом состоянии строки.
//
// Полосы не взаимозаменимы: у каждой свой носитель, свой владелец и своё
// состояние владельца — у личности это приглашение, у служебной учётки
// выключатель. Форма вида тоже своя: ограничение носителя служебной учётки
// требует зеркала клиента при уходе из `SECRET` и его отсутствия при возврате.
type basicCredLane struct {
	table      string // носитель — им же полоса сверяется со схемой
	name       string
	credID     string
	ownerID    string
	mint       func(t *testing.T, pool *pgxpool.Pool, credID, ownerID string) string
	ownerTable string // где живёт состояние владельца
	ownerCol   string
	ownerDead  string // литерал SQL: владелец перестаёт быть живым
	ownerAlive string
	// Добавка к SET при смене вида: без неё состояние «вид не SECRET»
	// неисполнимо у носителя служебной учётки, а неисполнимое Given — это
	// проба, которая не проверяет ничего.
	kindAwayExtra string
	kindBackExtra string
}

// basicCredState — состояние строки: как его создать и живо ли удостоверение
// после этого.
type basicCredState struct {
	name     string
	arrange  string
	wantLive bool
}

// basicCredLanesUnderTest — полосы, которые проба сверяет. Перечень СВЕРЯЕТСЯ со
// схемой (см. basicCredCarriers), а не заменяет её.
func basicCredLanesUnderTest() []basicCredLane {
	return []basicCredLane{
		{
			table:      "user_oauth_clients",
			name:       "личность",
			credID:     "uoc_0000000000000cx01",
			ownerID:    "usr0000000000000bat1",
			mint:       mintUserCredential,
			ownerTable: "users",
			ownerCol:   "invite_status",
			ownerDead:  "'BLOCKED'",
			ownerAlive: "'ACTIVE'",
		},
		{
			table:         "service_account_oauth_clients",
			name:          "служебная учётка",
			credID:        "soc_0000000000000cx11",
			ownerID:       "sva0000000000000bat1",
			mint:          mintSACredential,
			ownerTable:    "service_accounts",
			ownerCol:      "enabled",
			ownerDead:     "false",
			ownerAlive:    "true",
			kindAwayExtra: ", hydra_client_id = 'hyd-cx-1450'",
			kindBackExtra: ", hydra_client_id = NULL",
		},
	}
}

// basicCredCarriers — носители секретного удостоверения, ВЫВЕДЕННЫЕ из схемы:
// таблица, несущая и вид удостоверения, и его хеш. Выписанный перечень разошёлся
// бы с деревом молча — и разошёлся бы там, где расхождение не видно: полоса без
// пробы отвечает верно на всяком входе, который ей никто не подаёт.
func basicCredCarriers(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
SELECT table_name
  FROM information_schema.columns
 WHERE table_schema = 'kacho_iam'
   AND column_name IN ('credential_kind', 'secret_hash')
 GROUP BY table_name
HAVING count(DISTINCT column_name) = 2
 ORDER BY table_name`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		out = append(out, name)
	}
	require.NoError(t, rows.Err())
	return out
}

// basicCredStates — состояния строки для одной полосы. Порядок значим: каждое
// отрицание окружено положительными, иначе согласие полос было бы верно и о
// полосе, отвергающей всё.
func basicCredStates(l basicCredLane, hashHex string) []basicCredState {
	return []basicCredState{
		{"живое", `SELECT 1`, true},
		{"истёкшее", fmt.Sprintf(
			`UPDATE %s SET expires_at = now() - interval '1 second' WHERE id = '%s'`, l.table, l.credID), false},
		{"снова живое", fmt.Sprintf(
			`UPDATE %s SET expires_at = now() + interval '30 days' WHERE id = '%s'`, l.table, l.credID), true},
		{"владелец неживой", fmt.Sprintf(
			`UPDATE %s SET %s = %s WHERE id = '%s'`, l.ownerTable, l.ownerCol, l.ownerDead, l.ownerID), false},
		{"владелец снова живой", fmt.Sprintf(
			`UPDATE %s SET %s = %s WHERE id = '%s'`, l.ownerTable, l.ownerCol, l.ownerAlive, l.ownerID), true},
		{"вид не SECRET", fmt.Sprintf(
			`UPDATE %s SET credential_kind = 'KEYPAIR', secret_hash = ''::bytea%s WHERE id = '%s'`,
			l.table, l.kindAwayExtra, l.credID), false},
		{"вид снова SECRET", fmt.Sprintf(
			`UPDATE %s SET credential_kind = 'SECRET', secret_hash = decode('%s', 'hex')%s WHERE id = '%s'`,
			l.table, hashHex, l.kindBackExtra, l.credID), true},
		{"строка снята", fmt.Sprintf(`DELETE FROM %s WHERE id = '%s'`, l.table, l.credID), false},
	}
}

// TestBCL1450_LivenessByIdAgreesWithLivenessBySecretOnEveryState — обе полосы
// об одном предмете, сверенные между собой на КАЖДОМ состоянии строки и у
// КАЖДОГО носителя.
//
// Одного носителя мало, и это измерено: предикаты живости объявлены по одному на
// носителя, поэтому расстыковка на втором носителе доказанно не ловится сверкой
// первого.
func TestBCL1450_LivenessByIdAgreesWithLivenessBySecretOnEveryState(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	lanes := basicCredLanesUnderTest()
	carriers := basicCredCarriers(t, pool)
	require.NotEmpty(t, carriers,
		"носителей секретного удостоверения в схеме ноль — «полосы согласны» здесь означало бы «не сверено ничего»")
	covered := make(map[string]bool, len(lanes))
	for _, l := range lanes {
		covered[l.table] = true
	}
	for _, carrier := range carriers {
		require.True(t, covered[carrier],
			"носитель %q объявлен схемой, а его полоса живости не сверяется здесь ни на одном состоянии", carrier)
	}
	require.Len(t, lanes, len(carriers),
		"полос в пробе %d, носителей в схеме %d — перечень разошёлся со схемой", len(lanes), len(carriers))

	var lanesSeen, statesSeen, positives int
	for _, lane := range lanes {
		secret := lane.mint(t, pool, lane.credID, lane.ownerID)
		// Дату создания сдвигаем в прошлое: иначе истёкший срок — незаконный
		// вход ограничения `expires_at > created_at`, и состояние «истекло»
		// неисполнимо.
		_, err := pool.Exec(ctx, fmt.Sprintf(
			`UPDATE %s SET created_at = now() - interval '2 days' WHERE id = '%s'`, lane.table, lane.credID))
		require.NoError(t, err, "полоса %q: дату создания не сдвинуть", lane.name)

		// Смена вида требует и смены формы: ограничение схемы держит их вместе,
		// поэтому хеш сохраняется и возвращается вместе с видом. Иначе состояние
		// «вид снова SECRET» неисполнимо.
		var hashHex string
		require.NoError(t, pool.QueryRow(ctx, fmt.Sprintf(
			`SELECT encode(secret_hash, 'hex') FROM %s WHERE id = '%s'`, lane.table, lane.credID)).Scan(&hashHex))
		require.NotEmpty(t, hashHex,
			"полоса %q: хеш пуст — Given состояния «вид снова SECRET» неисполним", lane.name)

		var laneLive, laneDead int
		for _, st := range basicCredStates(lane, hashHex) {
			_, aerr := pool.Exec(ctx, st.arrange)
			require.NoError(t, aerr,
				"полоса %q, состояние %q не создать — Given пробы неисполним", lane.name, st.name)

			_, bySecret := repo.ResolveBasic(ctx, secret)
			byID := repo.CheckBasicLive(ctx, lane.credID)

			secretLive := bySecret == nil
			idLive := byID == nil
			require.Equal(t, secretLive, idLive,
				"полоса %q, состояние %q: полоса секрета говорит live=%v, полоса идентификатора — live=%v; "+
					"расхождение никем не решалось", lane.name, st.name, secretLive, idLive)
			require.Equal(t, st.wantLive, idLive,
				"полоса %q, состояние %q: живость по идентификатору не та, какой её объявляет предикат",
				lane.name, st.name)
			if !idLive {
				require.ErrorIs(t, byID, domain.ErrBasicCredentialRefused,
					"полоса %q, состояние %q: неживое удостоверение отвечает не единым отказом", lane.name, st.name)
				laneDead++
			} else {
				laneLive++
			}
			statesSeen++
		}
		// Согласие полос на одних живых состояниях верно и о предикате,
		// принимающем всё; на одних неживых — о предикате, отвергающем всё.
		require.NotZero(t, laneLive, "полоса %q: живых состояний ноль", lane.name)
		require.NotZero(t, laneDead, "полоса %q: неживых состояний ноль", lane.name)
		positives += laneLive
		lanesSeen++
	}

	t.Logf("осмотрено: полос %d (носителей в схеме %d), состояний строки %d, из них живых %d",
		lanesSeen, len(carriers), statesSeen, positives)
	require.Equal(t, len(lanes), lanesSeen,
		"полос осмотрено %d из %d — согласие сказано не обо всех", lanesSeen, len(lanes))
	require.NotZero(t, statesSeen,
		"состояний ноль — «полосы согласны» здесь означало бы «не сверено ни одно»")
}

// TestBCL1450_LivenessIsAskedWithoutTheSecret — вопрос отвечается по одному лишь
// идентификатору. Положительный контроль обязателен: «секрет не нужен» верно и о
// полосе, не находящей ничего.
func TestBCL1450_LivenessIsAskedWithoutTheSecret(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	const human = "uoc_0000000000000cx02"
	const machine = "soc_0000000000000cx03"
	mintUserCredential(t, pool, human, "usr0000000000000bat1")
	mintSACredential(t, pool, machine, "sva0000000000000bat1")

	require.NoError(t, repo.CheckBasicLive(ctx, human),
		"живое удостоверение личности не признано живым по идентификатору")
	require.NoError(t, repo.CheckBasicLive(ctx, machine),
		"живое удостоверение служебной учётки не признано живым по идентификатору")

	// Отрицание в паре с положительным: неизвестный идентификатор годной формы.
	require.ErrorIs(t, repo.CheckBasicLive(ctx, "uoc_0000000000000cx04"),
		domain.ErrBasicCredentialRefused, "неизвестный идентификатор признан живым")
}

// TestBCL1450_LivenessRefusalIsSingleAndIsNoOracle — по различию отказов нельзя
// узнать, существует ли удостоверение. Полоса идентификатора опаснее полосы
// секрета: спрашивать её можно, ничего не предъявляя.
func TestBCL1450_LivenessRefusalIsSingleAndIsNoOracle(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	const revoked = "uoc_0000000000000cx05"
	mintUserCredential(t, pool, revoked, "usr0000000000000bat1")
	_, err := pool.Exec(ctx, `DELETE FROM user_oauth_clients WHERE id = $1`, revoked)
	require.NoError(t, err)

	// Пять входов, ни один не живой, и различить их по отказу нельзя.
	inputs := []struct{ name, id string }{
		{"отозванное", revoked},
		{"не существовало никогда", "uoc_0000000000000cx06"},
		{"чужой префикс", "sva0000000000000bat1"},
		{"мусор", "не-идентификатор"},
		{"пусто", ""},
	}
	var msgs []string
	for _, in := range inputs {
		rerr := repo.CheckBasicLive(ctx, in.id)
		require.Error(t, rerr, "вход %q признан живым", in.name)
		require.ErrorIs(t, rerr, domain.ErrBasicCredentialRefused, "вход %q отвечает не единым отказом", in.name)
		msgs = append(msgs, rerr.Error())
	}
	for i := 1; i < len(msgs); i++ {
		require.Equal(t, msgs[0], msgs[i],
			"отказы различимы — по различию узнают, существует ли удостоверение")
	}
	t.Logf("осмотрено: неживых входов %d, все с одним отказом", len(msgs))

	// Положительный контроль в том же прогоне.
	const live = "uoc_0000000000000cx07"
	mintUserCredential(t, pool, live, "usr0000000000000bat1")
	require.NoError(t, repo.CheckBasicLive(ctx, live),
		"живое удостоверение отвергнуто — отрицания выше вакуумны")
}

// TestBCL1450_PresentedStringIsNotAcceptedAsAnIdentifier — предъявленная строка
// целиком в поле идентификатора отвергается, и это НЕ придирка к форме.
//
// Поле идентификатора не помечено носителем секрета намеренно: секрета в нём не
// бывает. Приняв полную строку молча, полоса сделала бы это утверждение ложным —
// секрет поехал бы по проводу в поле, которое никто не обязан беречь.
func TestBCL1450_PresentedStringIsNotAcceptedAsAnIdentifier(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	const credID = "uoc_0000000000000cx08"
	secret := mintUserCredential(t, pool, credID, "usr0000000000000bat1")
	p, err := credsecret.Parse(secret)
	require.NoError(t, err)
	require.Equal(t, credID, p.CredentialID, "разбор вернул не тот идентификатор — проба ниже вакуумна")

	require.ErrorIs(t, repo.CheckBasicLive(ctx, secret), domain.ErrBasicCredentialRefused,
		"предъявленная строка принята как идентификатор — секрет поехал в поле, не помеченное носителем секрета")

	// Положительный контроль: голый идентификатор той же строки проходит.
	require.NoError(t, repo.CheckBasicLive(ctx, credID),
		"голый идентификатор отвергнут — отрицание выше верно и о полосе, отвергающей всё")
}
