// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// expired_credential_reclaim_defaults_integration_test.go — ВЕЛИЧИНЫ УМОЛЧАНИЯ
// потолка после пересмотра (задача #1264, приёмка
// `expired-credential-reclaim.md` §4, сценарий CRED-RCL-29).
//
// # Почему проба нужна отдельно от самой уборки
//
// Работа состоит из ДВУХ половин, и вторая невидима без утверждения. Уборка
// освобождает места, которые прежде занимал мусор; величина умолчания была
// выведена как «одновременно действующих × 2», и множитель назван платой за
// отсутствие уборки. Сделать одну уборку значило бы МОЛЧА ужесточить предел:
// запас, заложенный под истёкшие, исчезает вместе с ними, а число остаётся
// прежним.
//
// # Почему проба на миграциях, а не на посеве
//
// Величины лежат в своде миграций. Посев их НЕ МЕНЯЕТ by construction — значит
// решение §4, объявленное в приёмке, в дереве не наступило бы вовсе, и это было
// бы ненаблюдаемо: посев проходит, миграция зелёная, число прежнее.
//
// # Что изменилось: утверждается ЧИСЛО, а не переход к нему
//
// Прежде первая проба доводила цепочку до потолка `20260824230000`, читала
// прежние `10` и `20`, применяла остаток цепочки и требовала `12` и `24` —
// то есть судила ПЕРЕХОД. Миграций сервиса теперь одна — свод, — и состояния
// «до пересмотра» не существует ни на одной применимой ревизии: свод несёт уже
// пересмотренные величины. Переход перестал быть наблюдаемым, и утверждать о
// нём нечего.
//
// Свойство при этом живо, и утверждается оно ПАРОЙ, в которой ни одна половина
// не заменяет другую: авторитетные величины умолчания равны `12` и `24` (проба
// первая) И списание распоряжается именно ими (проба вторая). Одной первой мало
// — число в таблице величин может лежать и не действовать; одной второй мало —
// снимок в строке учёта мог бы разойтись с авторитетом и об этом никто бы не
// узнал.

package migrations_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// CRED-RCL-29 (первая половина) — авторитетные величины умолчания в дереве
// равны пересмотренным `12` и `24`.
//
// Читается АВТОРИТЕТ (`kacho_iam.limits`, область `DEFAULT`, не отозванные), а
// не снимок в строке учёта: снимок правится мутацией и мог бы нести верное число
// при неверном авторитете — тогда следующий заведённый носитель получил бы
// прежний предел, и заметить это было бы нечем.
//
// Утверждается ТРОЙКА, потому что равенства двух чисел мало:
//
//   - обе величины прочитаны (перепись не ноль — иначе утверждение зеленело бы,
//     не прочитав ни строки; равенство карт это ловит, но не называет причины);
//   - живых объявлений умолчания на эти виды РОВНО два — второе, противоречащее,
//     лежало бы рядом и молчало;
//   - числа те, что назвало решение §4.1а.
func TestCredRcl29_CeilingDefaultsInTheTreeAreTheRevisedOnes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."), "цепочка миграций обязана примениться целиком")

	const kindsFilter = `
		 WHERE kind IN ('iam.user.credential', 'iam.serviceAccount.credential')
		   AND scope = 'DEFAULT' AND withdrawn_at IS NULL`

	var live int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.limits`+kindsFilter).Scan(&live))
	require.Equal(t, 2, live,
		"живых объявлений умолчания на виды удостоверения обязано быть РОВНО два: "+
			"меньше — предел на вид не назначен вовсе; больше — рядом лежит второе "+
			"объявление того же вида, и какое из них возьмёт носитель, решает порядок "+
			"строк, а не решение продукта")

	defaults := map[string]int64{}
	rows, err := db.Query(`SELECT kind, limit_value FROM kacho_iam.limits` + kindsFilter)
	require.NoError(t, err)
	for rows.Next() {
		var k string
		var v int64
		require.NoError(t, rows.Scan(&k, &v))
		defaults[k] = v
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())

	require.Equal(t, map[string]int64{
		// 5 назначений × 2 (ротация внахлёст) + 2 разовых — §4.1а.
		"iam.user.credential": 12,
		// 10 назначений × 2 + 4 разовых — §4.1а.
		"iam.serviceAccount.credential": 24,
	}, defaults, "величины умолчания обязаны нести пересмотр §4")

	t.Logf("перепись: живых объявлений умолчания %d, величины %v", live, defaults)
}

// CRED-RCL-29 (вторая половина) — новая величина ДЕЙСТВУЕТ, а не лежит.
//
// Число в таблице величин и число, которым распоряжается списание, — разные
// предметы: снимок величины живёт в строке учёта, и обновляется он мутацией.
// Проба доводит принципала до ПРЕЖНЕГО предела и требует, чтобы выдача сверх
// него прошла: без этого «12 в таблице» осталось бы утверждением о строке, а не
// о поведении.
func TestCredRcl29_TheRevisedCeilingIsTheOneThatChargingUses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."), "цепочка миграций обязана примениться целиком")

	seedCredentialOwners(t, db)

	// Одиннадцатое удостоверение — то самое, которому ПРЕЖНИЙ предел отказывал.
	for i := 1; i <= 11; i++ {
		mirror := fmt.Sprintf("rcl-limit-mirror-%02d", i)
		require.NoErrorf(t, insertUserCred(db,
			fmt.Sprintf("uoc_rcm000000000000%02d", i), "KEYPAIR", noHash,
			"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", &mirror, 30),
			"выдача %d обязана пройти под пересмотренным пределом", i)
	}

	var used, limit int64
	require.NoError(t, db.QueryRow(`
		SELECT used, limit_value FROM kacho_iam.project_resource_quotas
		 WHERE carrier_type = 'iam.user' AND carrier_id = 'usr00000000000000bat'
		   AND kind = 'iam.user.credential'`).Scan(&used, &limit))
	require.EqualValues(t, 11, used, "списание обязано учесть все одиннадцать")
	require.EqualValues(t, 12, limit, "снимок величины в строке учёта обязан нести пересмотренное число")

	t.Logf("перепись списания: used %d · limit %d", used, limit)
}
