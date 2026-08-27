// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// expired_credential_reclaim_defaults_integration_test.go — ВЕЛИЧИНЫ УМОЛЧАНИЯ
// потолка после пересмотра (задача #1264, приёмка
// `expired-credential-reclaim.md` §4, сценарий CRED-RCL-29).
//
// # Почему проба нужна отдельно от самой уборки
//
// Работа состоит из ДВУХ половин, и вторая невидима без утверждения. Уборка
// освобождает места, которые прежде занимал мусор; величина умолчания была
// выведена как «одновременно действующих × 2», и множитель назван платой за
// отсутствие уборки — дословно, в шапке применённой миграции потолка. Сделать
// одну уборку значило бы МОЛЧА ужесточить предел: запас, заложенный под
// истёкшие, исчезает вместе с ними, а число остаётся прежним.
//
// # Почему проба на миграциях, а не на посеве
//
// Величины засеяны применённой миграцией через `INSERT … ON CONFLICT (id) DO
// NOTHING`. Повторный посев их НЕ МЕНЯЕТ by construction — значит решение §4,
// объявленное в приёмке, в дереве не наступило бы вовсе, и это было бы
// ненаблюдаемо: посев проходит, миграция зелёная, число прежнее.

package migrations_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// CRED-RCL-29 — величины умолчания действуют после миграции.
//
// Утверждается ПАРА: и новое число, и то, что прежнее больше не действует.
// Одно только «предел равен 12» зеленело бы и на дереве, где посев завёл 12 с
// самого начала; предмет же — ПЕРЕХОД, и он утверждается ревизией: она обязана
// сдвинуться, потому что величина изменилась.
func TestCredRcl29_CeilingDefaultsRevisedForTheSlackThatTheSweepRemoves(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	// Состояние ДО этой работы: цепочка доведена до потолка включительно.
	require.NoError(t, goose.UpTo(db, ".", credentialCeilingVersion),
		"цепочка обязана дойти до потолка — иначе Given сценария не создан")

	before := map[string]int64{}
	rowsBefore, err := db.Query(`
		SELECT kind, limit_value FROM kacho_iam.limits
		 WHERE kind IN ('iam.user.credential', 'iam.serviceAccount.credential')
		   AND scope = 'DEFAULT' AND withdrawn_at IS NULL`)
	require.NoError(t, err)
	for rowsBefore.Next() {
		var k string
		var v int64
		require.NoError(t, rowsBefore.Scan(&k, &v))
		before[k] = v
	}
	require.NoError(t, rowsBefore.Err())
	require.NoError(t, rowsBefore.Close())

	// Предпосылка пробы: прежние числа те, из которых пересмотр исходил. Если
	// они уже другие — сценарий утверждает не тот переход, и молчать об этом
	// нельзя.
	require.Equal(t, map[string]int64{
		"iam.user.credential":           10,
		"iam.serviceAccount.credential": 20,
	}, before, "предпосылка §4: пересмотр исходит из 10 и 20")

	// When — применяется остаток цепочки, включая миграцию этой работы.
	require.NoError(t, goose.Up(db, "."), "миграция пересмотра обязана примениться")

	after := map[string]int64{}
	rowsAfter, err := db.Query(`
		SELECT kind, limit_value FROM kacho_iam.limits
		 WHERE kind IN ('iam.user.credential', 'iam.serviceAccount.credential')
		   AND scope = 'DEFAULT' AND withdrawn_at IS NULL`)
	require.NoError(t, err)
	for rowsAfter.Next() {
		var k string
		var v int64
		require.NoError(t, rowsAfter.Scan(&k, &v))
		after[k] = v
	}
	require.NoError(t, rowsAfter.Err())
	require.NoError(t, rowsAfter.Close())

	require.Equal(t, map[string]int64{
		// 5 назначений × 2 (ротация внахлёст) + 2 разовых — §4.1а.
		"iam.user.credential": 12,
		// 10 назначений × 2 + 4 разовых — §4.1а.
		"iam.serviceAccount.credential": 24,
	}, after, "величины умолчания обязаны нести пересмотр §4")

	t.Logf("перепись величин: было %v · стало %v", before, after)
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
