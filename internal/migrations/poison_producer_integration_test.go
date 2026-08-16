// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// poison_producer_integration_test.go — «травиться нечему» проверяется ВСТАВКОЙ,
// а не прочтением схемы.
//
// # Предмет (kacho#455)
//
// Две очереди kacho-iam — provider_compensation_outbox и subject_change_outbox —
// дренятся, травят строки и возврата отравленных не имеют. Возврат им не
// построить и не осмыслить: он собирается вокруг ключа партиции, которого у
// коммутативного потока нет, а сам смысл травления — разблокировать партицию,
// которой тоже нет. Поэтому исход выбран другой: очереди объявили
// `PermanentPolicy: drainer.RetryPermanent` и перестали травить постоянный отказ
// ПРИМЕНЕНИЯ.
//
// Остался ровно один путь отравления — отказ РАЗБОРА, и он остался намеренно:
// тело строки не станет разбираемым ни от какого события. Значит утверждение
// «травиться нечему» держится на одном факте: НЕРАЗБИРАЕМУЮ СТРОКУ НЕЛЬЗЯ
// ЗАПИСАТЬ.
//
// # Почему эта проба, если есть гейт по дереву
//
// Гейт `internal/repohygiene` TestRetryPermanentQueuesCannotBePoisonedByDecode
// утверждает, что ограничения ЕСТЬ. Он не утверждает, что их ДОСТАТОЧНО:
// достаточность — свойство пары «декодер ↔ схема», и проверить её можно только
// предъявив базе каждую форму, на которой декодер откажет, и потребовав отказа.
// Гейт ловит снятие ограничения, эта проба — расхождение между тем, что
// отвергает база, и тем, на чём спотыкается декодер.
//
// # Перечень форм взят у ДЕКОДЕРОВ, а не придуман
//
// Каждый случай ниже соответствует ветке `drainer.ErrPermanent` в
// `clients.DecodeSubjectChange` / `clients.DecodeProviderCompensation`. Расхождение
// перечней — сама по себе находка: ветка декодера без своей строки здесь означает
// условие отравления, которое никто не закрыл.
package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// poisonCase — одна форма строки, на которой декодер очереди отказал бы
// постоянно, вместе с веткой, которую она представляет.
type poisonCase struct {
	name string
	// decoderBranch — ветка декодера, ради которой строка отвергается. Названа,
	// чтобы отказ пробы указывал на предмет, а не на строку SQL.
	decoderBranch string
	insert        string
	args          []any
}

func TestIntegration_UndecodableRowCannotBeWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(db, "."), "цепь миграций обязана накатиться целиком")

	cases := []poisonCase{
		// ---- subject_change_outbox ------------------------------------------
		{
			name:          "subject_change: тело отсутствует",
			decoderBranch: `DecodeSubjectChange: "payload IS NULL"`,
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', NULL)`,
		},
		{
			name:          "subject_change: тело не объект",
			decoderBranch: `DecodeSubjectChange: "invalid json payload"`,
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', '"не объект"'::jsonb)`,
		},
		{
			name:          "subject_change: тело не называет субъекта",
			decoderBranch: `DecodeSubjectChange: "subject_id empty"`,
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', '{"event_type":"binding_revoke"}'::jsonb)`,
		},
		{
			name:          "subject_change: субъект в теле пуст",
			decoderBranch: `DecodeSubjectChange: "subject_id empty"`,
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', '{"subject_id":""}'::jsonb)`,
		},

		// ---- provider_compensation_outbox ------------------------------------
		{
			name:          "provider_compensation: тело не объект",
			decoderBranch: `DecodeProviderCompensation: "decode … payload"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.oauth_client.delete', '[]'::jsonb)`,
		},
		{
			name:          "provider_compensation: предмет не назван",
			decoderBranch: `DecodeProviderCompensation: "names no subject"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.oauth_client.delete', '{"reason":"r"}'::jsonb)`,
		},
		{
			name:          "provider_compensation: предметов названо два",
			decoderBranch: `DecodeProviderCompensation: "names two subjects"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.trust_grant.delete',
			                 '{"client_id":"c","grant_id":"g"}'::jsonb)`,
		},
		{
			name:          "provider_compensation: вид события вне словаря",
			decoderBranch: `NewProviderCompensationApplier: "unknown provider compensation event type"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.something.delete', '{"client_id":"c"}'::jsonb)`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ierr := db.ExecContext(ctx, tc.insert, tc.args...)
			require.Error(t, ierr,
				"база ПРИНЯЛА строку, на которой декодер откажет постоянно (%s). "+
					"Отказ разбора травит при любой политике, а возврата отравленных строк "+
					"у этой очереди нет и не будет — значит намерение теряется навсегда. "+
					"Либо закрой эту форму ограничением схемы, либо у очереди обязан "+
					"появиться возврат.", tc.decoderBranch)
		})
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, без которого всё вышесказанное ничего не стоит:
	// законная строка проходит. Без него проба зеленела бы на схеме, отвергающей
	// ВСЁ, — то есть на очереди, в которую нельзя записать ни одного намерения.
	t.Run("контроль: законная строка принимается", func(t *testing.T) {
		_, err := db.ExecContext(ctx,
			`INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			 VALUES ('usr_a', 'binding_revoke',
			         '{"subject_id":"usr_a","event_type":"binding_revoke"}'::jsonb)`)
		require.NoError(t, err,
			"законное намерение отвергнуто — ограничения оказались строже декодера, "+
				"и очередь перестала принимать то, ради чего заведена")

		_, err = db.ExecContext(ctx,
			`INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			 VALUES ('provider.oauth_client.delete',
			         '{"client_id":"c-1","origin":"sa_key","reason":"commit failed"}'::jsonb)`)
		require.NoError(t, err, "законная компенсация отвергнута")

		_, err = db.ExecContext(ctx,
			`INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			 VALUES ('provider.trust_grant.delete',
			         '{"grant_id":"g-1","origin":"sa_key","reason":"commit failed"}'::jsonb)`)
		require.NoError(t, err, "законная компенсация доверительного гранта отвергнута")
	})

	t.Logf("перепись: форм, на которых декодер отказал бы, предъявлено базе %d; "+
		"положительных контролей 3", len(cases))
}
