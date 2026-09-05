// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// poison_producer_integration_test.go — «травиться нечему» проверяется ВСТАВКОЙ,
// а не прочтением схемы.
//
// # Предмет (kacho#455)
//
// Две очереди kacho-iam — provider_compensation_outbox и subject_change_outbox —
// дренились, травили строки и возврата отравленных не имели. Возврат им не
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
// # У ДВУХ ПОЛОВИН ПРОБЫ РАЗНОЕ ОСНОВАНИЕ, и это надо сказать вслух
//
// Прошедшее время выше — не стиль. У журнала смены субъекта дренажа больше нет
// вовсе (#1024): толчок к краю снят, направление развёрнуто, потребитель читает
// журнал КУРСОРОМ (`id > $1`). Вместе с дренажом ушёл и его декодер —
// `clients.DecodeSubjectChange` в дереве не существует (предикат:
// `git grep -rn 'DecodeSubjectChange' -- . ':!*poison_producer*'` → пусто).
//
//	provider_compensation_outbox  дренится; декодер жив
//	                              (`clients.DecodeProviderCompensation`), и
//	                              перечень форм по-прежнему взят у его веток.
//	                              Расхождение перечней — сама по себе находка:
//	                              ветка декодера без своей строки здесь означает
//	                              условие отравления, которое никто не закрыл.
//
//	subject_change_outbox         дренажа и декодера нет. Основание этих
//	                              четырёх форм — САМИ ОГРАНИЧЕНИЯ миграции 0097:
//	                              они живы и по-прежнему что-то стерегут, но
//	                              стерегут уже ДРУГОГО потребителя.
//
// # Что ограничения журнала стерегут сегодня
//
// Строка обязана ОПИСЫВАТЬ СЕБЯ телом, а не только колонками: тело непусто, оно
// объект и оно называет субъекта. Тело — единственное место, откуда живая
// проекция чтения берёт тип субъекта
// (`repo/kacho/pg/subject_change_repo.go`: `COALESCE(payload->>'subject_type', ”)`),
// и единственная форма записи, пережившая обе усушки набора колонок: колонок
// журнал терял дважды (#1462 — величины предмета, #1396 — величины доставки),
// тела — ни разу.
//
// # Почему эта проба, если есть гейт по дереву
//
// Гейт `internal/repohygiene` TestRetryPermanentQueuesCannotBePoisonedByDecode
// утверждает, что ограничения ЕСТЬ. Он не утверждает, что их ДОСТАТОЧНО:
// достаточность — свойство пары «потребитель ↔ схема», и проверить её можно
// только предъявив базе каждую негодную форму и потребовав отказа.
//
// И журнала смены субъекта тот гейт НЕ КАСАЕТСЯ: он судит очереди по ПРОВОДКЕ
// дренажа (`drainer.Config.PermanentPolicy`), а проводки у журнала нет — его
// перечень сегодня это три очереди (kacho_iam.audit_outbox,
// kacho_iam.provider_compensation_outbox, public.audit_outbox). Значит для
// половины журнала эта проба — не вторая линия обороны, а ЕДИНСТВЕННАЯ:
// снимут ограничение 0097 — красной станет только она.
package migrations_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// poisonCase — одна негодная форма строки вместе с ОСНОВАНИЕМ, по которому она
// негодна.
type poisonCase struct {
	name string
	// basis — почему эта форма отвергается. Названо, чтобы отказ пробы указывал
	// на предмет, а не на строку SQL.
	//
	// Род основания у двух половин пробы РАЗНЫЙ, и поле нарочно не зовётся
	// «веткой декодера»: у очереди компенсаций это ветка живого
	// `clients.DecodeProviderCompensation`, у журнала смены субъекта декодера
	// нет вовсе — там основанием служит ограничение схемы (0097) и то, что
	// принимает на веру живая проекция чтения. Имя, называющее один род,
	// объявляло бы существующим механизм, которого у второй половины нет.
	basis  string
	insert string
	args   []any
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
			name:  "subject_change: тело отсутствует",
			basis: "0097 subject_change_outbox.payload NOT NULL: строка без тела себя не описывает",
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', NULL)`,
		},
		{
			name:  "subject_change: тело не объект",
			basis: "0097 CHECK subject_change_payload_is_object: тело обязано быть объектом",
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', '"не объект"'::jsonb)`,
		},
		{
			name:  "subject_change: тело не называет субъекта",
			basis: "0097 CHECK subject_change_payload_names_subject: тело обязано называть субъекта",
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', '{"event_type":"binding_revoke"}'::jsonb)`,
		},
		{
			name:  "subject_change: субъект в теле пуст",
			basis: "0097 CHECK subject_change_payload_names_subject: тело обязано называть субъекта",
			insert: `INSERT INTO kacho_iam.subject_change_outbox (subject_id, op, payload)
			         VALUES ('usr_a', 'binding_revoke', '{"subject_id":""}'::jsonb)`,
		},

		// ---- provider_compensation_outbox ------------------------------------
		{
			name:  "provider_compensation: тело не объект",
			basis: `DecodeProviderCompensation: "decode … payload"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.oauth_client.delete', '[]'::jsonb)`,
		},
		{
			name:  "provider_compensation: предмет не назван",
			basis: `DecodeProviderCompensation: "names no subject"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.oauth_client.delete', '{"reason":"r"}'::jsonb)`,
		},
		{
			name:  "provider_compensation: предметов названо два",
			basis: `DecodeProviderCompensation: "names two subjects"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.trust_grant.delete',
			                 '{"client_id":"c","grant_id":"g"}'::jsonb)`,
		},
		{
			name:  "provider_compensation: вид события вне словаря",
			basis: `NewProviderCompensationApplier: "unknown provider compensation event type"`,
			insert: `INSERT INTO kacho_iam.provider_compensation_outbox (event_type, payload)
			         VALUES ('provider.something.delete', '{"client_id":"c"}'::jsonb)`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ierr := db.ExecContext(ctx, tc.insert, tc.args...)
			require.Error(t, ierr,
				"база ПРИНЯЛА негодную строку (%s). "+
					"Форма негодна по основанию, которое живо: у очереди компенсаций это "+
					"ветка декодера (отказ разбора травит при любой политике, а возврата "+
					"отравленных строк у неё нет — значит намерение теряется навсегда), у "+
					"журнала смены субъекта — ограничение схемы, принятое живой проекцией "+
					"чтения на веру. Либо закрой эту форму ограничением, либо сними "+
					"основание вместе с формой.", tc.basis)
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

	// Перепись — по ДВУМ половинам врозь: у них разное основание, и одно число
	// на обе скрывало бы ровно тот случай, ради которого эта проба переписана —
	// исчезновение декодера у одной из них.
	var byDecoder, bySchema int
	for _, tc := range cases {
		if strings.HasPrefix(tc.name, "subject_change:") {
			bySchema++
			continue
		}
		byDecoder++
	}
	t.Logf("перепись: негодных форм предъявлено базе %d — по ветке живого декодера %d, "+
		"по ограничению схемы %d; положительных контролей 3",
		len(cases), byDecoder, bySchema)
}
