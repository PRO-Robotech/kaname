// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// condition_integration_test.go — условие на записи РЕШАЕТ исход, и оба
// направления этого проверяются.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА ОБЯЗАНА БЫТЬ ПАРНОЙ
//
// Реализация, отвечающая «нет» на оба запроса, удовлетворяет одному отрицанию и
// при этом не соблюдает условие — она просто не даёт доступа никогда. Реализация,
// отвечающая «да» на оба, тоже удовлетворяет одному утверждению — и не соблюдает
// условие вовсе. Различает их только пара: два запроса, отличающиеся ТОЛЬКО
// доводами, обязаны разойтись в ответе.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// seedConditionedFact кладёт факт, действующий только при выполненном условии.
func seedConditionedFact(t *testing.T, ctx context.Context, tx pgx.Tx, cond string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.relation_fact
		   (object_type, object_id, relation, subject, condition_name)
		 VALUES ('compute_instance', 'ins-1', 'ssh', 'user:usr-1', $1)`, cond)
}

// freshContext — доводы, при которых условие свежести выполнено.
func freshContext(now time.Time) map[string]any {
	return map[string]any{
		"current_time": now.Unix(),
		"acr_value":    "3",
		"amr_claims":   []string{"pwd", "webauthn"},
		"mfa_at":       now.Add(-2 * time.Minute).Unix(),
	}
}

func sshQuery(cctx map[string]any) relverdict.Query {
	return relverdict.Query{
		Subject: "user:usr-1", ObjectType: "compute_instance", ObjectID: "ins-1",
		Relation: "ssh", Context: cctx,
	}
}

// XC-12-26 — два запроса, отличающиеся ТОЛЬКО доводами, отвечают по-разному.
func TestAsk_ConditionDecidesTheOutcomeBothWays(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedConditionedFact(t, ctx, tx, "mfa_fresh")
		now := time.Now()

		got, _, err := relverdict.Ask(ctx, tx, sshQuery(freshContext(now)))
		if err != nil {
			t.Fatalf("свежие доводы: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("при выполненном условии вердикт %s, ожидался allow — реализация, "+
				"отказывающая всегда, удовлетворяет отрицанию и не соблюдает условие", got)
		}

		// Та же запись, тот же субъект, тот же объект. Отличается ОДИН довод.
		stale := freshContext(now)
		stale["mfa_at"] = now.Add(-4 * time.Hour).Unix()
		got, _, err = relverdict.Ask(ctx, tx, sshQuery(stale))
		if err != nil {
			t.Fatalf("устаревшие доводы: %v", err)
		}
		if got != relverdict.Deny {
			t.Errorf("при просроченном подтверждении вердикт %s, ожидался deny — "+
				"реализация, разрешающая всегда, не соблюдает условие вовсе", got)
		}
	})
}

// Каждый довод условия — несущий: убери любой, и права нет.
//
// Проверка нужна ровно потому, что предикат из трёх частей легко написать так,
// что решает одна: остальные две тогда стоят для вида.
func TestAsk_EveryPremiseOfTheConditionCarriesWeight(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedConditionedFact(t, ctx, tx, "mfa_fresh")
		now := time.Now()

		for _, tc := range []struct {
			name   string
			breaks func(map[string]any)
		}{
			{"уровень уверенности ниже требуемого", func(m map[string]any) { m["acr_value"] = "2" }},
			{"требуемый метод не применялся", func(m map[string]any) { m["amr_claims"] = []string{"pwd"} }},
			{"подтверждение просрочено", func(m map[string]any) { m["mfa_at"] = now.Add(-time.Hour).Unix() }},
			{"довода о подтверждении нет вовсе", func(m map[string]any) { delete(m, "mfa_at") }},
			{"доводов нет вовсе", func(m map[string]any) {
				for k := range m {
					delete(m, k)
				}
			}},
			{"подтверждение из будущего", func(m map[string]any) { m["mfa_at"] = now.Add(time.Hour).Unix() }},
		} {
			cctx := freshContext(now)
			tc.breaks(cctx)
			got, _, err := relverdict.Ask(ctx, tx, sshQuery(cctx))
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got != relverdict.Deny {
				t.Errorf("%s: вердикт %s, ожидался deny — этот довод не несёт веса, "+
					"то есть предикат из трёх частей решает меньшим числом", tc.name, got)
			}
		}
	})
}

// Непонятое условие — «не знаю», НИКОГДА не «нет».
//
// Слить их значило бы: новое условие в модели молча отбирает доступ у всех, кто
// им пользуется, и замечено это будет по чужим отказам, а не по красной пробе.
func TestAsk_UnknownConditionIsUnknownNotDenied(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedConditionedFact(t, ctx, tx, "условие_которого_нет_в_наборе")

		got, _, err := relverdict.Ask(ctx, tx, sshQuery(freshContext(time.Now())))
		if got != relverdict.Unknown {
			t.Fatalf("вердикт %s, ожидался unknown — незнание, выданное за отказ, "+
				"неотличимо от честного «прав нет»", got)
		}
		if err == nil {
			t.Error("«не знаю» без причины: вызывающий не сможет отличить непонятое условие " +
				"от недоступной БД, а это разные исходы")
		}
	})
}

// Безусловный источник решает независимо от непонятого соседа.
//
// Иначе одна нераспознанная запись отравляла бы вердикт по правам, которые к
// ней отношения не имеют.
func TestAsk_UnconditionalSourceWinsOverAnUnknownCondition(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedConditionedFact(t, ctx, tx, "условие_которого_нет_в_наборе")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('compute_instance', 'ins-1', 'ssh', 'group:grp-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'ops')
			 ON CONFLICT DO NOTHING`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
			 VALUES ('grp-1', 'user', 'usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, sshQuery(nil))
		if err != nil {
			t.Fatalf("Ask: %v", err)
		}
		if got != relverdict.Allow {
			t.Fatalf("вердикт %s, ожидался allow — безусловное право не должно зависеть "+
				"от того, что рядом лежит запись с непонятым условием", got)
		}
	})
}

// Схема не принимает доводы без условия: их некому читать.
func TestSchema_ParamsWithoutAConditionAreRefused(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		_, err := tx.Exec(ctx,
			`INSERT INTO kacho_iam.relation_fact
			   (object_type, object_id, relation, subject, condition_params)
			 VALUES ('compute_instance', 'ins-1', 'ssh', 'user:usr-1', '{"ttl": 5}'::jsonb)`)
		if err == nil {
			t.Fatal("доводы без условия приняты — они не будут прочитаны никем, и следующий " +
				"будет искать, почему его параметр не применился")
		}
	})
}
