// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// nested_rule_down_race_integration_test.go — ОТКАТ ВЛОЖЕННЫХ ПРАВИЛ И
// ОДНОВРЕМЕННЫЙ ПИСАТЕЛЬ (kaname#874, находка ревью круга 1, SA-874-1).
//
// # Предмет
//
// Откат снимает пять колонок контейнера с `role_rule_selectors`. Снятая колонка
// контейнера превращает вложенный селектор в селектор верхнего уровня — то есть
// право «на потомков названного контейнера» становится правом «на все объекты
// типа». Поэтому откат обязан отказать, пока хоть одна роль несёт `children` или
// хоть один селектор — контейнер.
//
// Подсчёт без замка читает снимок, в котором незафиксированного писателя нет:
// откат насчитывает ноль, проходит дальше и встаёт за писателем лишь на снятии
// индекса. Писатель фиксируется — и откат сносит колонки под уже записанным
// вложенным селектором.
//
// # Порядок задан, а не выпал
//
// Писатель записывает и НЕ фиксирует; откат запускается после; писатель
// заканчивает только тогда, когда в каталоге замков появился неудовлетворённый
// запрос отката на одну из двух таблиц.
//
// # Законный близнец
//
// Писатель, отказавшийся от транзакции, пока откат ждёт, следа не оставил — и
// откат обязан пройти: иначе «откат отказал» было бы верно и о защите,
// отказывающей всякому, кто ждал замка.

import (
	"database/sql"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const nestedRuleMigration = "20261017140000_nested_rule_reaches_descendants.sql"

func TestIntegration_NestedRuleRollbackDoesNotRaceItsWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	for _, sc := range []struct {
		name   string
		commit bool
	}{
		{name: "вложенная роль фиксируется, пока откат ждёт замка", commit: true},
		{name: "писатель вложенной роли отказался от транзакции, пока откат ждёт", commit: false},
	} {
		t.Run(sc.name, func(t *testing.T) {
			db := freshIamSchema(t)
			own, previous := versionsOf(t, nestedRuleMigration)
			require.NoError(t, goose.DownTo(db, ".", own), "миграции новее предмета обязаны сняться ДО сцены")
			ndSeedTenant(t, db)

			var tables []int64
			for _, rel := range []string{"kaname.roles", "kaname.role_rule_selectors"} {
				var oid int64
				require.NoError(t, db.QueryRow(`SELECT $1::regclass::oid`, rel).Scan(&oid))
				tables = append(tables, oid)
			}

			// ── ПИСАТЕЛЬ: вложенная роль и её вложенный селектор, НЕ зафиксированы ──
			tx, err := db.Begin()
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var writerPID int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&writerPID))
			_, err = tx.Exec(`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
			                  VALUES ('rol-ndrace', 'registry.ndrace', '[]'::jsonb, $1::jsonb, 'cluster_root')`, ndWholeRule)
			require.NoError(t, err, "писатель обязан записать роль — иначе сцена беспредметна")
			_, err = tx.Exec(`INSERT INTO kaname.role_rule_selectors
			    (role_id, rule_fp, arm, object_types, match_labels,
			     container_type, container_arm, container_resource_names, container_match_labels)
			    VALUES ('rol-ndrace', 'fp-ndrace', 'anchor', ARRAY['registry.repositories'], '{}'::jsonb,
			            'registry.registries', 'anchor', '{}'::text[], '{}'::jsonb)`)
			require.NoError(t, err, "писатель обязан записать вложенный селектор — иначе сцена беспредметна")

			goose.SetBaseFS(migrations.FS)
			require.NoError(t, goose.SetDialect("postgres"))
			done := make(chan error, 1)
			go func() { done <- goose.DownTo(db, ".", previous) }()

			// Ждём УСЛОВИЯ: откат стоит в очереди за замком писателя.
			waited := false
			for deadline := time.Now().Add(60 * time.Second); !waited && time.Now().Before(deadline); {
				select {
				case derr := <-done:
					t.Fatalf("откат завершился (%v), не дождавшись замка писателя — гонка не создана", derr)
				default:
				}
				var n int
				require.NoError(t, db.QueryRow(`
					SELECT count(*) FROM pg_locks
					 WHERE NOT granted AND pid <> $1 AND relation = ANY($2::oid[])`,
					writerPID, tables).Scan(&n))
				waited = n > 0
			}
			require.True(t, waited, "откат не встал в очередь за замком писателя за 60 с")
			if sc.commit {
				require.NoError(t, tx.Commit())
			} else {
				require.NoError(t, tx.Rollback())
			}
			var downErr error
			select {
			case downErr = <-done:
			case <-time.After(60 * time.Second):
				t.Fatal("откат не завершился за 60 с после того, как писатель освободил замок")
			}

			column := ndContainerColumnLeft(t, db)
			var written, carrying int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.role_rule_selectors
			                                 WHERE role_id = 'rol-ndrace'`).Scan(&written))
			if column {
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.role_rule_selectors
				                                 WHERE role_id = 'rol-ndrace' AND container_type IS NOT NULL`).Scan(&carrying))
			}
			lost := written - carrying
			t.Logf("исход: ошибка отката %v · колонка контейнера на месте %v · селекторов писателя %d · "+
				"из них с контейнером %d · потеряли контейнер %d", downErr, column, written, carrying, lost)

			if !sc.commit {
				require.NoError(t, downErr, "писатель не оставил ничего — откат обязан пройти")
				require.False(t, column, "прошедший откат снимает колонку контейнера")
				return
			}
			require.Error(t, downErr,
				"откат прошёл под зафиксированной вложенной ролью: подсчёт читал снимок без писателя")
			require.Contains(t, downErr.Error(), "withdraw the roles before rolling back",
				"отказ обязан прийти от подсчёта отката, а не от постороннего")
			require.True(t, column, "отказанный откат не снял колонку контейнера")
			require.Zero(t, lost, "селекторы с бывшим контейнером после отката: вложенное право "+
				"стало правом на все объекты типа")
		})
	}
}

// ndContainerColumnLeft — на месте ли колонка контейнера вложенного селектора.
func ndContainerColumnLeft(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var left bool
	require.NoError(t, db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                WHERE table_schema = 'kaname' AND table_name = 'role_rule_selectors'
		                  AND column_name = 'container_type')`).Scan(&left))
	return left
}
