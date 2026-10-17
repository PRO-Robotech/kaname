// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// selector_container_retire_integration_test.go — СНЯТИЕ ТИПА-КОНТЕЙНЕРА
// вложенного правила из каталога (kaname#874, находка ревью круга 1).
//
// # Предмет
//
// У строки селектора ДВА вида ссылок на каталог: элементы `object_types` и тип
// контейнера вложенного правила (`container_type`). Страж живости
// (`role_rule_selectors_types_live`) судит оба и под одним замком. Вырезание
// применителя каталога и его план читали только `object_types` — значит снятие
// типа, названного лишь контейнером:
//
//   - при живых `object_types` строку не трогало вовсе — селектор оставался
//     называть снятый контейнер (повисший), и всякая следующая правка строки
//     отвергалась бы стражем по причине, которой у её автора нет;
//   - при снятии рядом и одного из `object_types` укорачивало строку
//     обновлением, страж на нём судил мёртвый контейнер, отвечал 23514 — и
//     применение каталога откатывалось ЦЕЛИКОМ.
//
// Сегодня вложенное правило несут лишь системные роли (они вне вырезания), и
// вход недостижим; при открытии вложенных правил арендатору он становится
// критичным. Пробы стоят на арендаторской роли — ровно на том входе.
//
// # Три сцены, одна из них — положительный контроль
//
//  1. ПЕРЕКОС ЗАПИСИ: вложенный селектор записан и НЕ зафиксирован, применитель
//     снимает его контейнер. Страж держит строку контейнера `FOR KEY SHARE`,
//     снятие ждёт фиксации — и вырезание, идущее следом, обязано увидеть
//     записанное. Исход — повисших ноль, строка снята целиком: вложенный
//     селектор без контейнера стал бы селектором верхнего уровня.
//  2. УКОРОЧЕНИЕ под мёртвым контейнером: снимаются контейнер и один из
//     `object_types` — применение обязано пройти, строка — сняться.
//  3. КОНТРОЛЬ: снятие типа, которого селектор не называет, вложенную строку не
//     трогает. Без него «строка снята» было бы неотличимо от вырезания, снимающего
//     всякий вложенный селектор.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// insertNestedSelector — вложенный селектор (контейнер якорем) в транзакции
// вызывающего. Модельное имя контейнера выводит страж — писатель его не пишет.
func insertNestedSelector(ctx context.Context, tx pgx.Tx, role domain.RoleID, fp string,
	types []string, container string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO kaname.role_rule_selectors
		  (role_id, rule_fp, arm, object_types, resource_names, match_labels,
		   container_type, container_arm, container_resource_names, container_match_labels,
		   created_at, updated_at)
		VALUES ($1, $2, 'anchor', $3, '{}', '{}'::jsonb, $4, 'anchor', '{}', '{}'::jsonb, now(), now())`,
		string(role), fp, types, container)
	return err
}

func writeNestedSelector(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role domain.RoleID,
	fp string, types []string, container string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	require.NoErrorf(t, insertNestedSelector(ctx, tx, role, fp, types, container),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: вложенный селектор над живыми типами обязан записаться")
	require.NoError(t, tx.Commit(ctx))
}

func selectorRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role domain.RoleID, fp string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.role_rule_selectors
	                                        WHERE role_id = $1 AND rule_fp = $2`, string(role), fp).Scan(&n))
	return n
}

// TestSelectorContainerRetire_WriteSkew — сцена 1.
func TestSelectorContainerRetire_WriteSkew(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	const (
		container = applierProbeModule + ".nestskewbox"
		child     = applierProbeModule + ".nestskewitem"
	)
	_, err := applier.Apply(ctx, probeManifest(
		probeResource("nestskewbox", "get"),
		probeResource("nestskewitem", "get"),
	))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "nest874skew")

	dangling0, list0 := selectorsNamingDeadTypes(t, ctx, pool)
	require.Zerof(t, dangling0, "на входе уже есть повисшие %v", list0)

	// ── ПИСАТЕЛЬ: вложенный селектор записан и НЕ зафиксирован ────────────────
	txB, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = txB.Rollback(ctx) }()
	var writerPID int
	require.NoError(t, txB.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID))
	require.NoErrorf(t, insertNestedSelector(ctx, txB, role, "fp-nest-skew", []string{child}, container),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой контейнер обязан записаться — иначе одновременности не из чего строить")

	// ── ПРИМЕНИТЕЛЬ: снимает контейнер, тип объекта остаётся ──────────────────
	done := make(chan error, 1)
	go func() {
		_, aerr := applier.Apply(ctx, probeManifest(probeResource("nestskewitem", "get")))
		done <- aerr
	}()

	// Ждём УСЛОВИЯ: снятие стоит за замком писателя.
	blocked := false
	for deadline := time.Now().Add(60 * time.Second); !blocked && time.Now().Before(deadline); {
		select {
		case aerr := <-done:
			t.Fatalf("применение завершилось (%v), не дождавшись записи вложенного селектора — "+
				"общего замка нет, и стороны разошлись по своим снимкам", aerr)
		default:
		}
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid))`,
			writerPID).Scan(&n))
		blocked = n > 0
	}
	require.True(t, blocked, "снятие контейнера не встало за записью селектора за 60 с — гонка не создана")
	require.NoError(t, txB.Commit(ctx))

	var aerr error
	select {
	case aerr = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("применение не завершилось за 60 с после фиксации писателя")
	}

	dangling1, list1 := selectorsNamingDeadTypes(t, ctx, pool)
	rows := selectorRowsOf(t, ctx, pool, role, "fp-nest-skew")
	t.Logf("исход: применение %v · повисших %d %v · строк вложенного селектора %d", aerr, dangling1, list1, rows)

	require.NoErrorf(t, aerr, "применение, снимающее контейнер, отвергнуто")
	require.Zerof(t, dangling1, "вложенный селектор остался называть снятый контейнер: %v — вырезание "+
		"читает только object_types", list1)
	require.Zerof(t, rows, "вложенный селектор без живого контейнера обязан сняться целиком")
}

// TestSelectorContainerRetire_ShorteningUnderADeadContainer — сцена 2.
func TestSelectorContainerRetire_ShorteningUnderADeadContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	const (
		container = applierProbeModule + ".nestcutbox"
		kept      = applierProbeModule + ".nestcutkept"
		gone      = applierProbeModule + ".nestcutgone"
	)
	_, err := applier.Apply(ctx, probeManifest(
		probeResource("nestcutbox", "get"),
		probeResource("nestcutkept", "get"),
		probeResource("nestcutgone", "get"),
	))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "nest874cut")
	writeNestedSelector(t, ctx, pool, role, "fp-nest-cut", []string{kept, gone}, container)

	_, aerr := applier.Apply(ctx, probeManifest(probeResource("nestcutkept", "get")))

	dangling, list := selectorsNamingDeadTypes(t, ctx, pool)
	rows := selectorRowsOf(t, ctx, pool, role, "fp-nest-cut")
	var recorded int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.role_selector_prune
	                                        WHERE role_id = $1 AND rule_fp = 'fp-nest-cut' AND outcome = 'dropped'
	                                          AND coalesce(retired_reason, '') <> ''`, string(role)).Scan(&recorded))
	t.Logf("исход: применение %v · повисших %d %v · строк %d · записано в ведомость вырезания %d",
		aerr, dangling, list, rows, recorded)

	require.NoErrorf(t, aerr, "применение отвергнуто: укорочение строки под мёртвым контейнером судит "+
		"страж живости, и он отвечает 23514")
	require.Zerof(t, dangling, "повисшие после применения: %v", list)
	require.Zerof(t, rows, "вложенный селектор без живого контейнера обязан сняться целиком")
	require.Equalf(t, 2, recorded, "вырезанное обязано лечь в ведомость с причиной снятия — по элементу "+
		"на тип строки, исход «снята целиком»")
}

// TestSelectorContainerRetire_UnrelatedRetireKeepsTheNestedSelector — сцена 3,
// положительный контроль.
func TestSelectorContainerRetire_UnrelatedRetireKeepsTheNestedSelector(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	const (
		container = applierProbeModule + ".nestkeepbox"
		child     = applierProbeModule + ".nestkeepitem"
	)
	_, err := applier.Apply(ctx, probeManifest(
		probeResource("nestkeepbox", "get"),
		probeResource("nestkeepitem", "get"),
		probeResource("nestkeepother", "get"),
	))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "nest874keep")
	writeNestedSelector(t, ctx, pool, role, "fp-nest-keep", []string{child}, container)

	_, err = applier.Apply(ctx, probeManifest(
		probeResource("nestkeepbox", "get"),
		probeResource("nestkeepitem", "get"),
	))
	require.NoError(t, err, "снятие постороннего типа отвергнуто")

	var gotContainer string
	var gotTypes []string
	require.NoError(t, pool.QueryRow(ctx, `SELECT container_type, object_types FROM kaname.role_rule_selectors
	                                        WHERE role_id = $1 AND rule_fp = 'fp-nest-keep'`, string(role)).
		Scan(&gotContainer, &gotTypes))
	dangling, list := selectorsNamingDeadTypes(t, ctx, pool)
	t.Logf("исход: контейнер %s · типы %v · повисших %d %v", gotContainer, gotTypes, dangling, list)
	require.Equal(t, container, gotContainer, "снятие постороннего типа тронуло контейнер вложенного селектора")
	require.Equal(t, []string{child}, gotTypes)
	require.Zerof(t, dangling, "повисшие после снятия постороннего типа: %v", list)
}
