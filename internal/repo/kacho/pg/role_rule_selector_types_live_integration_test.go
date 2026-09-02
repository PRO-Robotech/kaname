// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_rule_selector_types_live_integration_test.go — ТРЕТЬЯ поверхность
// проекции правила получила референт: каждый элемент
// `role_rule_selectors.object_types` называет ЖИВУЮ строку каталога.
//
// Приёмка: services/iam/docs/engineering/acceptance/roles-pointing-at-moved-resources.md
// (APPROVED круга 2), сценарии IAM-RM-1-08, -09, -10, -16. Задача продукта #1825.
//
// Предмет, довод в пользу триггера и выбор fail-closed разобраны в шапке миграции
// 20260902174500_selector_types_name_a_live_resource.sql — здесь они не
// пересказываются, чтобы не завести двух мест об одном предмете.
//
// ГРАНИЦА НАЗВАНА: утверждение «отказ приходит от базы» без базы недоказуемо,
// поэтому пробы формы у триггера нет и быть не может. Проба IAM-RM-1-16 читает
// ТЕКСТ миграции и о поведении не говорит ничего.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// selectorMigrationPrefix — префикс имени миграции-предмета. Текст читается ИЗ
// ПОСТАВЛЯЕМОГО ФАЙЛА (migrations.FS), а не переписывается в пробу: копия была бы
// вторым местом об одном предмете и разошлась бы с оригиналом молча.
const selectorMigrationPrefix = "20260902174500"

// writeSelector — прямая вставка строки селекторов. Прямая намеренно: предмет
// пробы — ТРИГГЕР, то есть инвариант, который обязан держаться независимо от
// писателя. Пиши проба через порт — она проверяла бы одного писателя из двух.
func writeSelector(ctx context.Context, pool *pgxpool.Pool,
	role domain.RoleID, fp string, types []string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors
		  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
		VALUES ($1, $2, 'anchor', $3, '{}', '{}'::jsonb, now(), now())`,
		string(role), fp, types)
	return err
}

// TestIAMRM108_SelectorNamingARetiredTypeIsRefused — IAM-RM-1-08.
//
// Отрицание идёт В ПАРЕ с положительным контролем: без него «отвергнуто» было бы
// неотличимо от таблицы, которая не принимает ничего.
func TestIAMRM108_SelectorNamingARetiredTypeIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)

	// ПРЕДПОСЫЛКА — факт каталога, а не наше допущение о нём.
	var retired int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.catalog_resource
		 WHERE dotted = 'compute.disk' AND NOT live`).Scan(&retired))
	require.Equalf(t, 1, retired, "ПРЕДПОСЫЛКА НАРУШЕНА: снятой строки compute.disk "+
		"в каталоге нет — отвергать было бы нечего, и молчание триггера ничего не значило бы")

	role := catalogRole(t, ctx, pool, "rm108")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип записывается.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-live", []string{"compute.instance"}),
		"контроль: живой тип отвергнут — триггер судит не то, что объявляет")

	err := writeSelector(ctx, pool, role, "fp-dead", []string{"compute.disk"})
	require.Error(t, err, "селектор со СНЯТЫМ типом принят")
	code, constraint := pgCode(err)
	require.Equal(t, "23514", code, "отказ пришёл не тем кодом: %v", err)
	require.Equal(t, "role_rule_selectors_types_live", constraint)
	require.Containsf(t, err.Error(), "compute.disk",
		"отказ не называет ЭЛЕМЕНТ — автор правила пойдёт перечитывать массив, "+
			"которого он не писал")
	require.Contains(t, err.Error(), string(role), "отказ не называет роль")

	// Строки нет: отказ пришёл ДО записи, а не после неё.
	var got int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_selectors
		 WHERE role_id = $1 AND rule_fp = 'fp-dead'`, string(role)).Scan(&got))
	require.Zero(t, got)
}

// TestIAMRM109_TriggerJudgesEveryElementNotTheFirst — IAM-RM-1-09.
//
// Массив, чей первый тип жив, а второй снят, — самая частая форма после ручной
// вычистки, и разбор, останавливающийся на первом, пропустил бы её целиком.
func TestIAMRM109_TriggerJudgesEveryElementNotTheFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	role := catalogRole(t, ctx, pool, "rm109")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: два живых элемента записываются.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-two-live",
		[]string{"compute.instance", "vpc.network"}))

	err := writeSelector(ctx, pool, role, "fp-second-dead",
		[]string{"compute.instance", "compute.snapshot"})
	require.Error(t, err, "снятый ВТОРОЙ элемент пропущен — разбор остановился на первом")
	require.Containsf(t, err.Error(), "compute.snapshot",
		"отказ называет не тот элемент: %v", err)
	require.NotContainsf(t, err.Error(), "compute.instance",
		"отказ называет ЖИВОЙ элемент — читатель пойдёт чинить исправное: %v", err)

	// ОБНОВЛЕНИЕ судится так же, как вставка: оба писателя пишут через
	// `ON CONFLICT … DO UPDATE`, и сужение `OF object_types` пропустило бы правку
	// массива через EXCLUDED.
	_, uerr := pool.Exec(ctx, `
		UPDATE kacho_iam.role_rule_selectors
		   SET object_types = ARRAY['compute.image']
		 WHERE role_id = $1 AND rule_fp = 'fp-two-live'`, string(role))
	require.Error(t, uerr, "обновление на снятый тип принято")
	require.Contains(t, uerr.Error(), "compute.image")
}

// TestIAMRM110_SystemRoleSelectorSeedPasses — IAM-RM-1-10, характеризующий замок.
//
// Утверждает, что fail-closed НЕ срабатывает на сегодняшнем дереве: литерал типов
// (`domain.AllMaterializableTypes`) и каталог сходятся. Требовать от этой пробы
// красноты запрещено — она обязана ПЕРЕЖИТЬ изменение.
func TestIAMRM110_SystemRoleSelectorSeedPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors`).Scan(&before))

	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool),
		"досев селекторов отвергнут триггером: литерал типов разошёлся с каталогом — "+
			"это и есть fail-closed §2.4, и чинится он приведением каталога, а не снятием триггера")

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors`).Scan(&after))
	t.Logf("перепись: строк селекторов до досева %d, после %d", before, after)
	require.NotZerof(t, after, "ПРЕДПОСЫЛКА НАРУШЕНА: селекторов ноль — досев прошёл "+
		"даром, и его зелёное ничего не говорит о согласии литерала с каталогом")

	// Вторая половина того же утверждения: ни одна строка, лежащая в таблице,
	// не называет снятого типа. Досев мог пройти и оставить прежние строки.
	var stale []string
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT t
		  FROM kacho_iam.role_rule_selectors s, unnest(s.object_types) AS t
		 WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_resource cr
		                    WHERE cr.dotted = t AND cr.live)`)
	require.NoError(t, err)
	for rows.Next() {
		var ty string
		require.NoError(t, rows.Scan(&ty))
		stale = append(stale, ty)
	}
	require.NoError(t, rows.Err())
	require.Emptyf(t, stale, "селекторы называют типы вне ЖИВОГО каталога: %s",
		strings.Join(stale, ", "))
}

// TestIAMRM116_MigrationRollbackDropsTheTriggerAndRestoresNothing — IAM-RM-1-16.
//
// Проба ФОРМЫ: читает текст поставляемой миграции. О поведении она не говорит
// ничего — это сказано вслух, чтобы её зелёное не читалось шире сделанного.
func TestIAMRM116_MigrationRollbackDropsTheTriggerAndRestoresNothing(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err)
	var body string
	var name string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), selectorMigrationPrefix) {
			continue
		}
		name = e.Name()
		raw, rerr := migrations.FS.ReadFile(e.Name())
		require.NoError(t, rerr)
		body = string(raw)
	}
	require.NotEmptyf(t, name, "ПРЕДПОСЫЛКА НАРУШЕНА: миграции с префиксом %s в "+
		"поставляемом наборе нет — судить не о чем", selectorMigrationPrefix)

	i := strings.Index(body, "-- +goose Down")
	require.Positivef(t, i, "у миграции %s нет откатной половины", name)
	down := strings.TrimSpace(body[i+len("-- +goose Down"):])
	require.NotEmptyf(t, down, "откатная половина %s ПУСТА: обратный путь объявлен "+
		"полным (§2.9) и не исполнен", name)
	require.Contains(t, down, "DROP TRIGGER")
	require.Contains(t, down, "role_rule_selectors_types_live")
	// Откат ничего не восстанавливает — иначе он вернул бы состояние, которого
	// миграция не отнимала: данных она не трогает вовсе.
	for _, forbidden := range []string{"INSERT INTO", "UPDATE kacho_iam.", "DELETE FROM"} {
		require.NotContainsf(t, down, forbidden,
			"откат %s трогает ДАННЫЕ (%s), хотя накат их не трогал", name, forbidden)
	}
}
