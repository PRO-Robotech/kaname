// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_role_upsert_integration_test.go — ОПЕРАТОР применителя ролей модуля
// доводится до настоящего Postgres (приёмка
// `services/iam/docs/engineering/acceptance/roles-come-as-data-not-migrations.md`
// §3.1, §3.5; задача #1824).
//
// # Дефект, ради которого проба написана
//
// Ветвь приведения `UpsertSystemRole` присваивала `updated_at`, а столбца с
// таким именем у `kacho_iam.roles` НЕТ НИКОГДА: перепись DDL по всем 153
// миграциям даёт десять столбцов при создании и девять операций над столбцами
// после (`organization_id` снят, `rules`, `labels`, `is_system` заведены), и
// `updated_at` среди них не значится ни разу. Контроль в обратную сторону:
// тот же предикат находит `updated_at` у ДВЕНАДЦАТИ других таблиц схемы
// (`memberships`, `role_rule_selectors`, `watch_cursors`, …), то есть столбец
// он видеть умеет.
//
// Неизвестный столбец в `ON CONFLICT DO UPDATE SET` — ошибка РАЗБОРА всего
// оператора (`42703 undefined_column`), а не ветви приведения. Значит отказ
// приходил на ПЕРВОМ ЖЕ вызове, включая вставку: применитель не записал бы ни
// одной роли ни при каком входе, и центральное решение приёмки было
// неисполнимо by construction.
//
// # Почему это не покраснело раньше
//
// Ни одна проба не доводила оператор до Postgres. Дублёр писателя
// (`moduleroles/apply_test.go`) переписывает семантику на Go — приведение при
// отличии, ноль записей при совпадении — и перечня столбцов не видит НИКОГДА.
// Дублёр был верен в том, что утверждал, и слеп ровно к тому, что сломалось.
// Эта проба закрывает ту слепоту: она не сверяет текст оператора, она его
// ИСПОЛНЯЕТ.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// declaredModuleRole — системная роль модуля в том виде, в каком её объявляет
// манифест: ярус кластерный, `id` производится ИЗ ИМЕНИ той же функцией, что
// адресует уже посеянные строки (§3.7).
func declaredModuleRole(t *testing.T, name, description string, rules domain.Rules) domain.Role {
	t.Helper()
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err, "объявленное правило обязано сворачиваться в разрешения")
	return domain.Role{
		ID:          domain.SystemRoleID(domain.RoleName(name)),
		ClusterID:   domain.ClusterSingletonID,
		Name:        domain.RoleName(name),
		Description: domain.Description(description),
		Rules:       rules,
		Permissions: compiled,
	}
}

// requireNotAParseFailure — отказ разбора называется ПО ИМЕНИ, а не приходит
// как «что-то пошло не так».
//
// Отображение отказов сохраняет код состояния в цепочке
// (`pgmaperr.go`: «database error: sqlstate %s»), поэтому 42703 доезжает до
// пробы дословно — и падение указывает на причину, а не на симптом.
func requireNotAParseFailure(t *testing.T, err error, step string) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "42703") {
		t.Fatalf("%s: оператор НЕ РАЗОБРАН — он ссылается на столбец, которого у "+
			"kacho_iam.roles нет: %v\n"+
			"Это отказ разбора ВСЕГО оператора, а не его ветви приведения: применитель "+
			"не запишет ни одной роли ни при каком входе.", step, err)
	}
}

// TestMODRD12UpsertSystemRoleOperatorRunsAgainstTheLiveRolesTable — оператор
// применителя исполняется настоящим сервером на настоящей таблице.
//
// Три захода одним оператором, и каждый есть отдельное утверждение:
//   - вставки не было — строка заводится, `changed` истинно;
//   - объявленное совпало — ноль затронутых строк, `changed` ложно;
//   - объявленное отличается — строка приводится, `changed` истинно, а метки и
//     время создания арендатора остаются нетронутыми.
func TestMODRD12UpsertSystemRoleOperatorRunsAgainstTheLiveRolesTable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие — С ПРЕДЕЛОМ, а не `defer pool.Close()`: проба, упавшая внутри
	// открытой транзакции, соединение не вернёт, и отложенное закрытие ждало бы
	// его вечно, унося вердикт ВСЕГО пакета. Очистка исполняется после
	// `defer w.Rollback` тела, поэтому на исправном ходу не меняется ничто.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	const name = "vpc.probe1824.admin"
	declared := declaredModuleRole(t, name, "Роль модуля, объявленная манифестом.",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})

	// ── 1. Вставки не было: строка заводится ────────────────────────────────
	inserted, changed, err := upsertSystemRoleTx(ctx, t, repo, declared)
	requireNotAParseFailure(t, err, "первый заход (вставка)")
	require.NoError(t, err, "объявленная роль обязана записаться")
	assert.True(t, changed, "первый заход обязан сообщить, что строка заведена")
	assert.Equal(t, declared.ID, inserted.ID)
	assert.Equal(t, declared.Name, inserted.Name)
	assert.True(t, inserted.IsSystem,
		"ярус вычисляется из непустого cluster_id — строка обязана быть системной")
	require.False(t, inserted.CreatedAt.IsZero(), "время создания обязано быть проставлено")

	// Метка арендатора ставится ПОСЛЕ применителя: она не объявлена манифестом,
	// и приведение её трогать не вправе. Без неё третий заход не отличил бы
	// «сохранили» от «нечего было терять».
	_, err = pool.Exec(ctx,
		`UPDATE roles SET labels = '{"owner":"tenant"}'::jsonb WHERE id = $1`, string(declared.ID))
	require.NoError(t, err)

	// ── 2. Объявленное совпало: ноль затронутых строк ───────────────────────
	_, changed, err = upsertSystemRoleTx(ctx, t, repo, declared)
	requireNotAParseFailure(t, err, "повторное применение того же объявления")
	require.NoError(t, err, "повторное применение — ШТАТНЫЙ исход, а не отказ")
	assert.False(t, changed,
		"объявленное состояние уже стоит в строке — приведения быть не должно")

	// ── 3. Объявленное отличается: строка приводится ────────────────────────
	amended := declaredModuleRole(t, name, "Описание, изменённое манифестом.",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"}}})
	out, changed, err := upsertSystemRoleTx(ctx, t, repo, amended)
	requireNotAParseFailure(t, err, "приведение к изменённому объявлению")
	require.NoError(t, err, "приведение обязано исполниться")
	assert.True(t, changed, "объявление отличается — строка обязана быть приведена")
	assert.Equal(t, domain.Description("Описание, изменённое манифестом."), out.Description)
	assert.Equal(t, []string{"get", "list"}, []string(out.Rules[0].Verbs))
	assert.Equal(t, domain.Labels{"owner": "tenant"}, out.Labels,
		"метки арендатора манифестом не объявлены — приведение их не трогает")
	assert.WithinDuration(t, inserted.CreatedAt, out.CreatedAt, 0,
		"время создания приведением не переписывается")
}

// TestMODRD12UpsertSystemRoleRefusesARowWithoutAClusterTier — отрицание в паре
// с положительным выше, и у него НАЗВАН производитель.
//
// Утверждается не «пришёл отказ» — на неразобранном операторе отказ приходит
// всегда, и такое утверждение зеленело бы на сломанном. Утверждается, что
// отказ пришёл от ЯРУСА: строка без кластера системной не бывает, и решает это
// база (`roles_cluster_fk` / `roles_definition_tier_xor`), а не проверка в Go.
func TestMODRD12UpsertSystemRoleRefusesARowWithoutAClusterTier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие — С ПРЕДЕЛОМ, а не `defer pool.Close()`: проба, упавшая внутри
	// открытой транзакции, соединение не вернёт, и отложенное закрытие ждало бы
	// его вечно, унося вердикт ВСЕГО пакета. Очистка исполняется после
	// `defer w.Rollback` тела, поэтому на исправном ходу не меняется ничто.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	tierless := declaredModuleRole(t, "vpc.probe1824.view", "Роль без яруса.",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
	tierless.ClusterID = ""

	_, _, err = upsertSystemRoleTx(ctx, t, repo, tierless)
	require.Error(t, err, "строка без кластерного яруса системной ролью не станет")
	requireNotAParseFailure(t, err, "отказ по ярусу")
	assert.NotContains(t, err.Error(), "42703",
		"отказ обязан прийти от ЯРУСА, а не от разбора оператора")
	assert.ErrorIs(t, err, iamerr.ErrFailedPrecondition,
		"производитель отказа — внешний ключ на кластер (`roles_cluster_fk`), "+
			"и его класс есть предусловие, а не поломка сервиса")
}

// upsertSystemRoleTx — один заход применителя: писательская транзакция, один
// оператор, фиксация. Транзакция закрывается ВСЕГДА: голый require на отказе
// прервал бы тест до фиксации, и удержанное соединение не вернулось бы в пул.
func upsertSystemRoleTx(
	ctx context.Context, t *testing.T, repo *kachopg.Repository, r domain.Role,
) (domain.Role, bool, error) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	out, changed, err := w.RolesW().UpsertSystemRole(ctx, r)
	if err != nil {
		return domain.Role{}, false, err
	}
	require.NoError(t, w.Commit(ctx))
	return out, changed, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ВЛАДЕНИЕ РОЛЬЮ — писатель (задача продукта #1032, сценарии IAM-OM-1-14, -15).
//
// Столбец, который ПИШУТ и не ЧИТАЮТ, невидим отовсюду: его нет ни в ответе, ни
// в объекте в памяти. Здесь цена такой невидимости названа точно —
// `PolicyOfRole` получил бы пустого владельца у роли, которая им обладает, и
// судил бы её ПЛАТФОРМЕННОЙ, то есть самой мягкой. Поэтому проба идёт по всей
// цепочке: объявление → оператор → строка → чтение.

// ownedModuleRole — объявленная роль модуля С ВЛАДЕЛЬЦЕМ. Имя составляется из
// владельца: этого требует проверка строки `roles_owner_module_name_prefix`, и
// подать сюда несоставленное имя значило бы получить отказ ЧУЖОГО ограничения.
func ownedModuleRole(t *testing.T, owner, name, description string, rules domain.Rules) domain.Role {
	t.Helper()
	r := declaredModuleRole(t, name, description, rules)
	r.OwnerModule = owner
	return r
}

// TestIAMOM115_OwnerModuleSurvivesTheWriterAndTheRepeatedApply — IAM-OM-1-15.
//
// Свойство «повторное применение не пишет ничего» держится предикатом отличия в
// `ON CONFLICT DO UPDATE … WHERE`; сценарий утверждает, что новая колонка его НЕ
// ЛОМАЕТ — и что она доезжает до строки и обратно.
func TestIAMOM115_OwnerModuleSurvivesTheWriterAndTheRepeatedApply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	declared := ownedModuleRole(t, "vpc", "vpc.probe1032.viewer", "Роль модуля с владельцем.",
		domain.Rules{{Module: "vpc", Resources: []string{"*"}, Verbs: []string{"get"}}})

	inserted, changed, err := upsertSystemRoleTx(ctx, t, repo, declared)
	require.NoError(t, err, "роль модуля с владельцем обязана записаться")
	require.True(t, changed)
	require.Equal(t, "vpc", inserted.OwnerModule,
		"владелец обязан ДОЕХАТЬ обратно: столбец, который пишут и не читают, невидим "+
			"отовсюду, и политика роли читалась бы платформенной — самой мягкой")
	require.True(t, inserted.IsSystem,
		"признак системности НЕ меняется ни на одну строку: арендатор роль модуля не правит")

	// Строка судится ПО СТРОКЕ, а не по объекту: столбец мог бы заполняться в
	// памяти и не доезжать до таблицы.
	var stored *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT owner_module FROM roles WHERE id = $1`, string(declared.ID)).Scan(&stored))
	require.NotNil(t, stored)
	require.Equal(t, "vpc", *stored)

	// Повторное применение того же объявления не пишет ничего.
	_, changed, err = upsertSystemRoleTx(ctx, t, repo, declared)
	require.NoError(t, err, "повторное применение — ШТАТНЫЙ исход")
	require.False(t, changed,
		"новая колонка сломала бы предикат отличия, если бы читалась не тем способом, "+
			"каким пишется")
}

// TestIAMOM114_TwoProvidersDeclareTheSameLeafName — IAM-OM-1-14.
//
// Пространство имён системных ролей плоское и глобальное
// (`roles_system_unique UNIQUE (cluster_id, name) WHERE is_system`). Без
// составления имени второй поставщик со своим `viewer` получал бы 23505 по
// причине, от него не зависящей.
//
// Порядок применения на исход не влияет — утверждается обоими: иначе сценарий
// зеленел бы на реализации, где вторая молча перезаписывает первую.
func TestIAMOM114_TwoProvidersDeclareTheSameLeafName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	vpc := ownedModuleRole(t, "vpc", "vpc.viewer", "Наблюдатель сети.",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
	compute := ownedModuleRole(t, "compute", "compute.viewer", "Наблюдатель машин.",
		domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}})

	for _, order := range [][]domain.Role{{vpc, compute}, {compute, vpc}} {
		for _, r := range order {
			out, _, uerr := upsertSystemRoleTx(ctx, t, repo, r)
			require.NoErrorf(t, uerr,
				"роль %q поставщика %q обязана применяться независимо от порядка",
				r.Name, r.OwnerModule)
			if out.ID != "" {
				require.Equal(t, r.OwnerModule, out.OwnerModule)
			}
		}
	}

	var owners []string
	rows, err := pool.Query(ctx,
		`SELECT owner_module FROM roles WHERE name IN ('vpc.viewer','compute.viewer') ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var o *string
		require.NoError(t, rows.Scan(&o))
		require.NotNil(t, o, "у роли модуля владелец обязан быть непустым")
		owners = append(owners, *o)
	}
	require.NoError(t, rows.Err())
	t.Logf("перепись: строк с листовым именем viewer %d, владельцы %v", len(owners), owners)
	require.Equal(t, []string{"compute", "vpc"}, owners,
		"обе строки записаны, у каждой СВОЙ владелец — вторая первую не перезаписала")
}
