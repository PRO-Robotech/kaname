// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_ownership_tier_integration_test.go — ЯРУС ВЛАДЕНИЯ роли отделён от
// кластерного якоря; инвариант держит СТРОКА, а не разбор.
//
// Задача продукта #1032 (P0). Приёмка — APPROVED круга 2,
// `services/iam/docs/engineering/acceptance/role-ownership-tier-apart-from-cluster-anchor.md`,
// сценарии IAM-OM-1-06 … -12. Миграция —
// `20260902190500_role_ownership_tier_apart_from_cluster_anchor.sql`.
//
// # Что здесь утверждается
//
// Что негодная строка перестала быть ВСТАВИМОЙ, и перестала by construction —
// проверкой таблицы, а не тем, что «домен её раньше отвергнет». Домен и правда
// отвергнет: обе величины сервис проверяет сам, до вставки. Но предикат
// готовности задачи требует гейта, читающего ВСТАВЛЕННУЮ строку, и требует его
// именно потому, что разбор — это перечень путей записи, а перечень меняется
// молча (ban #10 буквально).
//
// # Обе стороны на каждой оси, и положительные половины — не украшение
//
//	подстановка модуля  роль С владельцем        → 23514 roles_rule_wildcards_confined
//	подстановка модуля  роль БЕЗ владельца       → проходит          (иначе -06 зеленел бы на проверке, отвергающей подстановку у всех)
//	подстановка ресурса в СВОЁМ модуле           → проходит
//	подстановка ресурса в ЧУЖОМ модуле           → 23514 roles_rule_wildcards_confined
//	имя не от владельца                          → 23514 roles_owner_module_name_prefix
//	имя без точки-разделителя                    → 23514 того же ограничения
//	владелец вне каталога                        → 23503 roles_owner_module_fk
//	владелец в каталоге                          → проходит          (иначе -10 зеленел бы на ключе, отвергающем ВСЯКОГО владельца)
//	владелец СНЯТ из каталога                    → проходит          — названное следствие формы ключа, не удача
//	снятие модуля при живой роли                 → проходит          — близнец IAM-MW-1-08 соседней APPROVED-приёмки
//
// # Имя ограничения — часть сценария
//
// Под другим именем отвечал бы другой ключ, и проба зеленела бы на чужом
// отказе. То же требование, что у соседа уровнем каталога.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// insertSystemRole — прямая вставка системной строки роли В ОБХОД применителя.
//
// Обход здесь не нарушение дисциплины, а предмет: сценарии утверждают, что
// негодную строку отвергает САМА ТАБЛИЦА, а не тот, кто её сегодня пишет.
// Писать через порт значило бы проверять порт.
func insertSystemRole(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, name string, owner *string, rules string) error {
	_, err := q.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, cluster_id, name, description, permissions, rules, owner_module)
		VALUES ($1, $2, $3, $4, '[]'::jsonb, $5::jsonb, $6)`,
		ids.NewID(domain.PrefixRole), domain.ClusterSingletonID, name,
		"ярус владения роли, проба #1032", rules, owner)
	return err
}

// ownedRules — правила роли в форме СТРОКИ (`verbs`, скалярный `module`), а не
// в форме ключа YAML манифеста (`classes`). Форму судит `iam_rules_valid`
// (0033), и подать сюда ключ манифеста значило бы получить отказ ЧУЖОГО
// ограничения — то есть зелень, не проверившую своего.
func ownedRules(module string, resources ...string) string {
	list := ""
	for i, r := range resources {
		if i > 0 {
			list += ","
		}
		list += fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf(`[{"module":%q,"resources":[%s],"verbs":["get"]}]`, module, list)
}

// liveCatalogModule — живой модуль каталога, ВЫВЕДЕННЫЙ из посева.
//
// Литерал связал бы пробу с составом посева: он растёт, и выписанное имя
// устарело бы молча — либо, хуже, указало бы на снятый модуль, и тогда ключ
// отвечал бы не тем, что сценарий утверждает.
func liveCatalogModule(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var module string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT module FROM kacho_iam.catalog_module WHERE live ORDER BY module LIMIT 1`).Scan(&module),
		"живого модуля каталога не нашлось — сценарий вакуумен, а не пройден")
	return module
}

// TestRolesCarryTheOwnershipTier — предпосылка всех сценариев ниже: колонка и
// три ограничения на месте И ПРОВЕРЕНЫ.
//
// Невалидированное ограничение планировщик доказанным не считает, поэтому
// «ограничение есть» и «ограничение проверено» — разные утверждения, и здесь
// нужно второе.
func TestRolesCarryTheOwnershipTier(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	var validated int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint
		 WHERE conrelid = 'kacho_iam.roles'::regclass
		   AND conname IN ('roles_owner_module_fk','roles_rule_wildcards_confined',
		                   'roles_owner_module_name_prefix')
		   AND convalidated`).Scan(&validated))

	var owned, platform int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE owner_module IS NOT NULL),
		       count(*) FILTER (WHERE owner_module IS NULL)
		  FROM kacho_iam.roles`).Scan(&owned, &platform))

	mods, _, _ := liveCatalogCounts(t, ctx, pool)
	// Перепись печатается ВСЕГДА: «ролей с владельцем ноль» — ожидаемое
	// состояние сразу после миграции, и оно обязано быть отличимо от «строк не
	// читали».
	t.Logf("перепись: ролей с владельцем %d · платформенных %d · живых модулей каталога %d · "+
		"проверенных ограничений владения %d из 3", owned, platform, mods, validated)

	require.Equal(t, 3, validated,
		"ограничения владения обязаны быть ПРОВЕРЕНЫ: NOT VALID без VALIDATE планировщик "+
			"доказанным не считает, и сценарии ниже утверждали бы про необязательное")
	require.Positive(t, platform,
		"платформенных ролей ноль — тогда утверждение «обратного заполнения не требуется» "+
			"вакуумно: заполнять было нечего")
}

// TestModuleWildcardInAnOwnedRoleIsRefusedByTheRow — IAM-OM-1-06.
func TestModuleWildcardInAnOwnedRoleIsRefusedByTheRow(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	module := liveCatalogModule(t, ctx, pool)

	err := insertSystemRole(ctx, pool, module+".wildmod", &module, ownedRules("*", "network"))
	require.Errorf(t, err, "строка с владельцем %q и подстановкой модуля обязана отвергаться", module)
	code, constraint := pgCode(err)
	t.Logf("владелец %q, module \"*\": SQLSTATE %s, ограничение %q", module, code, constraint)
	require.Equal(t, "23514", code)
	require.Equal(t, "roles_rule_wildcards_confined", constraint,
		"имя ограничения — часть сценария: под другим именем отвечал бы другой ключ")
}

// TestModuleWildcardWithoutAnOwnerPasses — IAM-OM-1-07, положительный контроль.
//
// Без него -06 зеленел бы на проверке, отвергающей подстановку у ВСЕХ, и мы
// отозвали бы у платформенной роли уже выданное послабление.
func TestModuleWildcardWithoutAnOwnerPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	require.NoError(t,
		insertSystemRole(ctx, pool, "platform-wildmod", nil, ownedRules("*", "*")),
		"платформенная роль (owner_module IS NULL) послабления подстановки НЕ теряет — "+
			"обратное было бы отзывом уже выданного")
}

// TestResourceWildcardInsideTheOwningModulePasses — IAM-OM-1-08.
func TestResourceWildcardInsideTheOwningModulePasses(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	module := liveCatalogModule(t, ctx, pool)

	require.NoError(t,
		insertSystemRole(ctx, pool, module+".ownwild", &module, ownedRules(module, "*")),
		"подстановка ресурса В СВОЁМ модуле законна: она находится в модуле своего правила, "+
			"и этот модуль есть владелец")
}

// TestResourceWildcardOutsideTheOwningModuleIsRefused — IAM-OM-1-06, вторая ось
// того же ограничения: подстановка ресурса при ЧУЖОМ модуле.
func TestResourceWildcardOutsideTheOwningModuleIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	var owner, foreign string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT module FROM kacho_iam.catalog_module WHERE live ORDER BY module LIMIT 1),
		       (SELECT module FROM kacho_iam.catalog_module WHERE live ORDER BY module DESC LIMIT 1)`).
		Scan(&owner, &foreign))
	require.NotEqual(t, owner, foreign,
		"живых модулей каталога меньше двух — сценарий «чужой модуль» невыразим, а не пройден")

	err := insertSystemRole(ctx, pool, owner+".foreignwild", &owner, ownedRules(foreign, "*"))
	require.Error(t, err)
	code, constraint := pgCode(err)
	t.Logf("владелец %q, правило над %q с ресурсом \"*\": SQLSTATE %s, ограничение %q",
		owner, foreign, code, constraint)
	require.Equal(t, "23514", code)
	require.Equal(t, "roles_rule_wildcards_confined", constraint)
}

// TestRoleNameNotComposedFromTheOwnerIsRefused — IAM-OM-1-09, обе половины.
//
// Вторая половина (`vpcviewer` — совпадает по префиксу БЕЗ точки) отдельным
// входом: без неё проверка сравнивала бы начало строки, а не сегмент.
func TestRoleNameNotComposedFromTheOwnerIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	module := liveCatalogModule(t, ctx, pool)

	for _, tc := range []struct {
		name string
		why  string
	}{
		{"otherprefix.viewer", "имя составлено из ЧУЖОГО модуля"},
		{module + "viewer", "префикс совпадает БЕЗ точки-разделителя — это не сегмент"},
	} {
		err := insertSystemRole(ctx, pool, tc.name, &module, ownedRules(module, "network"))
		require.Errorf(t, err, "%s: %s", tc.name, tc.why)
		code, constraint := pgCode(err)
		t.Logf("владелец %q, имя %q: SQLSTATE %s, ограничение %q (%s)",
			module, tc.name, code, constraint, tc.why)
		require.Equal(t, "23514", code, tc.name)
		require.Equal(t, "roles_owner_module_name_prefix", constraint, tc.name)
	}

	// Законный близнец: имя, составленное из владельца, проходит. Без него оба
	// отрицания зеленели бы на проверке, отвергающей ВСЯКОЕ имя.
	require.NoError(t,
		insertSystemRole(ctx, pool, module+".viewer", &module, ownedRules(module, "network")))
}

// TestOwnerOutsideTheModuleCatalogIsRefusedByTheKey — IAM-OM-1-10, обе стороны.
func TestOwnerOutsideTheModuleCatalogIsRefusedByTheKey(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	nosuch := "nosuch"
	err := insertSystemRole(ctx, pool, nosuch+".viewer", &nosuch, ownedRules("iam", "account"))
	require.Error(t, err, "владелец вне каталога модулей обязан отвергаться КЛЮЧОМ")
	code, constraint := pgCode(err)
	t.Logf("владелец %q: SQLSTATE %s, ключ %q", nosuch, code, constraint)
	require.Equal(t, "23503", code)
	require.Equal(t, "roles_owner_module_fk", constraint)

	// Положительный контроль: живой модуль каталога проходит — иначе сценарий
	// зеленел бы на ключе, отвергающем ВСЯКОГО владельца.
	module := liveCatalogModule(t, ctx, pool)
	require.NoError(t,
		insertSystemRole(ctx, pool, module+".livecheck", &module, ownedRules(module, "network")))
}

// TestOwnerRetiredFromTheCatalogIsNotRefused — IAM-OM-1-11.
//
// Сценарий закрепляет ВЫБРАННУЮ семантику, а не удачу реализации: ключ идёт на
// первичный ключ каталога и о живости не спрашивает. Его обязано ПЕРЕВЕРНУТЬ то
// изменение, которое даст роли собственную живость (#1913); до тех пор его
// зелень означает «состояние представимо и названо», а не «дыры нет».
func TestOwnerRetiredFromTheCatalogIsNotRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	// Снятие модуля идёт ПОЛНЫМ административным путём (глаголы → ресурсы →
	// строка модуля): ключи живости соседних уровней держат этот порядок, и
	// снять одну строку модуля нельзя by construction. Помощник тот же, каким
	// пользуется проба соседней приёмки, — своего второго писателя здесь не
	// заводится.
	verbs, refs := withdrawModule(t, ctx, pool, withdrawnModule, "проба #1032 -11")
	t.Logf("модуль %q снят: переселено выдач %d, объявлений %d", withdrawnModule, verbs, refs)

	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kacho_iam.catalog_module WHERE module = $1`, withdrawnModule).Scan(&live))
	require.False(t, live, "предпосылка сценария: модуль снят")

	owner := withdrawnModule
	require.NoError(t,
		insertSystemRole(ctx, pool, owner+".afterretire", &owner, ownedRules(owner, "registry")),
		"роль со СНЯТЫМ владельцем записывается: ключ адресует строку каталога независимо от "+
			"её живости. Это названное следствие формы ключа (#1913), а не дыра, найденная пробой")
	t.Logf("состояние «модуль %q снят, а роль с этим владельцем записана» ПРЕДСТАВИМО — "+
		"остаток назван и заведён задачей #1913", owner)
}

// TestRetiringAModuleThatOwnsARolePasses — IAM-OM-1-12, близнец IAM-MW-1-08.
//
// Прямой ответ на вопрос «не отбирает ли эта задача свойство, которое сосед
// доказал прогоном»: снятие модуля при живой роли обязано ПРОХОДИТЬ и до, и
// после миграции. Именно этот вход отверг форму ключа живости (§2.1 приёмки):
// с ключом на пару `(module, live)` строка роли отпускала бы референт только
// своим удалением, а удаления у роли модуля нет ни одного.
func TestRetiringAModuleThatOwnsARolePasses(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	owner := withdrawnModule
	require.NoError(t,
		insertSystemRole(ctx, pool, owner+".stillhere", &owner, ownedRules(owner, "registry")),
		"предпосылка сценария: у модуля есть живая роль")

	verbs, refs := withdrawModule(t, ctx, pool, owner, "проба #1032 -12")

	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kacho_iam.catalog_module WHERE module = $1`, owner).Scan(&live))
	require.Falsef(t, live,
		"снятие модуля %q при живой роли обязано ПРОХОДИТЬ: обратное отобрало бы у соседа "+
			"свойство, доказанное его прогоном (IAM-MW-1-08)", owner)

	var roles int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles WHERE owner_module = $1`, owner).Scan(&roles))
	t.Logf("модуль %q снят (переселено выдач %d, объявлений %d), ролей с этим владельцем "+
		"осталось %d — остаток назван (#1913), а не спрятан", owner, verbs, refs, roles)
	require.Positive(t, roles)
}
