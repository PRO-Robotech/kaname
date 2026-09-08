// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//	владелец СНЯТ из каталога                    → 23503 roles_owner_module_live_fk   ← ПЕРЕВЁРНУТО (#2026)
//	снятие модуля при ЖИВОЙ роли                 → 23503 roles_owner_module_live_fk   ← ПЕРЕВЁРНУТО (#2026)
//	снятие модуля, все роли которого СНЯТЫ       → проходит          — без этой половины два отрицания выше
//	                                                                  неотличимы от «модуль снять нельзя никогда»
//
// # Две последние строки ПЕРЕВЁРНУТЫ, и переворот был ЗАКАЗАН, а не случился
//
// До #2026 обе читались «проходит», и это было верно: ключ шёл на первичный ключ
// каталога и о живости не спрашивал. Шапки обоих сценариев называли условие
// своего переворота дословно — «его обязано ПЕРЕВЕРНУТЬ то изменение, которое
// даст роли собственную живость (#1913)». Условие наступило: пометка снятия роли
// в дереве есть, производитель провязан, и `roles_owner_module_live_fk` делает
// оба состояния непредставимыми.
//
// Форма самоистечения сработала как задумана: проба не «сломалась» и не была
// ослаблена — она ЗАМЕНЕНА утверждением о новом свойстве того же предмета.
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

	"github.com/PRO-Robotech/kaname/internal/domain"
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
		INSERT INTO kaname.roles (id, cluster_id, name, description, permissions, rules, owner_module)
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
		SELECT module FROM kaname.catalog_module WHERE live ORDER BY module LIMIT 1`).Scan(&module),
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
		 WHERE conrelid = 'kaname.roles'::regclass
		   AND conname IN ('roles_owner_module_fk','roles_rule_wildcards_confined',
		                   'roles_owner_module_name_prefix')
		   AND convalidated`).Scan(&validated))

	var owned, platform int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE owner_module IS NOT NULL),
		       count(*) FILTER (WHERE owner_module IS NULL)
		  FROM kaname.roles`).Scan(&owned, &platform))

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
		SELECT (SELECT module FROM kaname.catalog_module WHERE live ORDER BY module LIMIT 1),
		       (SELECT module FROM kaname.catalog_module WHERE live ORDER BY module DESC LIMIT 1)`).
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

// retireModuleReturningErr — снятие модуля ПОЛНЫМ путём, отдающее ошибку
// последнего шага вызывающему.
//
// Своим помощником, а не `withdrawModule`: тот роняет пробу через
// `require.NoError` и потому годится ровно там, где снятие обязано ПРОЙТИ.
// Здесь предмет обратный — отказ, — и его надо получить в руки, чтобы утвердить
// SQLSTATE и ИМЯ ключа.
//
// Порядок «глаголы → ресурсы → модуль» повторён дословно и обязателен: ударь мы
// сразу в строку модуля, первым ответил бы ключ СОСЕДНЕГО уровня
// (`catalog_resource_module_live_fk`), и проба зеленела бы на чужом отказе.
func retireModuleReturningErr(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	module, reason string,
) error {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	relocateModuleGrants(t, ctx, tx, module, reason)

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_verb
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1 AND live`, module, reason)
	require.NoError(t, err, "снятие глаголов модуля")

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_resource
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1 AND live`, module, reason)
	require.NoError(t, err, "снятие ресурсов модуля")

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_module
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1 AND live`, module, reason)
	return err
}

// TestOwnerRetiredFromTheCatalogIsRefusedByTheLivenessKey — IAM-OM-1-11,
// ПЕРЕВЁРНУТ задачей #2026.
//
// Прежняя редакция закрепляла обратное — «роль со снятым владельцем
// записывается» — и называла условие своего переворота дословно: «его обязано
// ПЕРЕВЕРНУТЬ то изменение, которое даст роли собственную живость (#1913)».
// Условие наступило, и сценарий ЗАМЕНЁН утверждением о новом свойстве того же
// предмета, а не ослаблен.
func TestOwnerRetiredFromTheCatalogIsRefusedByTheLivenessKey(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	// Снятие модуля идёт ПОЛНЫМ административным путём (глаголы → ресурсы →
	// строка модуля): ключи живости соседних уровней держат этот порядок, и
	// снять одну строку модуля нельзя by construction. Помощник тот же, каким
	// пользуется проба соседней приёмки, — своего второго писателя здесь не
	// заводится.
	verbs, refs := withdrawModule(t, ctx, pool, withdrawnModule, "проба #2026 -11")
	t.Logf("модуль %q снят: переселено выдач %d, объявлений %d", withdrawnModule, verbs, refs)

	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kaname.catalog_module WHERE module = $1`, withdrawnModule).Scan(&live))
	require.False(t, live, "предпосылка сценария: модуль снят")

	owner := withdrawnModule
	err := insertSystemRole(ctx, pool, owner+".afterretire", &owner, ownedRules(owner, "registry"))
	require.Error(t, err,
		"ЖИВАЯ роль со СНЯТЫМ владельцем обязана отвергаться КЛЮЧОМ: иначе роль снятого "+
			"модуля продолжает грантовать, и отвергнуть это состояние нечем")
	code, constraint := pgCode(err)
	t.Logf("владелец %q снят: SQLSTATE %s, ключ %q", owner, code, constraint)
	require.Equal(t, "23503", code)
	require.Equal(t, "roles_owner_module_live_fk", constraint,
		"имя ключа — часть сценария: под именем roles_owner_module_fk отвечал бы ключ, "+
			"который о живости не спрашивает вовсе")

	// Законный близнец: ЖИВОЙ модуль каталога ту же роль принимает. Без него
	// отрицание выше зеленело бы на ключе, отвергающем ВСЯКОГО владельца.
	alive := liveCatalogModule(t, ctx, pool)
	require.NoError(t,
		insertSystemRole(ctx, pool, alive+".afterretire", &alive, ownedRules(alive, "network")),
		"роль живого модуля обязана записываться: ключ судит ЖИВОСТЬ владельца, "+
			"а не наличие владельца вообще")
}

// TestRetiringAModuleThatOwnsALiveRoleIsRefused — IAM-OM-1-12, ПЕРЕВЁРНУТ
// задачей #2026, и вместе с ним переехал его довод.
//
// Прежняя редакция требовала, чтобы снятие модуля при живой роли ПРОХОДИЛО, и
// обосновывала это так: с ключом на пару строка роли отпускала бы референт
// только своим УДАЛЕНИЕМ, а удаления у роли модуля нет ни одного — значит модуль
// не снимался бы никогда.
//
// Посылка была верна и БОЛЬШЕ НЕ ВЕРНА. Роль отпускает референт не удалением, а
// ПОМЕТКОЙ снятия (#1913): у снятой строки составляющая ключа обращается в NULL.
// Поэтому положительный контроль ниже — не послабление, а ровно тот вход, на
// котором прежний довод держался: модуль, все роли которого сняты, снимается.
func TestRetiringAModuleThatOwnsALiveRoleIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	owner := withdrawnModule
	require.NoError(t,
		insertSystemRole(ctx, pool, owner+".stillhere", &owner, ownedRules(owner, "registry")),
		"предпосылка сценария: у модуля есть живая роль")

	// ОТРИЦАНИЕ. Помощник соседней приёмки снимает модуль полным путём и на
	// последнем шаге упирается в ключ живости роли.
	err := retireModuleReturningErr(t, ctx, pool, owner, "проба #2026 -12")
	require.Error(t, err,
		"снятие модуля при ЖИВОЙ роли обязано отвергаться: иначе роль снятого модуля "+
			"продолжает грантовать")
	code, constraint := pgCode(err)
	t.Logf("снятие модуля %q при живой роли отвергнуто: SQLSTATE %s, ключ %q",
		owner, code, constraint)
	require.Equal(t, "23503", code)
	require.Equal(t, "roles_owner_module_live_fk", constraint)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — обязателен. Без него отрицание выше неотличимо от
	// «модуль снять нельзя НИКОГДА», а это ровно тот исход, которым круг 1
	// приёмки отверг форму ключа живости.
	res, err := pool.Exec(ctx, `
		UPDATE kaname.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба #2026 -12'
		 WHERE owner_module = $1 AND live`, owner)
	require.NoError(t, err, "пометка снятия ролей модуля")
	require.Positive(t, res.RowsAffected(), "предпосылка контроля: снимать было что")

	verbs, refs := withdrawModule(t, ctx, pool, owner, "проба #2026 -12 контроль")

	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kaname.catalog_module WHERE module = $1`, owner).Scan(&live))
	require.Falsef(t, live,
		"модуль %q, все роли которого СНЯТЫ, обязан сниматься: обратное означало бы, что "+
			"ключ не держит порядок, а запирает каталог навсегда", owner)

	// Строки ролей ПЕРЕЖИЛИ снятие модуля — на этом стоит обратимость (#1913).
	var roles, liveRoles int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE live)
		   FROM kaname.roles WHERE owner_module = $1`, owner).Scan(&roles, &liveRoles))
	t.Logf("модуль %q снят (переселено выдач %d, объявлений %d), ролей с этим владельцем %d, "+
		"из них живых %d", owner, verbs, refs, roles, liveRoles)
	require.Positive(t, roles, "снятие модуля роль НЕ удаляет — она помечена")
	require.Zero(t, liveRoles)
}
