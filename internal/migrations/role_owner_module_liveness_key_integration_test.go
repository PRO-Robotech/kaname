// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_owner_module_liveness_key_integration_test.go — живость МОДУЛЯ-владельца
// у `kaname.roles` держится КЛЮЧОМ, а не рассуждением (задача продукта
// #2026).
//
// # Предмет
//
// `roles_owner_module_fk` идёт на ПЕРВИЧНЫЙ ключ каталога
// (`catalog_module(module)`), поэтому состояние «модуль СНЯТ, а его роли ЖИВЫ и
// грантуют» представимо, и отвергнуть его нечем: три ограничения `roles`,
// называющие `owner_module`, — про ярус (`roles_owner_module_is_cluster_tier`),
// про имя (`roles_owner_module_name_prefix`) и про подстановку
// (`roles_rule_wildcards_confined`), — и ни одно не про живость владельца.
//
// # Почему форма стала выразимой ТОЛЬКО СЕЙЧАС
//
// Круг 1 приёмки `role-ownership-tier-apart-from-cluster-anchor.md` (IAM-OM-1)
// эту же пару отверг ПРОГОНОМ, а не вкусом: составляющая вида
// `CASE WHEN owner_module IS NOT NULL THEN true END` даёт константу `true`, и
// строка отпускает референт только своим УДАЛЕНИЕМ, которого у роли модуля нет
// ни одного. Модуль с ролью не снимался бы НИКОГДА — ровно тот вход, на котором
// `IAM-MW-1-08` соседней приёмки отвергла ту же форму уровнем выше.
//
// `#1913` дал роли пометку снятия (`roles.live`), и половина, которой не
// хватало, появилась: составляющая `CASE WHEN live THEN true END` обращается в
// `NULL` у снятой строки, и снятая роль модуль ОТПУСКАЕТ. Довод записан
// `architecture/role-withdrawal-is-a-mark.md` §«Что это решение РАЗМЫКАЕТ»;
// форма усиления названа IAM-OM-1 §2.1 дословно («усиление до пары
// `(module, live)` — это `ADD CONSTRAINT` в изменении `#1913`»); предикат снятия
// — `role-withdrawal-has-a-producer.md` §9 Р1.
//
// # Что здесь ДОКАЗЫВАЕТСЯ парой, а не одним утверждением
//
// «Ключ держит порядок» неотличимо от «модуль снять нельзя никогда», если
// утверждать только отказ. Обе половины обязательны, и вторая — та самая, на
// которой отвергнута форма круга 1: снять роль — и снятие модуля ПРОХОДИТ.
//
// # Почему проба по ЖИВОЙ схеме, а не по тексту миграции
//
// Утверждается ИСХОД накатанной цепи, а не намерение одного файла: ограничение
// переопределяет любая поздняя миграция, и текст файла об этом не знает.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stretchr/testify/require"
)

const (
	// ownerModuleLivenessFK — ключ, который эта проба и заводит.
	ownerModuleLivenessFK = "roles_owner_module_live_fk"

	// ownerModulePlainFK — ключ, который остаётся РЯДОМ, а не заменяется.
	//
	// Он утверждает другое — «владелец известен платформе» — и утверждает это
	// БЕЗУСЛОВНО, тогда как ключ живости под `MATCH SIMPLE` у снятой строки не
	// проверяется вовсе. Тот же порядок стоит уровнем выше: у `catalog_resource`
	// живут ОБА (`catalog_resource_module_fk` и `catalog_resource_module_live_fk`).
	// Сверх того на его имя ключуется сценарий `-10` APPROVED-приёмки IAM-OM-1.
	ownerModulePlainFK = "roles_owner_module_fk"

	// livenessTestModule — модуль, заводимый ПРОБОЙ. Свой, а не посеянный:
	// у посеянных есть живые ресурсы, и снятие уперлось бы в
	// `catalog_resource_module_live_fk` — то есть красное пришло бы от СОСЕДА, а
	// не от проверяемого ключа.
	livenessTestModule = "t2probe"

	// livenessTestRole — роль этого модуля. Имя составлено из владельца:
	// `roles_owner_module_name_prefix` требует приставки `<модуль>.`.
	livenessTestRole = "rol_2026_owner_module_liveness"
)

// pgErrOf — SQLSTATE и имя ограничения из ошибки Postgres.
func pgErrOf(t *testing.T, err error) (code, constraint string) {
	t.Helper()
	require.Error(t, err)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "ожидалась ошибка Postgres, а не %T", err)
	return pgErr.Code, pgErr.ConstraintName
}

// seedModuleWithLiveRole — свой модуль каталога и ЖИВАЯ роль этого модуля.
//
// Роль системная намеренно: `roles_owner_module_is_cluster_tier` иного не
// допускает, а `roles_definition_tier_xor` требует ровно одного якоря яруса.
func seedModuleWithLiveRole(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.Exec(`
		INSERT INTO kaname.catalog_module (module, live) VALUES ($1, true)`,
		livenessTestModule)
	require.NoError(t, err, "свой модуль каталога")

	_, err = db.Exec(`
		INSERT INTO kaname.roles
		       (id, cluster_id, name, description, permissions, owner_module, created_at)
		VALUES ($1, 'cluster_root', $2, 'проба #2026',
		        '["t2probe.thing.*.get"]'::jsonb, $3, now())`,
		livenessTestRole, livenessTestModule+".viewer", livenessTestModule)
	require.NoError(t, err, "живая роль своего модуля")

	// Предпосылка сценария названа замером, а не подразумевается: без ЖИВОЙ
	// роли отрицание ниже вакуумно.
	var live int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.roles WHERE owner_module = $1 AND live`,
		livenessTestModule).Scan(&live))
	require.Equalf(t, 1, live,
		"предпосылка: у модуля %s ровно одна живая роль", livenessTestModule)
}

// retireModuleRow — снятие модуля тем же оператором, каким его снимает продукт.
func retireModuleRow(db *sql.DB, reason string) error {
	_, err := db.Exec(`
		UPDATE kaname.catalog_module
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1`, livenessTestModule, reason)
	return err
}

// withdrawRole — пометка снятия роли той же формой, что у `RetireRole`
// (`role_withdrawal_repo.go`): строка остаётся, живость становится ложной.
func withdrawRole(t *testing.T, db *sql.DB) {
	t.Helper()
	res, err := db.Exec(`
		UPDATE kaname.roles
		   SET live = false, retired_at = now(),
		       retired_reason = 'проба #2026', retired_by = 'probe'
		 WHERE id = $1 AND live`, livenessTestRole)
	require.NoError(t, err, "пометка снятия роли")
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "пометка обязана найти свою строку")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-OM-2-01 — ФОРМА ключа: пара, референт живости, MATCH SIMPLE, проверен.

func TestIntegration_RoleOwnerModuleLivenessKeyHasItsForm(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	t.Run("составляющая живости обращается в NULL у снятой строки", func(t *testing.T) {
		var genExpr sql.NullString
		var typ string
		err := db.QueryRow(`
			SELECT data_type, generation_expression
			  FROM information_schema.columns
			 WHERE table_schema = 'kaname'
			   AND table_name   = 'roles'
			   AND column_name  = 'owner_module_live'`).Scan(&typ, &genExpr)
		require.NoError(t, err,
			"колонки kaname.roles.owner_module_live нет: паре ключа не из чего "+
				"собраться, и живость владельца схемой не названа")
		require.Equal(t, "boolean", typ)
		require.True(t, genExpr.Valid,
			"колонка обязана быть ВЫЧИСЛЯЕМОЙ: обычную колонку пришлось бы кому-то "+
				"проставлять, и вторым писателем живости стал бы он")
		t.Logf("составляющая: %s", genExpr.String)

		// Утверждается ИСХОД составляющей, а не её ТЕКСТ: запись Postgres
		// нормализует по-своему, и сверка строкой мерила бы его нормализацию.
		//
		// Обе стороны обязательны. Только `true` у живой — и константная форма
		// круга 1 (`CASE WHEN owner_module IS NOT NULL`) прошла бы дословно;
		// именно её отсутствие `NULL` у снятой строки и делало модуль
		// неснимаемым навсегда.
		seedModuleWithLiveRole(t, db)

		var whenLive sql.NullBool
		require.NoError(t, db.QueryRow(
			`SELECT owner_module_live FROM kaname.roles WHERE id = $1`,
			livenessTestRole).Scan(&whenLive))
		require.True(t, whenLive.Valid && whenLive.Bool,
			"у ЖИВОЙ роли составляющая обязана быть true — иначе ключ не проверяется "+
				"вовсе, и живой роли снятый модуль сойдёт с рук")

		withdrawRole(t, db)

		var whenWithdrawn sql.NullBool
		require.NoError(t, db.QueryRow(
			`SELECT owner_module_live FROM kaname.roles WHERE id = $1`,
			livenessTestRole).Scan(&whenWithdrawn))
		require.False(t, whenWithdrawn.Valid,
			"у СНЯТОЙ роли составляющая обязана быть NULL: только так строка "+
				"ОТПУСКАЕТ модуль, и именно этой половины не было у формы круга 1")
	})

	t.Run("ключ ссылается на ПАРУ и проверен", func(t *testing.T) {
		var condef string
		var validated bool
		var matchType string
		err := db.QueryRow(`
			SELECT pg_get_constraintdef(oid), convalidated, confmatchtype
			  FROM pg_constraint
			 WHERE conrelid = 'kaname.roles'::regclass AND conname = $1`,
			ownerModuleLivenessFK).Scan(&condef, &validated, &matchType)
		require.NoErrorf(t, err,
			"ключа %s нет: живость модуля-владельца не держит ни один объект схемы",
			ownerModuleLivenessFK)
		t.Logf("ключ: %s (confmatchtype=%q)", condef, matchType)

		require.Contains(t, condef, "(owner_module, owner_module_live)",
			"ключ обязан идти ПАРОЙ: однокомпонентный не отличает живой модуль от снятого")
		require.Contains(t, condef, "catalog_module(module, live)",
			"референт — уникальность (module, live), а не первичный ключ")

		// Способ сверки MATCH берётся из КАТАЛОГА, а не из отрисовки.
		//
		// Первая редакция этой пробы искала подстроку "MATCH SIMPLE" в
		// `pg_get_constraintdef` — и была неверна: SIMPLE есть УМОЛЧАНИЕ, и
		// отрисовка его не печатает НИКОГДА, ни у этого ключа, ни у соседнего
		// `catalog_resource_module_live_fk`. То есть проба мерила бы отрисовку
		// Postgres, а не свойство ключа, и краснела бы на верной схеме.
		//
		// `confmatchtype` — та самая величина: 's' — SIMPLE, 'f' — FULL,
		// 'p' — PARTIAL. Различие несущее: под FULL пара `(модуль, NULL)`
		// отвергалась бы, и снятая роль модуль НЕ отпускала бы — то есть модуль
		// снова стал бы неснимаемым, ровно как у формы круга 1.
		require.Equal(t, "s", matchType,
			"сверка обязана быть MATCH SIMPLE: только при ней пара с пустой "+
				"составляющей считается выполненной, и снятая роль ОТПУСКАЕТ модуль")

		require.True(t, validated,
			"ключ не проверен (NOT VALID): строки, лежавшие до него, под него не подпадают")
	})

	t.Run("прежний ключ остаётся РЯДОМ, а не заменяется", func(t *testing.T) {
		var condef string
		err := db.QueryRow(`
			SELECT pg_get_constraintdef(oid)
			  FROM pg_constraint
			 WHERE conrelid = 'kaname.roles'::regclass AND conname = $1`,
			ownerModulePlainFK).Scan(&condef)
		require.NoErrorf(t, err,
			"ключ %s снят: утверждение «владелец известен платформе» держалось им "+
				"БЕЗУСЛОВНО, а ключ живости у снятой строки не проверяется вовсе. "+
				"Сверх того на его имя ключуется сценарий -10 APPROVED-приёмки IAM-OM-1",
			ownerModulePlainFK)
		t.Logf("прежний ключ: %s", condef)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-OM-2-02 — ключ держит порядок в ОБЕ стороны.

func TestIntegration_RoleOwnerModuleLivenessKeyHoldsBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}

	t.Run("путь вниз: снять модуль при ЖИВОЙ роли", func(t *testing.T) {
		db := freshIamSchema(t)
		seedModuleWithLiveRole(t, db)

		err := retireModuleRow(db, "проба IAM-OM-2-02(а)")
		require.Error(t, err,
			"снятие модуля при живой роли обязано отвергаться КЛЮЧОМ: иначе роль "+
				"снятого модуля продолжает грантовать")
		code, constraint := pgErrOf(t, err)
		t.Logf("снятие модуля отвергнуто: SQLSTATE %s, ограничение %q", code, constraint)
		require.Equal(t, "23503", code)
		require.Equal(t, ownerModuleLivenessFK, constraint,
			"имя ограничения — часть сценария: под другим именем отвечал бы другой ключ")

		var live bool
		require.NoError(t, db.QueryRow(
			`SELECT live FROM kaname.catalog_module WHERE module = $1`,
			livenessTestModule).Scan(&live))
		require.True(t, live, "отвергнутое снятие оставляет строку модуля живой")
	})

	t.Run("путь вверх: оживить роль при СНЯТОМ модуле", func(t *testing.T) {
		db := freshIamSchema(t)
		seedModuleWithLiveRole(t, db)
		withdrawRole(t, db)
		require.NoError(t, retireModuleRow(db, "проба IAM-OM-2-02(в)"))

		_, err := db.Exec(`
			UPDATE kaname.roles
			   SET live = true, retired_at = NULL, retired_reason = NULL, retired_by = NULL
			 WHERE id = $1`, livenessTestRole)
		require.Error(t, err,
			"оживление роли при снятом модуле обязано отвергаться: установка идёт "+
				"«модуль → роли», а не наоборот")
		code, constraint := pgErrOf(t, err)
		t.Logf("оживление роли отвергнуто: SQLSTATE %s, ограничение %q", code, constraint)
		require.Equal(t, "23503", code)
		require.Equal(t, ownerModuleLivenessFK, constraint)

		// Законный близнец: сперва модуль, затем роль — проходит. Без него
		// отрицание выше зеленело бы на схеме, где оживления не бывает вовсе.
		_, err = db.Exec(`
			UPDATE kaname.catalog_module
			   SET live = true, retired_at = NULL, retired_reason = NULL
			 WHERE module = $1`, livenessTestModule)
		require.NoError(t, err, "оживление модуля")
		_, err = db.Exec(`
			UPDATE kaname.roles
			   SET live = true, retired_at = NULL, retired_reason = NULL, retired_by = NULL
			 WHERE id = $1`, livenessTestRole)
		require.NoError(t, err, "после оживления модуля роль оживает")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-OM-2-03 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к -02(а). Без него -02(а) не отличает
// «ключ работает» от «модуль снять нельзя НИКОГДА» — и именно на этом входе
// круг 1 приёмки IAM-OM-1 отверг форму `CASE WHEN owner_module IS NOT NULL`.

func TestIntegration_ModuleWithAllRolesWithdrawnIsRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	seedModuleWithLiveRole(t, db)

	withdrawRole(t, db)

	require.NoError(t, retireModuleRow(db, "проба IAM-OM-2-03"),
		"модуль, ВСЕ роли которого сняты, ОБЯЗАН сниматься: иначе ключ не держит "+
			"порядок, а запирает каталог навсегда")

	var moduleLive bool
	require.NoError(t, db.QueryRow(
		`SELECT live FROM kaname.catalog_module WHERE module = $1`,
		livenessTestModule).Scan(&moduleLive))
	require.False(t, moduleLive)

	// Строка роли ПЕРЕЖИЛА снятие модуля — на этом стоит обратимость (#1913):
	// цикл «снять модуль → поставить снова» возвращает ТУ ЖЕ роль с тем же `id`.
	var roleRows, roleLive int
	require.NoError(t, db.QueryRow(
		`SELECT count(*), count(*) FILTER (WHERE live)
		   FROM kaname.roles WHERE owner_module = $1`,
		livenessTestModule).Scan(&roleRows, &roleLive))
	t.Logf("перепись: строк роли у снятого модуля %d, из них живых %d", roleRows, roleLive)
	require.Equal(t, 1, roleRows, "снятие модуля роль НЕ удаляет — она помечена")
	require.Zero(t, roleLive)

	// Соседний модуль не задет: ключ судит СВОЙ модуль, а не каталог целиком.
	var neighbours int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.catalog_module WHERE live AND module <> $1`,
		livenessTestModule).Scan(&neighbours))
	require.Positive(t, neighbours, "снятие одного модуля не снимает остальные")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-OM-2-04 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ширины: ключ не задевает того, чей
// владелец пуст.
//
// Без него ключ, отвергающий ВСЯКУЮ платформенную роль, прошёл бы обе половины
// выше: платформенных ролей в сценариях -02 и -03 нет вовсе.

func TestIntegration_PlatformRoleIsUntouchedByTheLivenessKey(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	// Предпосылка: платформенные роли в схеме ЕСТЬ, и их снятие ключом не
	// судится — пара `(NULL, …)` под MATCH SIMPLE выполнена by construction.
	var platform int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.roles WHERE owner_module IS NULL`).Scan(&platform))
	require.Positivef(t, platform,
		"предпосылка: платформенные роли посеяны — иначе контроль вакуумен")
	t.Logf("перепись: платформенных ролей %d", platform)

	_, err := db.Exec(`
		INSERT INTO kaname.roles
		       (id, cluster_id, name, description, permissions, created_at)
		VALUES ('rol_2026_platform_probe', 'cluster_root', 'probe-platform',
		        'платформенная роль пробы', '["iam.role.*.get"]'::jsonb, now())`)
	require.NoError(t, err,
		"платформенная роль отвергнута: ключ шире своего предмета — он судит "+
			"строку, у которой владельца-модуля нет вовсе")

	_, err = db.Exec(`
		UPDATE kaname.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба IAM-OM-2-04'
		 WHERE id = 'rol_2026_platform_probe'`)
	require.NoError(t, err, "снятие платформенной роли ключом живости не судится")
}
