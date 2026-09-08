// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_owner_module_cluster_tier_integration_test.go — роль с ВЛАДЕЛЬЦЕМ-МОДУЛЕМ
// стоит на кластерном ярусе, и это держит СХЕМА, а не единственный писатель
// (задача продукта #2020).
//
// # Предмет
//
// `owner_module` непуст ⟹ роль системная (кластерный ярус). Сегодня инвариант
// держится тем, что писатель ОДИН: применитель манифеста пропускает роль, чей
// ярус не кластерный (`moduleroles/apply.go`, ветка `mr.Tier.TierType !=
// ScopeTypeClusterDotted` → `Skipped++`), а `UpsertSystemRole` — единственный
// оператор, кладущий `owner_module`, — всегда пишет и `cluster_id`. Второй
// писатель вопрос времени, и его правка пройдёт обзор: в диффе строка роли
// выглядит обычной.
//
// # Почему это не «просто ещё одна проверка»
//
// На кластерном ярусе роли стоит архитектурный вывод соседней приёмки: цепь
// областей у такой роли пуста, поэтому меточную ветвь вердикта сужать не надо.
// Роль модуля с непустой цепью делает вывод неверным, а доступ возвращается
// МОЛЧА — отказа не будет ни от кого.
//
// # Что перепись нашла, и это меняет постановку
//
// Нарушающая строка сегодня НЕ проходит — но отвергают её проверки ИМЕНИ, а не
// владения, и какая именно, зависит от имени:
//
//   - имя с точкой (`vpc.viewer`) на арендаторском ярусе рубит
//     `roles_custom_name_check`: у не-системной роли имя обязано быть
//     `^[a-z][a-z0-9_]{0,40}$`, а точки в этом классе нет;
//   - имя без точки (`viewer`) рубит `roles_owner_module_name_prefix`: имя
//     обязано начинаться с `<модуль>.`.
//
// Пересечения у двух требований нет: одно требует точку на позиции
// `length(owner_module)+1`, другое её запрещает вовсе. Значит строки, нарушающей
// ТОЛЬКО владение, не существует — и любая инъекция «в лоб» измеряла бы имя, а
// не владение.
//
// Из этого следует ТРИ вещи, и ни одна не отменяет работу:
//
//  1. инвариант держится ПОБОЧНЫМ следствием двух правил об ИМЕНИ. Его никто не
//     решал, и в схеме он не назван;
//  2. отказ называет НЕ ТОТ предикат. Пишущий, поставивший владельца
//     арендаторской роли, читает «имя не той формы» и чинит имя — то есть гонится
//     за следствием. Хуже: он вправе «починить» его послаблением проверки имени;
//  3. держатель ЧУЖОЙ. Разреши `roles_custom_name_check` точку в имени
//     арендаторской роли (изменение законное и правдоподобное — точечные имена
//     арендатора), и инвариант испарится, не покраснев нигде.
//
// # Почему отрицание идёт с ИЗОЛИРОВАННЫМ сопутствующим
//
// Раз строки, нарушающей только владение, не существует, доказать способность
// НОВОГО ограничения падать можно ровно одним способом: снять сопутствующее
// ограничение имени в транзакции, подать строку и откатить. Тогда упасть может
// только проверяемое — это то же требование «инъекция роняет ТОЛЬКО
// проверяемое», применённое с другой стороны: убирается не предмет, а
// заслоняющий его сосед.
//
// Без этой изоляции проба зеленела бы и БЕЗ нового ограничения — на отказе
// проверки имени, — то есть не утверждала бы ничего.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ownerTierConstraint — имя ограничения, которое эта проба и заводит.
const ownerTierConstraint = "roles_owner_module_is_cluster_tier"

// systemAccountID — аккаунт, посеянный миграцией 0009. Берётся тем же
// выражением, что и посев: выписать значение значило бы завести второе место об
// одном предмете.
const systemAccountID = `'acc' || substr(md5('kacho-system'), 1, 17)`

// TestIntegration_RoleWithAModuleOwnerIsAlwaysClusterTier — владение модулем и
// кластерный ярус связаны СХЕМОЙ.
//
// Утверждаются обе стороны, и положительных контроля ДВА. Одного мало: контроль
// «законная роль модуля проходит» не заметил бы ограничения, отвергающего всякую
// АРЕНДАТОРСКУЮ роль, — а именно это сделала бы форма `CHECK (is_system)`,
// написанная без оговорки про NULL. Второй контроль ровно этот вход и подаёт.
func TestIntegration_RoleWithAModuleOwnerIsAlwaysClusterTier(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	t.Run("ограничение существует и ПРОВЕРЕНО", func(t *testing.T) {
		var condef string
		var validated bool
		err := db.QueryRow(`
			SELECT pg_get_constraintdef(oid), convalidated
			  FROM pg_constraint
			 WHERE conrelid = 'kaname.roles'::regclass
			   AND conname  = $1`, ownerTierConstraint).Scan(&condef, &validated)
		require.NoError(t, err,
			"ограничения %s нет: инвариант «есть владелец-модуль ⟹ роль системная» "+
				"не назван схемой ни одним объектом, и держит его только то, что писатель один",
			ownerTierConstraint)

		t.Logf("ограничение: %s", condef)
		require.True(t, validated,
			"ограничение не проверено (NOT VALID): планировщик доказанным его не считает, "+
				"а строки, лежавшие до него, под него не подпадали")
	})

	t.Run("положительный контроль 1: роль модуля на кластерном ярусе ПРОХОДИТ", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO kaname.roles
			       (id, cluster_id, name, description, permissions, owner_module, created_at)
			VALUES ('rol_p2_module_cluster', 'cluster_root', 'vpc.viewer',
			        'законная роль модуля', '["vpc.network.*.get"]'::jsonb, 'vpc', now())`)
		require.NoError(t, err,
			"законная роль модуля отвергнута: ограничение шире своего предмета — "+
				"оно рубит ровно тот вход, ради которого владение и заведено")
	})

	t.Run("положительный контроль 2: роль АРЕНДАТОРА без владельца ПРОХОДИТ", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO kaname.roles
			       (id, account_id, name, description, permissions, created_at)
			VALUES ('rol_p2_tenant_plain', ` + systemAccountID + `, 'viewer',
			        'обычная роль арендатора', '["vpc.network.*.get"]'::jsonb, now())`)
		require.NoError(t, err,
			"роль арендатора без владельца отвергнута: значит ограничение записано как "+
				"«роль обязана быть системной» вместо «роль С ВЛАДЕЛЬЦЕМ обязана быть системной» — "+
				"оно отобрало бы у арендатора весь его ярус")
	})

	t.Run("отрицание: роль модуля на ярусе аккаунта ОТВЕРГНУТА по имени владения", func(t *testing.T) {
		// Сопутствующее снимается в транзакции и возвращается откатом. Снят
		// ОДИН факт — проверка имени, — и подан вход, законный по всем
		// остальным: имя `auditor` проходит `roles_custom_name_check` и не занято
		// контролем 2 (частичный UNIQUE `roles_acc_custom_unique`), аккаунт и
		// модуль существуют, права годны. Значит упасть может только владение.
		tx, err := db.Begin()
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()

		_, err = tx.Exec(`ALTER TABLE kaname.roles DROP CONSTRAINT ` +
			`roles_owner_module_name_prefix`)
		require.NoError(t, err,
			"сопутствующее ограничение имени не снялось — изоляция не состоялась, "+
				"и отказ ниже принадлежал бы ему, а не владению")

		_, err = tx.Exec(`
			INSERT INTO kaname.roles
			       (id, account_id, name, description, permissions, owner_module, created_at)
			VALUES ('rol_p2_module_at_account', ` + systemAccountID + `, 'auditor',
			        'роль модуля на чужом ярусе', '["vpc.network.*.get"]'::jsonb, 'vpc', now())`)
		require.Error(t, err,
			"роль с владельцем-модулем легла на ярус АККАУНТА: инвариант «владелец ⟹ системная» "+
				"схемой не держится. Сегодня такую строку рубит проверка ИМЕНИ, но она про имя, "+
				"а не про владение, и переживёт первое же послабление имён")
		require.Contains(t, err.Error(), ownerTierConstraint,
			"строка отвергнута, но НЕ ограничением владения: отказ называет чужой предикат, "+
				"и пишущий пойдёт чинить не то")
	})

	// ── перепись: «ноль находок» обязано быть отличимо от «ноль прочитанного» ──
	var owned, platform, cons int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FILTER (WHERE owner_module IS NOT NULL),
		       count(*) FILTER (WHERE owner_module IS NULL)
		  FROM kaname.roles`).Scan(&owned, &platform))
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_constraint
		 WHERE conrelid = 'kaname.roles'::regclass AND contype = 'c'`).Scan(&cons))
	t.Logf("перепись ролей: с владельцем %d, платформенных %d; проверок на таблице %d",
		owned, platform, cons)
}

// TestIntegration_ModuleOwnerAtTenantTierIsUnrepresentableByName — ПРЕДПОСЫЛКА
// пробы выше: строки, нарушающей только владение, не существует.
//
// Это не украшение. Изоляция сопутствующего в отрицании выше законна ровно
// потому, что без неё отказ пришёл бы от имени; если два требования к имени
// когда-нибудь станут совместимыми, изоляция перестанет быть нужной — и об этом
// надо узнать здесь, а не гадать над зелёной пробой.
//
// Утверждается ПАРА: обе формы имени отвергаются, и каждая — СВОИМ
// ограничением.
func TestIntegration_ModuleOwnerAtTenantTierIsUnrepresentableByName(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	cases := []struct {
		name       string
		roleName   string
		constraint string
		why        string
	}{
		{
			name:       "имя с точкой рубит проверку имени арендатора",
			roleName:   "vpc.viewer",
			constraint: "roles_custom_name_check",
			why:        "у не-системной роли имя не содержит точки",
		},
		{
			name:       "имя без точки рубит составление имени из владельца",
			roleName:   "viewer",
			constraint: "roles_owner_module_name_prefix",
			why:        "имя роли с владельцем начинается с `<модуль>.`",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Симметрично отрицанию выше снимается ОДИН факт — на этот раз само
			// ограничение владения. Без снятия строка после GREEN нарушала бы
			// и имя, и владение, а какое из двух назовёт СУБД, не определено:
			// проба стала бы зависеть от порядка обхода ограничений.
			tx, err := db.Begin()
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()

			_, err = tx.Exec(`ALTER TABLE kaname.roles ` +
				`DROP CONSTRAINT IF EXISTS ` + ownerTierConstraint)
			require.NoError(t, err, "ограничение владения не снялось — изоляция не состоялась")

			_, err = tx.Exec(`
				INSERT INTO kaname.roles
				       (id, account_id, name, description, permissions, owner_module, created_at)
				VALUES ($1, `+systemAccountID+`, $2,
				        'предпосылка изоляции', '["vpc.network.*.get"]'::jsonb, 'vpc', now())`,
				"rol_p2_premise_"+tc.roleName, tc.roleName)
			require.Error(t, err,
				"строка легла: предпосылка изоляции неверна — вход, нарушающий только владение, "+
					"СУЩЕСТВУЕТ, и отрицание выше обязано подавать его без снятия соседа")
			require.Contains(t, err.Error(), tc.constraint,
				"отвергнуто не тем ограничением, которым объявлено (%s)", tc.why)
		})
	}
}
