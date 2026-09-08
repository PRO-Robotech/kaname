// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// retired_block_storage_integration_test.go — состояние базы после отставки
// блочного хранения.
//
// services/iam/internal/check/retired_block_storage_test.go судит АРТЕФАКТЫ
// дерева: четыре словаря iam, канонический файл модели, порождённый конфигмап,
// каталог прав. Ни один из них не видит СТРОКИ. Словарь бывает безупречен, пока
// девять привязываемых системных ролей всё ещё называют ресурс, их подстановки
// разворачиваются на него, а реконсайлеру подают зеркальные строки этого типа —
// ровно то состояние, которое оставила за собой отставка блочного хранения у
// compute.
//
// Поэтому здесь утверждается схема, которую база РЕАЛЬНО получила.
//
// # Здесь стояла вторая проба — она снята вместе со своим предметом
//
// Рядом жило утверждение о СТАТЕМЕНТАХ миграции 0074: схема поднималась ровно до
// её версии, сеялись снятая и живая строки, тело переигрывалось, и проверялось,
// что снята только снятая. Довод был верен для мира лестницы: свежая база пуста
// от снятых строк независимо от того, работает DELETE или нет, — то есть
// утверждение ниже удовлетворила бы и миграция, не делающая НИЧЕГО.
//
// Свод 171 миграции в одну первичную этот довод снял. Миграции, которая могла бы
// «не делать ничего», больше нет: посев — буквальный перечень строк, и отсутствие
// в нём снятого имени есть факт перечня, а не утверждение о статементе.
//
// Сильнее того, повторное появление снятого имени теперь запрещено СХЕМОЙ:
// триггер `role_rule_selector_types_live` отвергает объявленный тип, которого нет
// живым в `catalog_resource` (23514). Это свойство держат свои пробы —
// role_rule_selector_types_live_integration_test.go и
// selector_liveness_refusal_reaches_the_caller_integration_test.go, — и
// переписывать их здесь значило бы завести второе место об одном предмете.
//
// # Почему утверждение ниже не стало вакуумным
//
// Каждое отрицание идёт В ПАРЕ с положительным контролем из ТОГО ЖЕ модуля
// (compute.instance) или у нынешнего владельца (storage.volumes): «снятого имени
// нет» иначе неотличимо от «таблица пуста» и от «снято больше положенного».
// Плюс перепись объёма: число прочитанных ролей и строк проекции печатается и
// обязано быть ненулевым.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// retiredDottedTypes / retiredRoleNames — the block-storage identities iam has
// taken off its books. Mirrors services/iam/internal/check/retired_block_storage_test.go;
// duplicated deliberately so this gate fails on its own, without importing the
// package it guards.
var (
	retiredDottedTypes = []string{"compute.disk", "compute.image", "compute.snapshot"}
	retiredRoleNames   = []string{
		"compute.disk.admin", "compute.disk.edit", "compute.disk.view",
		"compute.image.admin", "compute.image.edit", "compute.image.view",
		"compute.snapshot.admin", "compute.snapshot.edit", "compute.snapshot.view",
	}
	// liveSiblingRoleNames — same module, still owned by compute. They are the
	// control that the retire was targeted: a migration that wiped every
	// `compute.%` role would pass the negative assertions and fail here.
	liveSiblingRoleNames = []string{"compute.instance.admin", "compute.instance.edit", "compute.instance.view"}
	// liveDottedTypes — types that must survive in the same columns.
	liveDottedTypes = []string{"compute.instance", "storage.volumes"}
)

func TestRetiredBlockStorageIsGoneFromMigratedSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Volume of what was inspected — "no retired row" must be distinguishable
	// from "no row at all".
	var totalRoles, totalSelectors int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.roles`).Scan(&totalRoles))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.role_rule_selectors`).Scan(&totalSelectors))
	require.NotZero(t, totalRoles, "no roles are seeded at all — this gate would assert nothing")
	require.NotZero(t, totalSelectors, "no role_rule_selectors rows exist at all — this gate would assert nothing")
	t.Logf("scanned: %d roles, %d role_rule_selectors rows", totalRoles, totalSelectors)

	// (1) No retired system role survives, and its live sibling does.
	for _, name := range retiredRoleNames {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.roles WHERE name = $1`, name).Scan(&n))
		require.Zerof(t, n, "system role %q is still seeded and bindable — kacho-storage owns this resource; a grantable role for it is a promise the product cannot keep", name)
	}
	for _, name := range liveSiblingRoleNames {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.roles WHERE name = $1`, name).Scan(&n))
		require.Equalf(t, 1, n, "system role %q is missing — the retire must remove the block-storage roles, not the module", name)
	}

	// (2) No selector expands onto a retired type; the live ones still do.
	for _, ty := range retiredDottedTypes {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.role_rule_selectors WHERE $1 = ANY(object_types)`, ty).Scan(&n))
		require.Zerof(t, n, "%d role_rule_selectors rows still select object type %q — the reconciler would materialize per-object tuples on a type no resource produces", n, ty)
	}
	for _, ty := range liveDottedTypes {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.role_rule_selectors WHERE $1 = ANY(object_types)`, ty).Scan(&n))
		require.NotZerof(t, n, "no role_rule_selectors row selects %q — the wildcard system-role selectors must keep the live types, or the negative half above proves nothing", ty)
	}

	// (3) Nothing may be granted on a retired role.
	for _, name := range retiredRoleNames {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kaname.access_bindings b
			  JOIN kaname.roles r ON r.id = b.role_id
			 WHERE r.name = $1`, name).Scan(&n))
		require.Zerof(t, n, "access_bindings still reference retired role %q", name)
	}

	// (4) resource_mirror carries no retired type. Прежде рядом стояла проба,
	// переигрывавшая тело отставки, и она держала это утверждение от вакуума;
	// её предмет — статементы миграции — снят сводом. Сегодня от вакуума держит
	// схема: `role_rule_selector_types_live` отвергает снятый тип на записи, и
	// это свойство утверждают свои пробы.
	for _, ty := range retiredDottedTypes {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = $1`, ty).Scan(&n))
		require.Zerof(t, n, "resource_mirror still holds rows of retired object type %q", ty)
	}
}
