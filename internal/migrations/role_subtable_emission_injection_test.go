// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// role_subtable_emission_injection_test.go — ДОКАЗАТЕЛЬСТВО, что отрицание
// соседней пробы (`role_subtable_boot_volume_integration_test.go`, §1) способно
// покраснеть, и ЦЕНА исхода, который задача #73 предлагала как основной.
//
// Отрицание «холостой подъём не даёт событий журнала» зелено и на схеме, где
// журнал не пишет ничего и ни при каких условиях. Отличить одно от другого может
// только инъекция: завести на три подтаблицы роли ровно те триггеры, о которых
// шла речь, и посмотреть, сколько событий родит подъём, в котором НЕ ИЗМЕНИЛОСЬ
// НИЧЕГО.
//
// Инъекция ставится ТЕМ ЖЕ обработчиком, что у трёх живых подтаблиц состава
// (`kaname.resource_journal_emit_member`), — не своей копией: копия была бы
// снисходительнее продукта и мерила бы себя.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// installRoleSubtableEmission — исход «завести триггеры», внесённый в схему.
//
// `('iam_role', 'role_id', 'roles')`: вид предмета, колонка-ссылка на владельца
// и его таблица — та же тройка аргументов, какой объявлены три живые подтаблицы
// состава.
func installRoleSubtableEmission(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, tbl := range roleSubtables {
		_, err := pool.Exec(ctx, fmt.Sprintf(
			`CREATE TRIGGER %s_resource_journal_trg
			   AFTER INSERT OR UPDATE OR DELETE ON kaname.%s
			   FOR EACH ROW EXECUTE FUNCTION
			     kaname.resource_journal_emit_member('iam_role', 'role_id', 'roles')`, tbl, tbl))
		require.NoError(t, err)
	}
}

// TestIntegration_RoleSubtableEmissionWouldStormOnEveryBoot — #73, инъекция.
func TestIntegration_RoleSubtableEmissionWouldStormOnEveryBoot(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool := freshIamPool(t, ctx)

	// Первый подъём наполняет проекции — мерой не служит.
	runBootLanes(t, ctx, pool)

	// ЗАКОННЫЙ БЛИЗНЕЦ: до инъекции тот же самый подъём молчит. Без этой
	// половины красное ниже не доказывало бы ничего — оно могло бы приходить от
	// чего угодно в подъёме, а не от заведённых триггеров.
	truncateJournal(t, ctx, pool)
	runBootLanes(t, ctx, pool)
	require.Zero(t, journalRowsOfKind(t, ctx, pool, "iam_role"),
		"до инъекции холостой подъём обязан молчать — иначе инъекция ниже "+
			"меряет не себя")

	// ИНЪЕКЦИЯ: исход «завести триггеры».
	installRoleSubtableEmission(t, ctx, pool)

	truncateJournal(t, ctx, pool)
	runBootLanes(t, ctx, pool)
	stormed := journalRowsOfKind(t, ctx, pool, "iam_role")

	var distinctRoles int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(DISTINCT resource_id) FROM kaname.resource_journal
		  WHERE resource_kind = 'iam_role'`).Scan(&distinctRoles))

	t.Logf("ЦЕНА ИСХОДА «завести триггеры»: событий журнала за ОДИН холостой "+
		"подъём %d, различных ролей среди них %d — то есть %d дублей на роль, "+
		"и ни один не описывает изменения",
		stormed, distinctRoles, stormed/max64(distinctRoles, 1))

	assert.NotZero(t, stormed,
		"инъекция не родила ни одного события: обработчик эмиссии подтаблиц не "+
			"сработал, и отрицание соседней пробы осталось НЕДОКАЗАННЫМ — оно "+
			"зелено на схеме, которая не пишет вовсе")
}

// max64 — нижняя граница делителя: деление на ноль обрушило бы печать переписи
// раньше, чем она объяснила бы, что ролей не нашлось.
func max64(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}
