// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// selector_pruning_leaves_a_ledger_integration_test.go — вырезание висячих
// элементов селектора ОСТАВЛЯЕТ СЛЕД (задача продукта #1988).
//
// # Предмет
//
// У переселения проекций ведомость есть (`role_grant_orphan`): снятое видно, у
// него названы роль, предмет, причина и момент. У вырезания третьей проекции не
// было НИКАКОЙ — вырезанное необратимо и не записано, а объём оператор узнавал
// ТОЛЬКО из плана.
//
// # Чего эта проба НЕ утверждает — и это важнее того, что утверждает
//
// Ведомость — ВТОРАЯ ОПОРА к принятому решению, а не отмена его. Решение не
// ставить потолок на эту популяцию (#1034) остаётся: потолок запрещал бы
// ПОЧИНКУ — висячий элемент делает строку неприемлемой для стража живости, и
// арендатор не может её править, пока висяк не вырезан. Проба потолка не
// заводит и не проверяет; она проверяет, что необратимое перестало быть
// БЕЗМОЛВНЫМ.
//
// # Почему СВОЯ таблица, а не третья популяция сирот
//
// Закрытый набор источников сироты знает две популяции, и «третьей у него нет by
// construction» — это записанное решение применителя, а не пропуск. Довод его
// верен и здесь не пересматривается: у строки селектора нет пары «тип + глагол»,
// которой сироты адресуются. Ведомость вырезания адресуется ИНАЧЕ — парой «роль +
// отпечаток правила» — и потому живёт своей таблицей.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// prunedLedgerRow — строка ведомости вырезанного, как её читает разбирающий.
type prunedLedgerRow struct {
	RuleFP     string
	ObjectType string
	Outcome    string
	Reason     *string
	PrunedAt   time.Time
}

// prunedLedgerOf — ведомость одной роли плюс ОБЪЁМ ОСМОТРЕННОГО по всей таблице.
//
// Две величины, а не одна: «у этой роли записей столько» не отличает «ведомость
// пуста» от «ведомость не читается», и без общего числа строк «ноль у роли»
// получено было бы даром.
func prunedLedgerOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role string) ([]prunedLedgerRow, int) {
	t.Helper()
	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_selector_prune`).Scan(&total))

	rows, err := pool.Query(ctx, `
		SELECT rule_fp, object_type, outcome, retired_reason, pruned_at
		  FROM kaname.role_selector_prune
		 WHERE role_id = $1
		 ORDER BY rule_fp, object_type`, role)
	require.NoError(t, err)
	defer rows.Close()
	var out []prunedLedgerRow
	for rows.Next() {
		var r prunedLedgerRow
		require.NoError(t, rows.Scan(&r.RuleFP, &r.ObjectType, &r.Outcome, &r.Reason, &r.PrunedAt))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out, total
}

// TestPruningASelectorLeavesALedgerRow — ВЫРЕЗАННОЕ ЗАПИСАНО.
//
// Обе ветви вырезания дают запись, и записи РАЗЛИЧАЮТ их исходом: строка,
// потерявшая последний живой тип, снята целиком, а строка, у которой живой тип
// остался, укорочена. Сложи мы их в одну величину — потеряли бы ровно то
// различие, ради которого ведомость и заводится.
func TestPruningASelectorLeavesALedgerRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	role := catalogRole(t, ctx, pool, "led1988")

	// ── ПРЕДПОСЫЛКА: у ЭТОЙ роли ведомость пуста, а таблица читается ──────────
	before, total0 := prunedLedgerOf(t, ctx, pool, string(role))
	t.Logf("ведомость ДО: строк всего %d · у роли %d", total0, len(before))
	require.Emptyf(t, before, "у свежей роли в ведомости уже есть записи %v — "+
		"всё, что проба измерит дальше, будет смешано с чужим", before)

	const doomed = applierProbeModule + ".led1988gone"
	const kept = applierProbeModule + ".led1988kept"

	rep, err := applier.Apply(ctx, probeManifest(
		probeResource("led1988gone", "get"),
		probeResource("led1988kept", "get"),
	))
	require.NoError(t, err)
	require.Truef(t, rep.Changed(), "заведение ресурсов обязано изменить каталог: %s", rep)

	// Две строки: одна назовёт ТОЛЬКО обречённый тип (её снимут целиком), вторая
	// смешанная (её укоротят). Без второй проба утверждала бы про одну ветвь.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-led-only", []string{doomed}),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип обязан записаться, иначе вырезать будет нечего")
	require.NoError(t, writeSelector(ctx, pool, role, "fp-led-mixed", []string{doomed, kept}))

	// ── ГЛАГОЛ ────────────────────────────────────────────────────────────────
	gone, err := applier.Apply(ctx, probeManifest(probeResource("led1988kept", "get")))
	require.NoErrorf(t, err, "применение отвергнуто: %v", err)
	require.Positivef(t, gone.RetiredResources,
		"применитель ресурсов не снял (%s) — вход не произведён, и всё ниже вакуумно", gone)
	require.Equalf(t, 2, gone.PrunedSelectorTypes,
		"вырезано не два элемента — по одному из каждой строки (%s)", gone)

	// ── ИСХОД: ВЫРЕЗАННОЕ ЗАПИСАНО ───────────────────────────────────────────
	after, total1 := prunedLedgerOf(t, ctx, pool, string(role))
	t.Logf("ведомость ПОСЛЕ: строк всего %d · у роли %d %+v · вырезано элементов %d",
		total1, len(after), after, gone.PrunedSelectorTypes)

	require.Lenf(t, after, 2, "вырезано %d элементов, а записано %d — необратимое "+
		"осталось безмолвным ровно там, где ведомость и заводилась",
		gone.PrunedSelectorTypes, len(after))

	byFP := map[string]prunedLedgerRow{}
	for _, r := range after {
		byFP[r.RuleFP] = r
	}

	only, ok := byFP["fp-led-only"]
	require.Truef(t, ok, "строка, снятая ЦЕЛИКОМ, в ведомости не названа: %+v", after)
	require.Equal(t, doomed, only.ObjectType, "ведомость называет не тот вырезанный тип")
	require.Equalf(t, "dropped", only.Outcome,
		"строка без единого живого типа снята целиком, а ведомость называет это иначе: %+v", only)

	mixed, ok := byFP["fp-led-mixed"]
	require.Truef(t, ok, "УКОРОЧЕННАЯ строка в ведомости не названа: %+v", after)
	require.Equal(t, doomed, mixed.ObjectType,
		"ведомость записала живой тип: укорочение унесло бы больше, чем сняла платформа")
	require.Equalf(t, "shortened", mixed.Outcome,
		"укорочение и снятие целиком — события разного рода, а ведомость их не различает: %+v", mixed)

	// ── ПРИЧИНА И МОМЕНТ ─────────────────────────────────────────────────────
	//
	// «Каким применением» отвечает МОМЕНТ: он транзакционный, поэтому у всех
	// строк одного применения он совпадает ДОСЛОВНО. Причину несёт снятая строка
	// каталога — та самая, чьё снятие и сделало элемент висячим.
	require.Equalf(t, only.PrunedAt, mixed.PrunedAt,
		"момент у строк ОДНОГО применения разошёлся — по нему нельзя собрать, "+
			"что снято одним заходом")
	var retiredReason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT retired_reason FROM kaname.catalog_resource WHERE dotted = $1`,
		doomed).Scan(&retiredReason))
	require.NotEmpty(t, retiredReason, "снятая строка каталога причины не несёт — "+
		"тогда её нечего и переносить в ведомость")
	for _, r := range after {
		require.NotNilf(t, r.Reason, "ведомость не несёт причины: %+v", r)
		require.Equalf(t, retiredReason, *r.Reason,
			"причина в ведомости разошлась с причиной снятия строки каталога: %+v", r)
	}
}

// TestPruningNothingLeavesTheLedgerAlone — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него «записей стало две» было бы неотличимо от ведомости, которая пишет
// строку на ВСЯКОЕ снятие ресурса, — то есть от предиката, срабатывающего на
// снятии как таковом, а не на вырезанном элементе.
func TestPruningNothingLeavesTheLedgerAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_selector_prune`).Scan(&before))

	rep, err := applier.Apply(ctx, probeManifest(
		probeResource("led1988lonely", "get"),
		probeResource("led1988stay", "get"),
	))
	require.NoError(t, err)
	require.True(t, rep.Changed())

	gone, err := applier.Apply(ctx, probeManifest(probeResource("led1988stay", "get")))
	require.NoError(t, err)
	require.Positivef(t, gone.RetiredResources,
		"ресурс не снят (%s) — контроль вакуумен: он ничего не наблюдал", gone)
	require.Zerof(t, gone.PrunedSelectorTypes,
		"этого ресурса не называет ни один селектор, а вырезано %d", gone.PrunedSelectorTypes)

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_selector_prune`).Scan(&after))
	t.Logf("ведомость: строк ДО %d · ПОСЛЕ %d · снято ресурсов %d · вырезано элементов %d",
		before, after, gone.RetiredResources, gone.PrunedSelectorTypes)
	require.Equalf(t, before, after,
		"снятие ресурса, которого не называет ни один селектор, записало строку в "+
			"ведомость: предикат срабатывает на снятии, а не на вырезанном элементе")
}

// TestPrunedLedgerDiesWithItsRole — след живёт РОВНО пока живёт его роль.
//
// Тот же довод, что у ведомости переселения: запись адресована ролью, и пережить
// её она не может — иначе ведомость копила бы строки, у которых нет предмета, и
// читающий не отличил бы отобранное у живой роли от следа удалённой.
func TestPrunedLedgerDiesWithItsRole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	role := catalogRole(t, ctx, pool, "led1988cascade")
	const doomed = applierProbeModule + ".led1988cascadegone"

	_, err := applier.Apply(ctx, probeManifest(
		probeResource("led1988cascadegone", "get"),
		probeResource("led1988cascadestay", "get"),
	))
	require.NoError(t, err)
	require.NoError(t, writeSelector(ctx, pool, role, "fp-cascade", []string{doomed}))

	gone, err := applier.Apply(ctx, probeManifest(probeResource("led1988cascadestay", "get")))
	require.NoError(t, err)
	require.Positive(t, gone.PrunedSelectorTypes)

	rows, _ := prunedLedgerOf(t, ctx, pool, string(role))
	require.Lenf(t, rows, 1, "ПРЕДПОСЫЛКА: записи, которая должна умереть, нет: %+v", rows)

	_, err = pool.Exec(ctx, `DELETE FROM kaname.roles WHERE id = $1`, string(role))
	require.NoError(t, err)

	rows, total := prunedLedgerOf(t, ctx, pool, string(role))
	t.Logf("после удаления роли: у роли %d · всего в ведомости %d", len(rows), total)
	require.Emptyf(t, rows, "след пережил свою роль: %+v", rows)
}
