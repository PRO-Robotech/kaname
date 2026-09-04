// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// selector_loses_its_referent_integration_test.go — ТРЕТЬЯ поверхность проекции
// правила теряет референт, когда строку каталога снимает ГЛАГОЛ (задача продукта
// #1942).
//
// # Предмет: у половины референта нет производителя входа
//
// Референт третьей проекции — триггер `role_rule_selectors_types_live` — держится
// НА ВХОДЕ (`BEFORE INSERT OR UPDATE ON kacho_iam.role_rule_selectors`). Он судит
// запись селектора и НЕ судит снятие строки каталога; обратной половины у него
// нет и быть не может тем же способом — ключ на элемент массива невыразим, и это
// сказано в шапке самой миграции `20260902174500`.
//
// Две другие проекции референт имеют КЛЮЧОМ (`role_rule_ref_res_fk`,
// `role_verb_type_fk`), поэтому снятие ресурса их роняет — и потому применитель
// обязан переселять их тем же оператором (`ResettleTenantProjections`). Третью
// не роняет ничто, и она остаётся называть снятый тип МОЛЧА.
//
// # Почему это стало дефектом только теперь
//
// Пока строки каталога снимала ТОЛЬКО применённая миграция, остаток закрывал
// человек: `0074` вычищала селекторы двумя отдельными шагами руками — снимала
// строку, называвшую только снятые типы, и вырезала снятые элементы из
// подстановочных строк. С применителем каталога (#1034) снятие стало ГЛАГОЛОМ, у
// которого автора-человека рядом нет, и остаток стал дефектом.
//
// # Решение село, и замок переписан ТЕМ ЖЕ изменением
//
// Здесь стоял ХАРАКТЕРИЗУЮЩИЙ ЗАМОК: он закреплял сегодняшний исход («селектор
// продолжает называть снятый тип») как известный — ровно затем, чтобы смена была
// видна. Смена наступила: применитель приводит третью проекцию к каталожному
// факту (`modulecatalog/prune.go`), то есть делает глаголом ровно те два шага,
// которые `0074` выполнила рукой. Замок покраснел, как и задумывалось, и
// переписан под решение, а не ослаблен.
//
// # Что утверждается теперь
//
// Пара, обе стороны: снятие строки каталога при живом селекторе, её называющем,
// НЕ оставляет повисших — и снятие ресурса, которого не называет ни один
// селектор, переписи не двигает вовсе. Плюс граница: вход в селекторы по-прежнему
// стережёт триггер, и записать снятый тип нельзя — это входная половина
// референта, и она не менялась.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// selectorsNamingDeadTypes — перепись: сколько строк селекторов называют тип, у
// которого в каталоге нет ЖИВОЙ строки.
//
// Возвращает и число строк, и их перечень: одно число не говорит, ЧТО именно
// повисло, а перечень без числа не отличает «ничего не нашли» от «ничего не
// прочли».
func selectorsNamingDeadTypes(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (int, []string) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT s.role_id, s.rule_fp, t AS dotted
		  FROM kacho_iam.role_rule_selectors s
		  CROSS JOIN LATERAL unnest(s.object_types) AS t
		 WHERE NOT EXISTS (
		         SELECT 1 FROM kacho_iam.catalog_resource cr
		          WHERE cr.dotted = t AND cr.live)
		 ORDER BY s.role_id, s.rule_fp, t`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var role, fp, dotted string
		require.NoError(t, rows.Scan(&role, &fp, &dotted))
		out = append(out, role+"/"+fp+" → "+dotted)
	}
	require.NoError(t, rows.Err())
	return len(out), out
}

// selectorObjectTypesRead — объём осмотренного: сколько ЭЛЕМЕНТОВ массивов
// прочитано переписью выше. Без него «повисших ноль» неотличимо от «прочитано
// ноль», а таблица селекторов на свежей базе непуста только благодаря досеву.
func selectorObjectTypesRead(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_selectors s
		 CROSS JOIN LATERAL unnest(s.object_types) AS t`).Scan(&n))
	return n
}

// TestRetiringAResourcePrunesTheSelectorThatNamedIt — РЕШЕНИЕ #1942 на живой базе.
//
// Снятие строки каталога глаголом приводит третью проекцию к каталожному факту:
// повисших не остаётся, а строка селектора, назвавшая ТОЛЬКО снятый тип, снята
// целиком — пустой массив запрещён ограничением `role_rule_selectors_types_nonempty`.
func TestRetiringAResourcePrunesTheSelectorThatNamedIt(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	// ── ПРЕДПОСЫЛКА, а не допущение: на намигрированной базе повисших нет ──────
	read0 := selectorObjectTypesRead(t, ctx, pool)
	dangling0, list0 := selectorsNamingDeadTypes(t, ctx, pool)
	t.Logf("перепись ДО: элементов object_types прочитано %d · называют снятый тип %d %v",
		read0, dangling0, list0)
	require.Positivef(t, read0, "прочитано ноль элементов object_types — перепись беспредметна, "+
		"и её «повисших ноль» получено даром")
	require.Zerof(t, dangling0, "на намигрированной базе селекторы уже называют снятые типы %v — "+
		"это НЕ предмет этой пробы, и всё, что она измерит дальше, будет смешано с чужим", list0)

	// ── ВХОД: ресурс заведён глаголом и назван живым селектором ────────────────
	const dotted = applierProbeModule + ".orphaned"
	rep, err := applier.Apply(ctx, probeManifest(
		probeResource("orphaned", "get"),
		probeResource("kept", "get"),
	))
	require.NoError(t, err)
	require.True(t, rep.Changed(), "заведение ресурсов обязано изменить каталог: %s", rep)

	role := catalogRole(t, ctx, pool, "sel1942")
	require.NoError(t, writeSelector(ctx, pool, role, "fp-1942", []string{dotted}),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип обязан записаться, иначе снимать будет нечего")
	// Вторая строка — СМЕШАННАЯ: снятый тип рядом с живым. Без неё проба
	// утверждала бы только про ветвь снятия строки, а укорочение осталось бы
	// непокрытым — при том что именно оно и есть частый случай.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-1942-mixed",
		[]string{dotted, applierProbeModule + ".kept"}))

	// ── ГЛАГОЛ: тот же модуль без снятого ресурса ─────────────────────────────
	gone, err := applier.Apply(ctx, probeManifest(probeResource("kept", "get")))
	require.NoError(t, err, "применение отвергнуто: %v", err)
	require.Positivef(t, gone.RetiredResources,
		"применитель ресурсов не снял (%s) — вход не произведён, и всё ниже вакуумно", gone)

	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kacho_iam.catalog_resource WHERE dotted = $1`, dotted).Scan(&live))
	require.Falsef(t, live, "строка каталога %s жива после снятия", dotted)

	// ── ИСХОД ────────────────────────────────────────────────────────────────
	read1 := selectorObjectTypesRead(t, ctx, pool)
	dangling1, list1 := selectorsNamingDeadTypes(t, ctx, pool)
	t.Logf("перепись ПОСЛЕ: элементов object_types прочитано %d · называют снятый тип %d %v · "+
		"укорочено %d снято %d вырезано элементов %d",
		read1, dangling1, list1,
		gone.PrunedSelectorRows, gone.PrunedSelectorRowsDropped, gone.PrunedSelectorTypes)

	require.Zerof(t, dangling1, "снятие оставило селекторы называть снятый тип: %v", list1)
	require.Equalf(t, 1, gone.PrunedSelectorRows,
		"смешанная строка обязана быть УКОРОЧЕНА, а не снята: живой тип в ней остался (%s)", gone)
	require.Equalf(t, 1, gone.PrunedSelectorRowsDropped,
		"строка, назвавшая только снятый тип, обязана быть снята целиком: пустой массив "+
			"запрещён ограничением схемы (%s)", gone)
	require.Equalf(t, 2, gone.PrunedSelectorTypes,
		"вырезано не два элемента — по одному из каждой строки (%s)", gone)

	// Укороченная строка сохранила ЖИВОЙ тип: без этого «повисших ноль» вышло бы
	// и у правки, снёсшей обе строки, — то есть у отбора права сверх снятого.
	var kept []string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT object_types FROM kacho_iam.role_rule_selectors
		  WHERE role_id = $1 AND rule_fp = 'fp-1942-mixed'`, string(role)).Scan(&kept))
	require.Equal(t, []string{applierProbeModule + ".kept"}, kept,
		"укорочение унесло живой тип — правка отобрала больше, чем сняла платформа")

	var survived int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors
		  WHERE role_id = $1 AND rule_fp = 'fp-1942'`, string(role)).Scan(&survived))
	require.Zero(t, survived, "строка без единого живого типа уцелела")

	// ── ГРАНИЦА: входная половина референта не менялась ───────────────────────
	err = writeSelector(ctx, pool, role, "fp-1942-next", []string{dotted})
	require.Error(t, err, "запись снятого типа обязана быть отвергнута триггером — "+
		"вырезание закрывает снятие, а не вход")
	require.Containsf(t, err.Error(), dotted,
		"отказ обязан назвать ЭЛЕМЕНТ: автор правила ни одного элемента подстановочной "+
			"строки сам не выбирал: %v", err)
	require.Truef(t, strings.Contains(err.Error(), "23514") ||
		strings.Contains(err.Error(), "not a live platform resource"),
		"отказ пришёл не от референта третьей поверхности: %v", err)
}

// TestRetiringAResourceNoSelectorNamesLeavesTheCensusAlone — ПАРНЫЙ
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него «повисших стало 1» было бы неотличимо от переписи, которая считает
// повисшим ВСЯКИЙ снятый ресурс — то есть от предиката, срабатывающего на
// снятии как таковом, а не на потерянном референте.
func TestRetiringAResourceNoSelectorNamesLeavesTheCensusAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	read0 := selectorObjectTypesRead(t, ctx, pool)
	dangling0, _ := selectorsNamingDeadTypes(t, ctx, pool)
	require.Positive(t, read0, "прочитано ноль элементов object_types — перепись беспредметна")
	require.Zero(t, dangling0, "предпосылка нарушена: повисшие есть до пробы")

	rep, err := applier.Apply(ctx, probeManifest(
		probeResource("unnamed", "get"),
		probeResource("kept", "get"),
	))
	require.NoError(t, err)
	require.True(t, rep.Changed(), "заведение обязано изменить каталог: %s", rep)

	// Селектор пишется на СОСЕДНИЙ ресурс: он остаётся живым, поэтому снятие
	// `unnamed` его референта не касается. Одна ось различия с пробой выше.
	role := catalogRole(t, ctx, pool, "sel1942pos")
	require.NoError(t, writeSelector(ctx, pool, role, "fp-1942-pos",
		[]string{applierProbeModule + ".kept"}))

	gone, err := applier.Apply(ctx, probeManifest(probeResource("kept", "get")))
	require.NoError(t, err)
	require.Positivef(t, gone.RetiredResources, "ресурс не снят (%s) — контроль вакуумен", gone)

	read1 := selectorObjectTypesRead(t, ctx, pool)
	dangling1, list1 := selectorsNamingDeadTypes(t, ctx, pool)
	t.Logf("перепись: элементов прочитано %d → %d · повисших %d → %d %v",
		read0, read1, dangling0, dangling1, list1)
	require.Positive(t, read1, "после снятия перепись читает ноль элементов — она ослепла")
	require.Zerof(t, dangling1,
		"снятие ресурса, которого НЕ называет ни один селектор, дало %d повисших %v — "+
			"перепись срабатывает на снятии как таковом, и число из соседней пробы "+
			"не значит того, что она утверждает", dangling1, list1)
	require.Zerof(t, gone.PrunedSelectorRows+gone.PrunedSelectorRowsDropped,
		"вырезание тронуло строки, снятого типа не называвшие (%s) — применитель правит "+
			"селекторы арендаторов шире собственного предмета", gone)
}
