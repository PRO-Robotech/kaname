// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// list_page_cost_integration_test.go — СТОИМОСТЬ СТРАНИЦЫ ПРИНАДЛЕЖИТ ЗАПРОСУ,
// а не набору.
//
// # Предмет
//
// Перечисление отдаёт страницу, но брало в кандидаты ВЕСЬ тип после курсора и
// только потом сужало. Цепь областей при этом раскручивалась на всём наборе, а не
// на странице, поэтому одна и та же страница договора дорожала с ростом числа
// объектов — при неизменном ответе.
//
// # Предикат — СВОЙСТВО, а не число
//
// Утверждается не «быстрее», а «НЕ РАСТЁТ»: величина на большом наборе не
// превосходит величину на малом больше чем в K раз, и K объявлен ДО прогона,
// константой ниже, а не подобран под полученные числа.
//
// # Единица — СТРОКИ, а не миллисекунды
//
// Миллисекунда зависит от машины, соседней нагрузки и кэша; строка, прочитанная
// Postgres, не зависит ни от чего из этого и воспроизводится на чужом стенде.
// Считается она самим Postgres — `pg_stat_xact_all_tables` за текущую
// транзакцию, — а не нашей оценкой плана: оценка плана есть мнение планировщика,
// а предмет здесь фактическое чтение.
//
// # Положительный контроль рядом — иначе отрицание зеленеет на сломанном
//
// «Не растёт» выполняется тождественно для запроса, который не читает ничего и
// не отвечает ничем. Поэтому каждая точка кривой ОБЯЗАНА отдать полную страницу
// правильных идентификаторов; страница короче запрошенной или с чужим объектом
// роняет пробу раньше, чем дело доходит до отношения величин.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
)

// pageCostRatioCeiling — K, объявленный ДО прогона.
//
// Три, а не единица: планировщик волен выбрать для маленькой таблицы полный
// проход вместо обхода индекса, и тогда малая точка кривой прочитает НЕ МЕНЬШЕ
// большой. Запас покрывает эту разницу и не покрывает рост с набором: до фикса
// отношение измерялось десятками.
const pageCostRatioCeiling = 3.0

// pageCostNarrowPage — страница ЗАВЕДОМО меньше самого малого набора кривой.
//
// Меньше — чтобы обе точки отдавали страницу ОДНОГО размера: сравнение страниц
// разной длины мерило бы длину ответа, а не стоимость страницы.
const pageCostNarrowPage = 50

// pageCostContractPage — страница договора. Сужать её ради бюджета запрещено
// нормой, поэтому она меряется как есть.
const pageCostContractPage = 1000

// TestList_PageCostBelongsToTheRequestNotTheSet — кривая по числу объектов плоская.
func TestList_PageCostBelongsToTheRequestNotTheSet(t *testing.T) {
	type point struct {
		n          int
		rowsNarrow int64
		rowsPage   int64
	}
	var curve []point

	for _, n := range []int{100, 1000, 10000} {
		p := point{n: n}
		withTx(t, func(ctx context.Context, tx pgx.Tx) {
			seedLabelledSet(t, ctx, tx, n)
			p.rowsNarrow = measureListRows(t, ctx, tx, pageCostNarrowPage, n)
			p.rowsPage = measureListRows(t, ctx, tx, pageCostContractPage, n)
		})
		curve = append(curve, p)
	}

	// Объём осмотренного печатается ВСЕГДА: «не растёт» без кривой неотличимо от
	// «ничего не мерили».
	t.Logf("осмотрено: %d точек кривой; единица — строк, прочитанных Postgres из схемы kacho_iam за один вызов List", len(curve))
	for _, p := range curve {
		t.Logf("  N=%-6d страница %-4d: %6d строк   страница %-4d: %6d строк",
			p.n, pageCostNarrowPage, p.rowsNarrow, pageCostContractPage, p.rowsPage)
	}

	small, large := curve[0], curve[len(curve)-1]
	// (а) узкая страница: обе точки отдают страницу одной длины, значит отношение
	// говорит про стоимость, а не про длину ответа.
	if got := ratio(large.rowsNarrow, small.rowsNarrow); got > pageCostRatioCeiling {
		t.Errorf("страница %d: N=%d прочитала %d строк против %d при N=%d — в %.1f раза, потолок K=%.1f "+
			"объявлен до прогона. Стоимость страницы растёт с НАБОРОМ: кандидаты берутся без предела, "+
			"и цепь областей раскручивается на всём типе вместо страницы",
			pageCostNarrowPage, large.n, large.rowsNarrow, small.rowsNarrow, small.n, got, pageCostRatioCeiling)
	}
	// (б) страница договора: тот же вопрос на величине, которая есть часть
	// контракта. Малая точка здесь — N=1000, где страница впервые заполняется
	// целиком; сравнивать с N=100 значило бы сравнить страницу из 100 со страницей
	// из 1000.
	mid := curve[1]
	if got := ratio(large.rowsPage, mid.rowsPage); got > pageCostRatioCeiling {
		t.Errorf("страница договора %d: N=%d прочитала %d строк против %d при N=%d — в %.1f раза, "+
			"потолок K=%.1f объявлен до прогона. page_size до 1000 — часть контракта, и сужать его "+
			"ради бюджета норма запрещает",
			pageCostContractPage, large.n, large.rowsPage, mid.rowsPage, mid.n, got, pageCostRatioCeiling)
	}
}

func ratio(large, small int64) float64 {
	if small <= 0 {
		return float64(large)
	}
	return float64(large) / float64(small)
}

// measureListRows — сколько строк Postgres прочитал из схемы iam за ОДИН вызов
// перечисления, вместе с положительным контролем ответа.
//
// Контроль здесь, а не в вызывающем: величина, снятая с запроса, который ответил
// не то, — это стоимость неверного ответа, и отношение таких величин ничего не
// говорит о стоимости страницы.
func measureListRows(t *testing.T, ctx context.Context, tx pgx.Tx, page, n int) int64 {
	t.Helper()
	before := tuplesRead(t, ctx, tx)
	ids, next, err := relverdict.List(ctx, tx, relverdict.ListQuery{
		Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get", Limit: page,
	})
	if err != nil {
		t.Fatalf("перечисление (N=%d, страница %d): %v", n, page, err)
	}
	after := tuplesRead(t, ctx, tx)

	want := page
	if n < page {
		want = n
	}
	if len(ids) != want {
		t.Fatalf("N=%d, страница %d: отдано %d идентификаторов, ожидалось %d — "+
			"величина, снятая с неполного ответа, есть стоимость неполного ответа", n, page, len(ids), want)
	}
	if want == page && next == "" {
		t.Fatalf("N=%d: страница полна (%d), а продолжения нет — остаток набора стал бы "+
			"невидим при живых правах", n, page)
	}
	for _, id := range ids {
		if len(id) < 4 || id[:4] != "net-" {
			t.Fatalf("N=%d: в странице чужой объект %q", n, id)
		}
	}
	return after - before
}

// tuplesRead — строки, прочитанные из таблиц схемы iam в ТЕКУЩЕЙ транзакции.
//
// Спрашивается сам Postgres: он считает фактические чтения, а не наше
// представление о плане. Прогонный проход и выборка по индексу складываются —
// предмет один: сколько строк пришлось тронуть, чтобы ответить.
func tuplesRead(t *testing.T, ctx context.Context, tx pgx.Tx) int64 {
	t.Helper()
	var total int64
	if err := tx.QueryRow(ctx, `
		SELECT coalesce(sum(seq_tup_read + coalesce(idx_tup_fetch, 0)), 0)::bigint
		  FROM pg_stat_xact_all_tables
		 WHERE schemaname = 'kacho_iam'`).Scan(&total); err != nil {
		t.Fatalf("счётчик прочитанных строк: %v", err)
	}
	return total
}

// seedLabelledSet — набор из n объектов, все под правилом с ветвью МЕТОК.
//
// Ветвь меток, а не якорная: предмет находки — ячейка, где страница сужается
// предикатом меток, и якорная ветвь этот предикат не читает вовсе.
func seedLabelledSet(t *testing.T, ctx context.Context, tx pgx.Tx, n int) {
	t.Helper()
	seedTenant(t, ctx, tx)
	seedRole(t, ctx, tx, "rol-cost", "vpc_network", "get", "labels", `{"env":"prod"}`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ('acb-c', 'user', 'usr-1', 'rol-cost', 'project', 'prj-1', 'ACTIVE')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-c', 'user', 'usr-1')`)

	// Посев набором, а не построчно: построчный посев на десяти тысячах мерил бы
	// терпение, а не форму.
	exec(t, ctx, tx, fmt.Sprintf(`
		INSERT INTO kacho_iam.resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels)
		SELECT 'vpc_network', 'net-' || to_char(g, 'FM0000000'), 'prj-1', 'acc-1', '{"env":"prod"}'::jsonb
		  FROM generate_series(0, %d) g`, n-1))
	exec(t, ctx, tx, fmt.Sprintf(`
		INSERT INTO kacho_iam.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
		SELECT 'vpc_network', 'net-' || to_char(g, 'FM0000000'), 'project', 'prj-1', 1
		  FROM generate_series(0, %d) g`, n-1))
	// Статистика — чтобы измерялся ЗАПРОС, а не отсутствие статистики: на пустых
	// оценках планировщик выбирает план по умолчанию, и кривая говорила бы о нём.
	exec(t, ctx, tx, `ANALYZE kacho_iam.resource_mirror, kacho_iam.resource_parent_edge,
		kacho_iam.access_bindings, kacho_iam.access_binding_subjects, kacho_iam.relation_fact`)
}
