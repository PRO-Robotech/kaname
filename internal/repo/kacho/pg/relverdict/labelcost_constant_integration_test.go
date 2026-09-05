// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// labelcost_constant_integration_test.go — ВЫДАЧА ПО МЕТКЕ НЕ РАЗВОРАЧИВАЕТ НАБОР,
// и это свойство обязано держаться гейтом, а не намерением.
//
// # Что здесь утверждается и почему именно строками, а не миллисекундами
//
// Требование эпика — константа на проверку: время ответа не зависит от того,
// сколько ресурсов в облаке. Замер #727 показал, что оно выполнено: вердикт по
// объекту стоит около миллисекунды при десяти объектах под меткой и при десяти
// тысячах, а ввод метки не стоит ничего.
//
// Замер, однако, вердиктом не является: он снимается вручную, живёт отчётом и
// молчит, когда свойство пропадает. Держать константу обязан гейт, и он считает
// СТРОКИ, а не время: время шумит на занятой машине и требует порога, порог
// требует запаса, а запас прячет двукратный рост. Число строк детерминированно —
// либо разворачивание есть, либо его нет.
//
// # Что сломает эту пробу
//
// Возврат материализации по меткам: путь, который на вводе метки или на создании
// объекта под правилом ПИШЕТ строку на каждый совпавший объект. Тогда десятикратный
// рост числа объектов даст десятикратный рост числа строк, и проба назовёт это
// числом.
//
// # Почему положительный контроль обязателен
//
// Проба «строк не прибавилось» зеленеет на мёртвом пути: там, где выдача не
// работает вовсе, строк тоже не прибавляется. Поэтому рядом стоит утверждение,
// что вердикт на этих же объектах ПОЛОЖИТЕЛЕН, — без него отрицание не отличается
// от сломанной меточной ветви.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// verdictRows — строки, которые могло бы породить разворачивание набора.
//
// Считается ПРОЕКЦИЯ ЖУРНАЛА: именно в неё писала бы материализация «право на
// каждый совпавший объект». Таблица выбрана одна и названа здесь, чтобы проба
// не превратилась в перепись схемы, которая краснеет на каждой новой таблице,
// не имея к ней отношения.
func verdictRows(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.relation_fact`).Scan(&n); err != nil {
		t.Fatalf("счёт строк проекции: %v", err)
	}
	return n
}

// seedLabelledProjects — n проектов с меткой, попадающей под правило выдачи.
func seedLabelledProjects(t *testing.T, ctx context.Context, tx pgx.Tx, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		id := fmt.Sprintf("prj-cost-%05d", i)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.projects (id, account_id, name, labels)
			 VALUES ($1, 'acc-1', $2, $3::jsonb)`,
			id, fmt.Sprintf("cost-%05d", i), `{"env":"prod"}`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('project', $1, 'account', $2, 1)`, id, labelScopeAccount)
	}
}

func TestLabelGrantDoesNotExpandWithTheObjectCount(t *testing.T) {
	const (
		firstBatch  = 20
		secondBatch = 200 // десятикратный рост оси
	)

	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedLabelGrant(t, ctx, tx, "project")

		base := verdictRows(t, ctx, tx)

		seedLabelledProjects(t, ctx, tx, 0, firstBatch)
		afterFirst := verdictRows(t, ctx, tx)

		seedLabelledProjects(t, ctx, tx, firstBatch, secondBatch)
		afterSecond := verdictRows(t, ctx, tx)

		grewOnFirst := afterFirst - base
		grewOnSecond := afterSecond - afterFirst

		t.Logf("строк проекции: до объектов %d · после %d объектов %d (+%d) · после %d объектов %d (+%d)",
			base, firstBatch, afterFirst, grewOnFirst, secondBatch, afterSecond, grewOnSecond)

		// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — идёт ПЕРВЫМ намеренно.
		//
		// Если он не проходит, отрицание ниже не утверждает ничего: строк не
		// прибавляется и там, где меточная ветвь мертва. Спрашиваем объект из
		// ВТОРОЙ партии — той, что заводилась после первого замера.
		lastID := fmt.Sprintf("prj-cost-%05d", secondBatch-1)
		if got := askLabelled(t, ctx, tx, "project", lastID); got != relverdict.Allow {
			t.Fatalf("меточная выдача не достала project:%s — вердикт %v. Пока это так, "+
				"утверждение «строк не прибавилось» ничего не значит: на мёртвой ветви "+
				"их не прибавляется тоже", lastID, got)
		}

		// ОТРИЦАНИЕ: рост оси в десять раз не порождает строк.
		if grewOnSecond != 0 {
			t.Fatalf("рост оси с %d до %d объектов добавил %d строк проекции — выдача по "+
				"метке снова разворачивает набор. Это возвращает зависимость цены от числа "+
				"ресурсов, снятую в #727: вердикт обязан вычисляться запросом, а не читаться "+
				"из заранее развёрнутого множества",
				firstBatch, secondBatch, grewOnSecond)
		}
		if grewOnFirst != 0 {
			t.Fatalf("заведение первых %d объектов добавило %d строк проекции — см. выше",
				firstBatch, grewOnFirst)
		}
	})
}

// TestLabelCostGateSeesExpansionWhenItHappens — ДОКАЗАТЕЛЬСТВО ИНЪЕКЦИЕЙ.
//
// Проба выше утверждает «строк не прибавилось». Утверждение это стоит ровно
// столько, сколько стоит способность счётчика ЗАМЕТИТЬ прибавку: счётчик,
// смотрящий не в ту таблицу или считающий константу, дал бы тот же ноль на
// разворачивании — и гейт зеленел бы именно тогда, когда обязан краснеть.
//
// Здесь разворачивание ВОСПРОИЗВОДИТСЯ руками — по строке на объект, ровно так,
// как писала бы материализация, — и утверждается, что счётчик видит рост,
// пропорциональный числу объектов.
//
// Прод-код при этом не трогается: инъекция идёт в данные внутри транзакции,
// которая откатывается. Гейт, доказанный подменой прод-кода, доказывал бы
// свойство подменённого кода.
func TestLabelCostGateSeesExpansionWhenItHappens(t *testing.T) {
	const objects = 30

	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedLabelGrant(t, ctx, tx, "project")
		seedLabelledProjects(t, ctx, tx, 0, objects)

		before := verdictRows(t, ctx, tx)

		// Разворачивание, какого в продукте нет: по факту на каждый объект.
		for i := 0; i < objects; i++ {
			exec(t, ctx, tx,
				`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
				 VALUES ('project', $1, 'v_get', 'user:usr-1')`,
				fmt.Sprintf("prj-cost-%05d", i))
		}

		after := verdictRows(t, ctx, tx)
		grew := after - before

		t.Logf("инъекция разворачивания: строк было %d, стало %d (+%d) на %d объектов",
			before, after, grew, objects)

		if grew != objects {
			t.Fatalf("счётчик строк проекции увидел прибавку %d вместо %d — он не замечает "+
				"разворачивания, а значит зелёный вердикт соседней пробы ничего не "+
				"утверждает", grew, objects)
		}
	})
}
