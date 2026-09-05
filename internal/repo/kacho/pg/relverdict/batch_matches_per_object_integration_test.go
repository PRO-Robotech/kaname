// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// batch_matches_per_object_integration_test.go — два пути чтения, ОДИН ответ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Вердикт спрашивают двумя способами. Одиночный (`Allowed`) идёт от стража, у
// которого на руках один объект. Страничный (`AllowedMany`) идёт от фильтра
// списка: он собирает ответ ОДНОЙ читающей транзакцией, потому что стоимость
// страницы принадлежит запросу, а страница по контракту доходит до тысячи
// объектов.
//
// Это ВТОРОЕ чтение тех же строк — и второе чтение есть место, где расхождение
// прячется. Разойдись эти два пути хоть на одном объекте, и доступ стал бы
// зависеть от того, пришёл вопрос в одиночку или на странице. Страницы — ровно
// то место, куда никто не смотрит: одиночный путь щупают стражи на каждом
// обращении, а страничный виден только через состав списка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОБА НАПИСАНА ЗАНОВО
//
// Равенство двух путей утверждалось и раньше — пробой в пакете двери решения,
// написанной против отдельного страничного чтения структурных фактов. И то
// чтение, и та проба сняты вместе с внешним движком отношений. Страничный путь
// при этом НЕ СНЯТ: он переехал в форму (`Asker.AllowedMany`) и остался тем, чем
// был, — вторым чтением тех же столбцов.
//
// Замер на момент написания: `AllowedMany` во всём дереве не звала НИ ОДНА проба
// против настоящей базы (предикат: `git grep -ln AllowedMany -- '*_test.go'` —
// единственное попадание было в страже провязки, который лишь требует наличия
// метода у подставного типа). То есть свойство пережило свою проверку — тот самый
// класс, ради которого проверки и заводят.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ, КРОМЕ РАВЕНСТВА
//
// Позиционность. Ответ обязан прийти той же длины и в порядке ЗАДАННЫХ
// идентификаторов: верный, но переставленный вердикт отфильтровал бы страницу
// чужим ответом, и снаружи это выглядит как «часть ресурсов пропала» — жалоба, по
// которой к перестановке не придёшь никогда.
//
// Смешанная страница. Разрешённые и запрещённые объекты идут ВПЕРЕМЕЖКУ и
// намеренно: страница, где сначала все «да», а потом все «нет», зеленеет и на
// реализации, потерявшей соответствие позиций.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// seedMixedPage кладёт n объектов, из которых доступны ТОЛЬКО чётные.
//
// Разграничение сделано выдачей на разные области, а не пропуском строк: объект
// без родителя выпал бы из ответа по другой причине (цепь не строится), и
// отрицательная половина зеленела бы на сломанном обходе вверх.
func seedMixedPage(t *testing.T, ctx context.Context, tx pgx.Tx, n int) (ids []string, want []bool) {
	t.Helper()
	// Вторая область — тот же аккаунт, другой проект: выдачи на неё нет.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ('prj-2', 'acc-1', 'other')
		 ON CONFLICT DO NOTHING`)
	pointerThroughJournal(t, ctx, tx, "project", "prj-2", "account", "account:acc-1")

	ids = make([]string, 0, n)
	want = make([]bool, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("net-mix-%02d", i)
		granted := i%2 == 0
		parent := "prj-2"
		if granted {
			parent = "prj-1"
		}
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id) VALUES ($2, $1)`,
			id, catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', $1, 'project', $2, 1)`, id, parent)
		ids = append(ids, id)
		want = append(want, granted)
	}
	return ids, want
}

// Страничный вердикт совпадает с одиночным — по КАЖДОМУ объекту страницы.
//
// # ЭТА ПРОБА НЕОТДЕЛИМА ОТ `TestAllowedMany_EveryArmOfTheRuleReachesThePage`
//
// Сужений по областям в страничном запросе ТРИ — ветвь выдач, ветвь прямых
// фактов и ветвь меток, — и снятие любого даёт наблюдаемый over- или under-grant.
// Эта проба ловит только ПЕРВОЕ: её посев строит доступ якорной выдачей, поэтому
// на двух остальных ветвях страница и одиночный вопрос молчат ОДИНАКОВО, и
// «ответы совпали» ничего о них не говорит.
//
// Две другие ветви держит `EveryArmOfTheRuleReachesThePage` (соседний файл,
// `batch_roundtrip_integration_test.go`): у неё на каждой ветви есть достижимый
// объект и недостижимый.
//
// Поэтому пробы снимаются только ВМЕСТЕ. Снятие одной оставляет её полосу без
// сторожа, и заметно это не станет: оставшаяся продолжит зеленеть.
func TestAllowedMany_AgreesWithAllowedObjectByObject(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-batch", "vpc_network", "get", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-batch", "rol-batch")
		seedMixedPage(t, ctx, tx, 8)
	})
	asker := relverdict.NewAsker(pool)

	ids, want := func() ([]string, []bool) {
		ids := make([]string, 0, 8)
		want := make([]bool, 0, 8)
		for i := 0; i < 8; i++ {
			ids = append(ids, fmt.Sprintf("net-mix-%02d", i))
			want = append(want, i%2 == 0)
		}
		return ids, want
	}()

	page, err := asker.AllowedMany(ctx, "user:usr-1", "vpc_network", ids, "v_get", nil)
	if err != nil {
		t.Fatalf("страничный вопрос: %v", err)
	}
	if len(page) != len(ids) {
		t.Fatalf("страница из %d объектов получила %d вердиктов — соответствие позиций потеряно, "+
			"и любая сверка по индексу читает чужой ответ", len(ids), len(page))
	}

	// Положительный и отрицательный контроли ВНУТРИ одного прогона: без первого
	// проба зеленела бы на форме, которая отвечает «нет» всегда; без второго — на
	// форме, которая отвечает «да» всегда.
	allowed, denied := 0, 0
	for i, id := range ids {
		one, err := asker.Allowed(ctx, "user:usr-1", "vpc_network", id, "v_get", nil)
		if err != nil {
			t.Fatalf("одиночный вопрос про %s: %v", id, err)
		}
		if one != want[i] {
			t.Fatalf("одиночный вердикт про %s = %v, ожидался %v — расходится сама фикстура, "+
				"и сравнивать два пути на ней нельзя", id, one, want[i])
		}
		if page[i] != one {
			t.Errorf("объект %s (позиция %d): страница сказала %v, одиночный вопрос — %v. "+
				"Доступ зависит от того, пришёл вопрос в одиночку или на странице",
				id, i, page[i], one)
		}
		if one {
			allowed++
		} else {
			denied++
		}
	}
	if allowed == 0 || denied == 0 {
		t.Fatalf("фикстура вырождена: разрешено %d, отказано %d — равенство путей, проверенное "+
			"на односторонней странице, ничего не утверждает", allowed, denied)
	}
	t.Logf("перепись: объектов на странице %d, из них разрешено %d, отказано %d", len(ids), allowed, denied)
}

// Порядок ответа — порядок ЗАДАННЫХ идентификаторов, а не порядок хранения.
//
// Отдельной пробой, а не строкой в предыдущей: та сверяет позиции на порядке,
// который совпадает с естественным порядком строк в базе, и на нём перестановка
// невидима by construction.
func TestAllowedMany_AnswersInTheOrderItWasAsked(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-order", "vpc_network", "get", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-order", "rol-order")
		seedMixedPage(t, ctx, tx, 6)
	})
	asker := relverdict.NewAsker(pool)

	// Обратный порядок: доступные объекты чётные, значит в перевёрнутой странице
	// из шести элементов ожидание тоже переворачивается.
	ids := []string{"net-mix-05", "net-mix-04", "net-mix-03", "net-mix-02", "net-mix-01", "net-mix-00"}
	want := []bool{false, true, false, true, false, true}

	page, err := asker.AllowedMany(ctx, "user:usr-1", "vpc_network", ids, "v_get", nil)
	if err != nil {
		t.Fatalf("страничный вопрос: %v", err)
	}
	if len(page) != len(ids) {
		t.Fatalf("длина ответа %d при %d заданных", len(page), len(ids))
	}
	for i := range ids {
		if page[i] != want[i] {
			t.Fatalf("порядок ответа не следует порядку вопроса: позиция %d (%s) = %v, ожидалось %v. "+
				"Верный, но переставленный вердикт отфильтровал бы страницу чужим ответом",
				i, ids[i], page[i], want[i])
		}
	}
}

// Отношение, которого модель не знает, отвергается и на СТРАНИЦЕ.
//
// Одиночный путь это уже утверждает (`TestAsk_RelationUnknownToTheModelIsAnErrorNotADenial`).
// Страничный обязан вести себя так же: частичный ответ или молчаливое «нет» на
// всю страницу означали бы вердикт, которого никто не выносил.
func TestAllowedMany_UnknownRelationIsAnErrorNotAPageOfDenials(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-unk", "vpc_network", "get", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-unk", "rol-unk")
		seedMixedPage(t, ctx, tx, 4)
	})
	asker := relverdict.NewAsker(pool)
	ids := []string{"net-mix-00", "net-mix-01"}

	// Положительный контроль рядом: на ЗНАКОМОМ отношении та же страница проходит.
	// Без него отрицание ниже зеленело бы и на форме, которая не отвечает никогда.
	if _, err := asker.AllowedMany(ctx, "user:usr-1", "vpc_network", ids, "v_get", nil); err != nil {
		t.Fatalf("знакомое отношение не прошло: %v — отрицание ниже недействительно", err)
	}

	page, err := asker.AllowedMany(ctx, "user:usr-1", "vpc_network", ids, "v_gte", nil)
	if err == nil {
		t.Fatalf("отношение, которого в модели нет, принято молча и дало страницу вердиктов %v — "+
			"вызывающий не отличит опечатку от отказа, и искать будет в правах", page)
	}
}
