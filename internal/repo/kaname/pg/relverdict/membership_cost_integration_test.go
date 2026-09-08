// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// membership_cost_integration_test.go — СТОИМОСТЬ ВОПРОСА НЕ ПРИНАДЛЕЖИТ ЧУЖИМ
// ЧЛЕНСТВАМ.
//
// # Предмет
//
// Цепочка «кем говорит спрашивающий» ищет группы, в которых он состоит, сравнивая
// СКЛЕЙКУ двух колонок с готовой строкой субъекта:
//
//	WHERE gm.member_type || ':' || gm.member_id = $1::text
//
// Единственный индекс таблицы членств — по паре колонок; склейку он не
// обслуживает, поэтому каждая ветвь читает таблицу целиком. Следствие: вопрос про
// ОДИН объект дорожает с числом членств ВО ВСЕЙ СХЕМЕ — не у спрашивающего, а у
// всех арендаторов сразу.
//
// Замер до починки (1000 объектов, страница 1000): прямой вердикт читал 18 строк
// при одном членстве в схеме и 20 018 при десяти тысячах — ровно удвоенное число
// членств плюс постоянная.
//
// # Ось, которой не варьировала ни одна проба
//
// Соседняя проба стоимости страницы доказывает плоскость по числу ОБЪЕКТОВ и
// молчит об этой оси: пробы пакета кладут в таблицу членств по одной строке.
// Плоскость по одной оси не влечёт плоскости по другой, и здесь это не
// придирка — предикат склейки читается по-разному именно с ростом второй.
//
// # Единица и форма утверждения — как у соседней пробы, намеренно
//
// Строки, прочитанные Postgres за транзакцию, а не миллисекунды: строка не
// зависит от машины, соседней нагрузки и кэша. Утверждается СВОЙСТВО «не растёт»,
// а потолок отношения объявлен ДО прогона константой ниже, а не подобран под
// полученные числа.
//
// # Положительный контроль — иначе отрицание зеленеет на сломанном
//
// «Не растёт» выполняется тождественно для запроса, который ничего не читает и
// ничего не отвечает. Поэтому каждая точка кривой обязана вернуть ВЕРНЫЙ вердикт:
// разрешено там, где право есть, и отказано там, где его нет. Неверный ответ
// роняет пробу раньше, чем дело доходит до отношения величин.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// membershipCostRatioCeiling — K, объявленный ДО прогона.
//
// Постоянная часть чтения (сам объект, его правило, область) не зависит от числа
// членств, поэтому отношение никогда не будет ровно единицей даже при идеальном
// доступе по индексу. Два — это запас на дребезг статистики и на постоянную
// часть; отношение, наблюдавшееся до починки, — больше тысячи, и никакой запас
// его не покрывает.
const membershipCostRatioCeiling = 2.0

// membershipSmall / membershipLarge — две точки кривой по числу ЧУЖИХ членств.
//
// Чужих: спрашивающий в обеих точках состоит ровно в одной группе, и именно она
// даёт ему право. Всё остальное — членства других субъектов в других группах, то
// есть ровно то, что вопрос читать не обязан.
const (
	membershipSmall = 1
	membershipLarge = 10001
)

// TestVerdict_CostDoesNotBelongToOtherTenantsMemberships — прямой вердикт про ОДИН
// объект читает одинаково при одном членстве в схеме и при десяти тысячах.
func TestVerdict_CostDoesNotBelongToOtherTenantsMemberships(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	small := measureVerdictRowsAtMembershipScale(t, membershipSmall)
	large := measureVerdictRowsAtMembershipScale(t, membershipLarge)

	got := ratio(large, small)
	t.Logf("перепись: членств в схеме %d → строк %d; членств %d → строк %d; отношение %.2f при потолке %.2f",
		membershipSmall, small, membershipLarge, large, got, membershipCostRatioCeiling)

	if got > membershipCostRatioCeiling {
		t.Fatalf(
			"стоимость прямого вердикта растёт с числом ЧУЖИХ членств: %d строк против %d (отношение %.2f > %.2f).\n"+
				"Спрашивающий в обеих точках состоит ровно в одной группе — разница целиком в членствах,\n"+
				"которых вопрос не касается. Причина известна: предикат сравнивает СКЛЕЙКУ колонок\n"+
				"(gm.member_type || ':' || gm.member_id) с готовой строкой, и индекс по паре колонок такую\n"+
				"форму не обслуживает.",
			large, small, got, membershipCostRatioCeiling)
	}
}

// measureVerdictRowsAtMembershipScale — строки, прочитанные ОДНИМ прямым вердиктом
// на схеме, где всего n членств.
//
// Транзакция откатывается: точки кривой не должны видеть посев друг друга.
func measureVerdictRowsAtMembershipScale(t *testing.T, n int) int64 {
	t.Helper()

	var rows int64
	// Харнесс дерева, а не своё соединение: транзакция откатывается, и точки
	// кривой не видят посева друг друга.
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedMembershipNoise(t, ctx, tx, n)

		before := tuplesRead(t, ctx, tx)
		allowed := askDirectVerdict(t, ctx, tx)
		after := tuplesRead(t, ctx, tx)

		// Положительный контроль: вердикт обязан быть ВЕРНЫМ в каждой точке,
		// иначе «не растёт» доказывалось бы на запросе, который ничего не находит.
		if !allowed {
			t.Fatalf("при %d членствах вердикт отказал там, где право выдано через группу — "+
				"проба мерила бы стоимость неверного ответа", n)
		}
		rows = after - before
	})
	return rows
}

// seedMembershipNoise — n членств в схеме, из которых РОВНО ОДНО принадлежит
// спрашивающему и даёт ему право.
//
// Остальные — членства других субъектов в других группах: то, что вопрос читать
// не обязан. Именно их число и варьируется.
func seedMembershipNoise(t *testing.T, ctx context.Context, tx pgx.Tx, n int) {
	t.Helper()

	// Аккаунт — предпосылка группы (внешний ключ). Соседние пробы пакета сеют
	// `acc-1` своим харнессом; здесь заводится собственный, чтобы посев шума не
	// зависел от того, что успела положить соседняя проба.
	if _, err := tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ($1, 'membership-cost', $2)
		ON CONFLICT DO NOTHING`, membershipCostAccountID, membershipCostSubjectID); err != nil {
		t.Fatalf("посев аккаунта: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO kaname.groups (id, account_id, name, description)
		VALUES ($1, $2, 'membership-cost', '')
		ON CONFLICT DO NOTHING`, membershipCostGroupID, membershipCostAccountID); err != nil {
		t.Fatalf("посев группы: %v", err)
	}
	// Пользователь — предпосылка членства (внешний ключ проверяется).
	if _, err := tx.Exec(ctx, `
		INSERT INTO kaname.users (id, external_id, email, account_id)
		VALUES ($1, $1, $1 || '@kacho.local', $2)
		ON CONFLICT DO NOTHING`, membershipCostSubjectID, membershipCostAccountID); err != nil {
		t.Fatalf("посев спрашивающего: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO kaname.group_members (group_id, member_type, member_id)
		VALUES ($1, 'user', $2)
		ON CONFLICT DO NOTHING`, membershipCostGroupID, membershipCostSubjectID); err != nil {
		t.Fatalf("посев членства спрашивающего: %v", err)
	}

	// Шум: n−1 членств ЧУЖИХ субъектов в чужих группах.
	if n > 1 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO kaname.groups (id, account_id, name, description)
			SELECT 'grp-noise-' || lpad(i::text, 12, '0'), $2, 'noise-' || i, ''
			  FROM generate_series(1, $1) AS i
			ON CONFLICT DO NOTHING`, n-1, membershipCostAccountID); err != nil {
			t.Fatalf("посев чужих групп: %v", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO kaname.users (id, external_id, email, account_id)
			SELECT 'usr-noise-' || lpad(i::text, 12, '0'), 'ext-noise-' || i,
			       'noise-' || i || '@kacho.local', $2
			  FROM generate_series(1, $1) AS i
			ON CONFLICT DO NOTHING`, n-1, membershipCostAccountID); err != nil {
			t.Fatalf("посев чужих субъектов: %v", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO kaname.group_members (group_id, member_type, member_id)
			SELECT 'grp-noise-' || lpad(i::text, 12, '0'), 'user', 'usr-noise-' || lpad(i::text, 12, '0')
			  FROM generate_series(1, $1) AS i
			ON CONFLICT DO NOTHING`, n-1); err != nil {
			t.Fatalf("посев чужих членств: %v", err)
		}
	}

	// Факт, выданный ГРУППЕ: без него цепочка членств не читалась бы вовсе, и
	// проба мерила бы вопрос, который до неё не доходит.
	if _, err := tx.Exec(ctx, `
		INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		VALUES ('vpc_network', $1, 'v_get', 'group:' || $2)
		ON CONFLICT DO NOTHING`, membershipCostObjectID, membershipCostGroupID); err != nil {
		t.Fatalf("посев факта группы: %v", err)
	}

	// Статистика: без неё планировщик выбирает план по пустым оценкам, и проба
	// утверждала бы о другом состоянии мира, чем развёрнутая база.
	if _, err := tx.Exec(ctx, `ANALYZE kaname.group_members, kaname.groups`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	var got int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM kaname.group_members`).Scan(&got); err != nil {
		t.Fatalf("перепись членств: %v", err)
	}
	if got < int64(n) {
		t.Fatalf("посев не создал заявленного числа членств: объявлено %d, в таблице %d — "+
			"кривая мерила бы не ту ось", n, got)
	}
}

const (
	membershipCostAccountID = "acc-membership-cost"
	membershipCostGroupID   = "grp-membership-cost"
	membershipCostSubjectID = "usr-membership-cost"
	membershipCostObjectID  = "net-membership-cost"
)

// askDirectVerdict — ОДИН прямой вопрос настоящим путём пакета.
//
// Своей копии запроса здесь нет намеренно: копия мерила бы саму себя и осталась
// бы красной после починки прод-кода — либо, будучи поправленной вместе с ним,
// перестала бы касаться предмета вовсе. Проба обязана звать то, что исполняется.
func askDirectVerdict(t *testing.T, ctx context.Context, tx pgx.Tx) bool {
	t.Helper()

	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject:    "user:" + membershipCostSubjectID,
		ObjectType: "vpc_network",
		ObjectID:   membershipCostObjectID,
		Relation:   "v_get",
	})
	if err != nil {
		t.Fatalf("прямой вердикт: %v", err)
	}
	return got == relverdict.Allow
}

// TestList_CostDoesNotBelongToOtherTenantsMemberships — то же свойство для
// ПЕРЕЧИСЛЕНИЯ, а не только для прямого вердикта.
//
// ЗАЧЕМ ОТДЕЛЬНАЯ ТОЧКА. Предикат склейки несут ЧЕТЫРЕ вопроса формы E, и проба
// вердикта покрывает лишь путь `query.go`. Инъекция это и показала: возврат
// склейки в `list.go` оставлял пробу вердикта зелёной — то есть половина
// починки была бы без охраны, и следующий, кто перепишет перечисление обратно,
// узнал бы об этом от арендатора, а не от прогона.
func TestList_CostDoesNotBelongToOtherTenantsMemberships(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	small := measureListRowsAtMembershipScale(t, membershipSmall)
	large := measureListRowsAtMembershipScale(t, membershipLarge)

	got := ratio(large, small)
	t.Logf("перепись: членств %d → строк %d; членств %d → строк %d; отношение %.2f при потолке %.2f",
		membershipSmall, small, membershipLarge, large, got, membershipCostRatioCeiling)

	if got > membershipCostRatioCeiling {
		t.Fatalf("стоимость страницы растёт с числом ЧУЖИХ членств: %d строк против %d "+
			"(отношение %.2f > %.2f) — предикат склейки в перечислении", large, small, got, membershipCostRatioCeiling)
	}
}

// measureListRowsAtMembershipScale — строки, прочитанные ОДНИМ перечислением на
// схеме, где всего n членств.
//
// Набор объектов сеется ГОТОВЫМ посевом соседней пробы (через производителя цепи,
// а не прямой записью в таблицу рёбер), а сверху кладётся шум членств. Субъект —
// тот же `usr-1`, что и там: право ему выдано напрямую, и это НЕ ослабляет
// предмет — предикат склейки читает таблицу членств целиком независимо от того,
// состоит ли спрашивающий хоть в одной группе. Именно поэтому чужие членства и
// дорожают вопрос, к которому не относятся.
func measureListRowsAtMembershipScale(t *testing.T, n int) int64 {
	t.Helper()

	const objects = 10

	var rows int64
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedLabelledSet(t, ctx, tx, objects)
		seedMembershipNoise(t, ctx, tx, n)

		before := tuplesRead(t, ctx, tx)
		ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get", Limit: objects,
		})
		if err != nil {
			t.Fatalf("перечисление при %d членствах: %v", n, err)
		}
		after := tuplesRead(t, ctx, tx)

		// Положительный контроль: страница обязана быть ПОЛНОЙ. Без него «не
		// растёт» доказывалось бы на перечислении, которое ничего не находит, —
		// и первая же редакция этой пробы на нём и споткнулась, что и было её
		// работой.
		if len(ids) != objects {
			t.Fatalf("при %d членствах перечисление отдало %d идентификаторов из %d — "+
				"проба мерила бы стоимость неполного ответа", n, len(ids), objects)
		}
		rows = after - before
	})
	return rows
}
