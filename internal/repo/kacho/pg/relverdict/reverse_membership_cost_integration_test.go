// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// reverse_membership_cost_integration_test.go — #758: СТОИМОСТЬ ОБРАТНОГО
// ВОПРОСА НЕ ПРИНАДЛЕЖИТ ЧУЖИМ ЧЛЕНСТВАМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Соседняя проба (`membership_cost_integration_test.go`) доказала это свойство
// для ПРЯМЫХ вопросов — вердикта и перечисления объектов. Оба разбирают ПАРАМЕТР
// (`split_part`/`substr` от `$1`) и заходят в членства парой колонок.
//
// У ОБРАТНЫХ вопросов — «кто может» (`Subjects`) и «почему» (`Expand`) —
// параметра нет by construction: развернуть надо не вызывающего, а КАЖДЫЙ
// найденный субъект, и он приходит текстовой колонкой CTE. Поэтому там осталась
// прежняя форма:
//
//	JOIN kacho_iam.group_members gm
//	  ON n.subject IN ('group:' || gm.group_id, 'group:' || gm.group_id || '#member')
//
// `gm.group_id` — ведущая колонка `group_members_pkey`; склейка выводит её
// из-под ключа, и каждый обратный вопрос читает таблицу членств ЦЕЛИКОМ.
// Следствие то же, что нашла соседняя проба: вопрос про ОДИН объект дорожает с
// числом членств во всей схеме — не у спрашивающего, а у всех арендаторов сразу.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТОГО НЕ ВИДЕЛ НИ ОДИН ПРИБОР
//
// Обратные вопросы не идут через пер-RPC гейт вердикта: их зовут `ListSubjects`
// и `ExpandAccess`, а не `Check`. Измеренная стоимость вердикта их не касается,
// и долг оттого тихий. Соседняя проба его тоже не видит — она зовёт `Ask` и
// `List`, то есть ровно те два пути, где форма УЖЕ починена.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА, ПОТОЛОК И ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — как у соседней пробы, намеренно
//
// Единица — строки, прочитанные Postgres за транзакцию: она не зависит от
// машины, соседней нагрузки и кэша. Потолок отношения объявлен ДО прогона
// (`membershipCostRatioCeiling`, тот же), а не подобран под полученные числа.
//
// «Не растёт» выполняется тождественно для запроса, который ничего не находит,
// поэтому КАЖДАЯ точка кривой обязана вернуть верный ответ: обратный вопрос
// обязан назвать члена группы, которому право и принадлежит. Неверный ответ
// роняет пробу раньше, чем дело доходит до отношения величин.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// reverseMemberSubject — кого обратный вопрос обязан назвать в ОБЕИХ точках.
//
// Именно член группы, а не сама группа: группу называет прямой источник
// (строка факта), и проба, довольная ею, зеленела бы при полностью снятом
// развороте членства — то есть при снятом предмете.
const reverseMemberSubject = "user:" + membershipCostSubjectID

// TestSubjects_CostDoesNotBelongToOtherTenantsMemberships — «кто может» про ОДИН
// объект читает одинаково при одном членстве в схеме и при десяти тысячах.
func TestSubjects_CostDoesNotBelongToOtherTenantsMemberships(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	small := measureSubjectsRowsAtMembershipScale(t, membershipSmall)
	large := measureSubjectsRowsAtMembershipScale(t, membershipLarge)

	got := ratio(large, small)
	t.Logf("перепись: членств в схеме %d → строк %d; членств %d → строк %d; отношение %.2f при потолке %.2f",
		membershipSmall, small, membershipLarge, large, got, membershipCostRatioCeiling)

	if got > membershipCostRatioCeiling {
		t.Fatalf(
			"стоимость обратного вопроса «кто может» растёт с числом ЧУЖИХ членств: %d строк против %d "+
				"(отношение %.2f > %.2f).\nПраво в обеих точках выдано через ОДНУ группу; разница целиком "+
				"в членствах, которых вопрос не касается. Причина известна: разворот членства сравнивает "+
				"СКЛЕЙКУ ('group:' || gm.group_id) с субъектом, и индекс по (group_id, member_type, member_id) "+
				"такую форму не обслуживает.",
			large, small, got, membershipCostRatioCeiling)
	}
}

// TestExpand_CostDoesNotBelongToOtherTenantsMemberships — то же свойство для
// вопроса «почему».
//
// ЗАЧЕМ ОТДЕЛЬНАЯ ТОЧКА. Склейку несут ДВА обратных запроса, и у каждого свой
// текст. Инъекция это и показывает: возврат склейки в `expand.go` оставляет
// пробу «кто может» зелёной — то есть половина починки была бы без охраны.
func TestExpand_CostDoesNotBelongToOtherTenantsMemberships(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	small := measureExpandRowsAtMembershipScale(t, membershipSmall)
	large := measureExpandRowsAtMembershipScale(t, membershipLarge)

	got := ratio(large, small)
	t.Logf("перепись: членств в схеме %d → строк %d; членств %d → строк %d; отношение %.2f при потолке %.2f",
		membershipSmall, small, membershipLarge, large, got, membershipCostRatioCeiling)

	if got > membershipCostRatioCeiling {
		t.Fatalf(
			"стоимость обратного вопроса «почему» растёт с числом ЧУЖИХ членств: %d строк против %d "+
				"(отношение %.2f > %.2f).\nПричина та же, что у «кто может»: разворот членства сравнивает "+
				"склейку колонки с субъектом и выводит ведущую колонку ключа из-под индекса.",
			large, small, got, membershipCostRatioCeiling)
	}
}

// measureSubjectsRowsAtMembershipScale — строки, прочитанные ОДНИМ вопросом
// «кто может» на схеме, где всего n членств.
func measureSubjectsRowsAtMembershipScale(t *testing.T, n int) int64 {
	t.Helper()

	var rows int64
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedMembershipNoise(t, ctx, tx, n)

		before := tuplesRead(t, ctx, tx)
		got, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network",
			ObjectID:   membershipCostObjectID,
			Relation:   "v_get",
			Limit:      100,
		})
		after := tuplesRead(t, ctx, tx)
		if err != nil {
			t.Fatalf("при %d членствах вопрос «кто может»: %v", n, err)
		}
		assertNamesTheMember(t, n, "кто может", got)
		rows = after - before
	})
	return rows
}

// measureExpandRowsAtMembershipScale — строки, прочитанные ОДНИМ вопросом
// «почему» на схеме, где всего n членств.
func measureExpandRowsAtMembershipScale(t *testing.T, n int) int64 {
	t.Helper()

	var rows int64
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedMembershipNoise(t, ctx, tx, n)

		before := tuplesRead(t, ctx, tx)
		got, err := relverdict.Expand(ctx, tx, "vpc_network", membershipCostObjectID, "v_get")
		after := tuplesRead(t, ctx, tx)
		if err != nil {
			t.Fatalf("при %d членствах вопрос «почему»: %v", n, err)
		}
		subjects := make([]string, 0, len(got))
		for _, s := range got {
			subjects = append(subjects, s.Subject)
		}
		assertNamesTheMember(t, n, "почему", subjects)
		rows = after - before
	})
	return rows
}

// assertNamesTheMember — положительный контроль обеих точек кривой.
//
// Отдельной функцией, потому что обе пробы обязаны требовать ОДНО И ТО ЖЕ:
// разойдясь, они дали бы «не растёт» на разных ответах, и сравнивать было бы
// нечего.
func assertNamesTheMember(t *testing.T, n int, question string, subjects []string) {
	t.Helper()
	for _, s := range subjects {
		if s == reverseMemberSubject {
			return
		}
	}
	t.Fatalf("при %d членствах вопрос «%s» НЕ назвал %s, хотя право выдано его группе: "+
		"проба мерила бы стоимость неверного ответа. Названы: %v",
		n, question, reverseMemberSubject, subjects)
}
