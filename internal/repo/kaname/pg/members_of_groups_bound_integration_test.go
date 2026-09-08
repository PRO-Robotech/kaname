// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// members_of_groups_bound_integration_test.go — СОСТАВ, ВОЗВРАЩАЕМЫЙ ОДНИМ
// ПЕРЕЧИСЛЕНИЕМ, ОГРАНИЧЕН СВЕРХУ, И УСЕЧЕНИЕ НАЗВАНО.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Полное перечисление выдач (#914) дочитывает состав групп, названных субъектами
// страницы. Страница ограничивает число ГРУПП — и не ограничивает числа ЧЛЕНОВ:
// членство неограниченно by construction, ровно поэтому у него есть свой
// пагинированный глагол. Чтение без предела отдало бы на законной странице сумму
// составов без верхней границы.
//
// Предел сам по себе — половина решения. Вторая половина в том, что усечение
// НАЗВАНО поимённо: молча укороченный состав читается вызывающим как факт о
// доступе, и «в группе больше никого» неотличимо от «дальше мы не читали».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГРУППЫ ДВЕ, А НЕ ОДНА
//
// Утверждение про усечение односторонне на одной группе: «назвали неполной» и
// «назвали неполными все» дают один и тот же ответ. Вторая группа, чей состав
// умещается ЦЕЛИКОМ и лежит по порядку РАНЬШЕ, — положительный контроль: она
// обязана вернуться полностью и в перечень неполных НЕ попасть.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// membersBoundLimit — предел, объявленный репозиторием. Здесь он воспроизведён
// числом намеренно: проба обязана утверждать ВЕЛИЧИНУ границы, а не повторять
// ту же константу, из которой граница вычислена, — иначе её изменение пройдёт
// молча по обеим сторонам сразу.
const membersBoundLimit = 1000

// rowsReadBy — сколько строк ПРОЧИТАЛ оператор. Берётся у плана настоящего
// исполнения (`EXPLAIN ANALYZE`), а не у длины ответа: форму ответа держит срез
// в Go, и по ней снятие предела выборки неотличимо от его наличия.
func rowsReadBy(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) float64 {
	t.Helper()
	var plan []map[string]any
	require.NoError(t, pool.QueryRow(ctx,
		"EXPLAIN (ANALYZE, FORMAT JSON) "+sql, args...).Scan(&plan))
	require.Len(t, plan, 1, "план обязан быть один — иначе замер не о том операторе")
	node, ok := plan[0]["Plan"].(map[string]any)
	require.True(t, ok, "у плана нет корневого узла — замер не состоялся")
	rows, ok := node["Actual Rows"].(float64)
	require.True(t, ok, "в плане нет числа прочитанных строк — замер не состоялся")
	return rows
}

// TestIntegration_R914_MembersOfGroupsIsBoundedAndNamesTheTruncation — предел
// действует, а усечение названо поимённо.
func TestIntegration_R914_MembersOfGroupsIsBoundedAndNamesTheTruncation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: закрытие пула ждёт возврата ВСЕХ соединений, а
	// проба, упавшая внутри открытой транзакции, своё уже не вернёт — отложенное
	// закрытие встанет ждать писателя, которого нет, и пакет упрётся в предел
	// прогона. Тогда «не выполнилось» приходит к читателю под видом красного, и
	// вердикта нет ни у одной пробы пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	const smallGroup = "grp-bound-a-small914" // по порядку РАНЬШЕ — умещается целиком
	const hugeGroup = "grp-bound-b-huge9141"  // по порядку ПОЗЖЕ — упирается в предел
	const smallSize = 3

	// Аккаунт заводится ТЕМ ЖЕ путём, что и в проде (владелец — настоящий
	// пользователь, отложенный внешний ключ разрешает курицу с яйцом): аккаунт,
	// вставленный сырым SQL в обход, отвергается ссылочной целостностью.
	repoForSeed := kanamepg.New(pool, nil)
	owner := mustSeedUser(t, ctx, pool, "members-bound-914")
	accountID := string(seedAccount(t, ctx, repoForSeed, "members-bound-914", owner).ID)

	for name, g := range map[string]string{"bound-a-small": smallGroup, "bound-b-huge": hugeGroup} {
		_, err = pool.Exec(ctx, `
			INSERT INTO kaname.groups (id, account_id, name)
			VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, g, accountID, name)
		require.NoError(t, err)
	}

	// Члены заводятся ОДНИМ стейтментом: строка членства проверяется триггером
	// существования, поэтому учётки обязаны быть настоящими.
	seedMembers := func(group, idPrefix string, n int) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
			SELECT $1 || lpad(i::text, 6, '0'), $2, $1 || lpad(i::text, 6, '0'),
			       $1 || lpad(i::text, 6, '0') || '@kacho.local', 'm', 'ACTIVE'
			  FROM generate_series(1, $3) AS i
			ON CONFLICT DO NOTHING`, idPrefix, accountID, n)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `
			INSERT INTO kaname.group_members (group_id, member_type, member_id)
			SELECT $1, 'user', $2 || lpad(i::text, 6, '0')
			  FROM generate_series(1, $3) AS i
			ON CONFLICT DO NOTHING`, group, idPrefix, n)
		require.NoError(t, err)
	}
	seedMembers(smallGroup, "usr-bnd-a-", smallSize)
	seedMembers(hugeGroup, "usr-bnd-b-", membersBoundLimit+50)

	rd, err := repoForSeed.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	members, incomplete, err := rd.Groups().MembersOfGroups(ctx,
		[]domain.GroupID{domain.GroupID(hugeGroup), domain.GroupID(smallGroup)})
	require.NoError(t, err)

	assert.LessOrEqual(t, len(members), membersBoundLimit,
		"состав, возвращаемый одним перечислением, обязан быть ограничен сверху: "+
			"страница ограничивает число ГРУПП, а не число ЧЛЕНОВ")
	assert.Equal(t, []domain.GroupID{domain.GroupID(hugeGroup)}, incomplete,
		"усечение обязано быть НАЗВАНО поимённо — иначе укороченный состав читается "+
			"как «в группе больше никого», а не как «дальше мы не читали»")

	// СТОИМОСТЬ чтения, а не только форма ответа. Форму держит срез в Go —
	// поэтому по длине ответа снятие предела выборки неотличимо от его наличия,
	// и утверждать надо то, что предел и держит: сколько строк оператор ПРОЧИТАЛ.
	read := rowsReadBy(t, ctx, pool, kanamepg.MembersOfGroupsSQL,
		[]string{smallGroup, hugeGroup}, kanamepg.MaxMembersInGrantSurface+1)
	assert.LessOrEqualf(t, read, float64(kanamepg.MaxMembersInGrantSurface+1),
		"оператор прочитал %.0f строк при пределе %d: без предела выборки он читает ВЕСЬ "+
			"состав названных групп, чтобы отдать первую тысячу — стоимость страницы "+
			"начинает принадлежать чужому членству", read, kanamepg.MaxMembersInGrantSurface)
	assert.Greaterf(t, read, float64(smallSize),
		"замер обязан быть предметным: прочитано %.0f строк — меньше, чем засеяно у одной "+
			"только малой группы, значит план снят не с того оператора", read)

	byGroup := map[string]int{}
	for _, m := range members {
		byGroup[string(m.GroupID)]++
	}
	assert.Equal(t, smallSize, byGroup[smallGroup],
		"положительный контроль: группа, чей состав умещается, возвращается ЦЕЛИКОМ "+
			"и неполной не объявляется")

	// Отрицание рядом: те же две группы поодиночке. Маленькая — полна и не
	// названа; большая — усечена и названа. Без этой пары «назвали неполной»
	// зеленело бы и на реализации, объявляющей неполными все группы подряд.
	for _, tc := range []struct {
		name       string
		group      string
		wantCap    bool
		wantMember int
	}{
		{"умещается целиком", smallGroup, false, smallSize},
		{"упирается в предел", hugeGroup, true, membersBoundLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, inc, err := rd.Groups().MembersOfGroups(ctx, []domain.GroupID{domain.GroupID(tc.group)})
			require.NoError(t, err)
			assert.Len(t, got, tc.wantMember)
			if tc.wantCap {
				assert.Equal(t, []domain.GroupID{domain.GroupID(tc.group)}, inc)
			} else {
				assert.Empty(t, inc, fmt.Sprintf("группа %s возвращена целиком — объявлять её неполной не о чем", tc.group))
			}
		})
	}
}
