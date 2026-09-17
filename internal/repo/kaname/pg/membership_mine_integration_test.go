// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_mine_integration_test.go — СВОЙ список членств (IAM-ID-2, стадия
// S2; сценарии IAM-ID-2-07, -11 и индекс под курсор из §7 п. 7в).
//
// Предмет проб — СУЖЕНИЕ ОТБОРА ПО ЧЕЛОВЕКУ: человек стоит в условии запроса, а
// не в проверке после чтения. У каждого отрицания стоит положительный контроль,
// и оба утверждаются на ОДНИХ данных: рядом с человеком живёт сосед с членствами
// в тех же аккаунтах — иначе «чужих строк не выбрал» доказывалось бы их
// отсутствием, а не сужением.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// homeMembershipOf — членство, которое посев человека (`mustSeedUser`) заводит
// ЗЕРКАЛОМ строки: у человека есть аккаунт заведения, и триггер схемы кладёт
// членство в нём. Свой список обязан его показать — это тоже «где числюсь».
func homeMembershipOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID) (domain.AccountID, domain.MembershipID) {
	t.Helper()
	var acc, id string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT m.account_id, m.id FROM memberships m JOIN users u ON u.id = m.user_id
		 WHERE m.user_id = $1 AND m.account_id = u.account_id`, string(userID)).Scan(&acc, &id))
	return domain.AccountID(acc), domain.MembershipID(id)
}

// seedAccountWithFreshOwner — аккаунт под СВОИМ владельцем: темп заведения
// аккаунтов одной личностью ограничен схемой (три за час), и семь аккаунтов
// одним владельцем упёрлись бы в него — что верно для продукта и не по делу
// для пробы чтения.
func seedAccountWithFreshOwner(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kanamepg.Repository, name string) domain.Account {
	t.Helper()
	return seedAccount(t, ctx, repo, name, mustSeedUser(t, ctx, pool, name+"own"))
}

// TestMembership_IAMID2_07_MineIsCompleteAcrossAccountsIncludingInvited — свой
// список полон: все аккаунты, где человек числится, включая тот, куда его
// позвали; след приглашения различает случаи, а не отдаёт константу.
func TestMembership_IAMID2_07_MineIsCompleteAcrossAccountsIncludingInvited(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mbr07own")
	person := mustSeedUser(t, ctx, pool, "mbr07per")
	neighbour := mustSeedUser(t, ctx, pool, "mbr07nbr")
	home, homeID := homeMembershipOf(t, ctx, pool, person)
	accA := seedAccount(t, ctx, repo, "mbr07-a", owner)
	accB := seedAccount(t, ctx, repo, "mbr07-b", owner)
	accC := seedAccountWithFreshOwner(t, ctx, pool, repo, "mbr07-c")

	base := time.Now().UTC().Truncate(time.Second)
	idA := seedMembershipRow(t, ctx, pool, person, accA.ID, domain.MembershipStateActive, "", base)
	idB := seedMembershipRow(t, ctx, pool, person, accB.ID, domain.MembershipStateActive, "", base.Add(time.Second))
	idC := seedMembershipRow(t, ctx, pool, person, accC.ID, domain.MembershipStateActive, owner, base.Add(2*time.Second))
	// Сосед состоит в ТЕХ ЖЕ аккаунтах: его строки обязаны не попасть в чужой
	// свой список.
	seedMembershipRow(t, ctx, pool, neighbour, accA.ID, domain.MembershipStateActive, owner, base)
	seedMembershipRow(t, ctx, pool, neighbour, accC.ID, domain.MembershipStateActive, owner, base)

	rd, done := membershipReaderOn(t, ctx, repo)
	defer done()

	rows, next, err := rd.ListMine(ctx, person, repomembership.MinePage{})
	require.NoError(t, err)
	require.Empty(t, next)
	require.Len(t, rows, 4, "перечень содержит РОВНО четыре записи: аккаунт заведения, A, B "+
		"и C — аккаунт, куда позвали, из перечня не выпадает")

	byAccount := map[domain.AccountID]domain.Membership{}
	got := map[domain.AccountID]bool{}
	for _, m := range rows {
		require.Equal(t, person, m.UserID, "в свой список попала строка соседа")
		require.NotEmpty(t, m.State, "state заполнен у КАЖДОЙ записи: проекции не расходятся")
		byAccount[m.AccountID] = m
		got[m.AccountID] = true
	}
	// Состав сверяется по МНОЖЕСТВУ аккаунтов, а не по индексам: порядок объявлен
	// незначимым.
	require.Equal(t, map[domain.AccountID]bool{home: true, accA.ID: true, accB.ID: true, accC.ID: true}, got)
	require.Equal(t, homeID, byAccount[home].ID)
	require.Equal(t, idA, byAccount[accA.ID].ID)
	require.Equal(t, idB, byAccount[accB.ID].ID)
	require.Equal(t, idC, byAccount[accC.ID].ID)

	// След приглашения: у `C` непуст и называет пригласившего; ПОЛОЖИТЕЛЬНЫЙ
	// контроль — у `A`, заведённой не приглашением, пуст.
	require.Equal(t, owner, byAccount[accC.ID].InvitedBy, "«куда позвали» читается по следу приглашения")
	require.Equal(t, accC.ID, byAccount[accC.ID].AccountID)
	require.Equal(t, base.Add(2*time.Second), byAccount[accC.ID].CreatedAt.UTC(), "createdAt — момент выписки приглашения")
	require.Empty(t, byAccount[accA.ID].InvitedBy, "поле различает два случая, а не отдаёт константу")

	// Имя аккаунта — зеркало, и у аккаунта с заданным именем оно НЕПУСТО.
	require.Equal(t, domain.AccountName("mbr07-c"), byAccount[accC.ID].AccountName)
}

// TestMembership_IAMID2_11_MineCursorNeitherSkipsNorDuplicates — курсор своего
// списка обходит страницу за страницей, ни одной строки не теряя и ни одной не
// повторяя; шум соседа обходу невидим.
func TestMembership_IAMID2_11_MineCursorNeitherSkipsNorDuplicates(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	person := mustSeedUser(t, ctx, pool, "mbr11per")
	neighbour := mustSeedUser(t, ctx, pool, "mbr11nbr")
	_, homeID := homeMembershipOf(t, ctx, pool, person)

	base := time.Now().UTC().Truncate(time.Second)
	want := map[domain.MembershipID]bool{homeID: true}
	const seeded = 7
	total := seeded + 1 // плюс членство в аккаунте заведения
	for i := 0; i < seeded; i++ {
		acc := seedAccountWithFreshOwner(t, ctx, pool, repo, fmt.Sprintf("mbr11-%d", i))
		// Одна и та же секунда у нескольких строк — курсор обязан разрешать
		// спор идентификатором, а не терять строки с равным created_at.
		at := base.Add(time.Duration(i/2) * time.Second)
		want[seedMembershipRow(t, ctx, pool, person, acc.ID, domain.MembershipStateActive, "", at)] = true
		seedMembershipRow(t, ctx, pool, neighbour, acc.ID, domain.MembershipStateActive, "", at)
	}

	rd, done := membershipReaderOn(t, ctx, repo)
	defer done()

	seen := map[domain.MembershipID]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 20, "обход не сходится — токен не продвигается")
		rows, next, err := rd.ListMine(ctx, person, repomembership.MinePage{PageSize: 3, PageToken: token})
		require.NoError(t, err)
		for _, m := range rows {
			seen[m.ID]++
			require.Equal(t, person, m.UserID, "в страницу попала строка соседа")
		}
		if next == "" {
			break
		}
		token = next
	}
	require.Len(t, seen, total, "обход потерял либо добрал строки")
	for id := range want {
		require.Equal(t, 1, seen[id], "строка %s встретилась не ровно один раз", id)
	}

	// Положительный контроль токена: страница из одной строки отдаёт непустой
	// токен, и по нему приходит СЛЕДУЮЩАЯ строка.
	first, next, err := rd.ListMine(ctx, person, repomembership.MinePage{PageSize: 1})
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.NotEmpty(t, next)
	second, _, err := rd.ListMine(ctx, person, repomembership.MinePage{PageSize: 1, PageToken: next})
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.NotEqual(t, first[0].ID, second[0].ID)
}

// TestMembership_MineRejectsBadFormAndEmptySubject — размер страницы вне
// предела и негодный токен отвергаются, а не подрезаются; пустой человек до
// запроса не доходит: он означал бы «любой», то есть межаккаунтный перечень.
func TestMembership_MineRejectsBadFormAndEmptySubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mbrmfown")
	accA := seedAccount(t, ctx, repo, "mbrmf-a", owner)
	seedMembershipRow(t, ctx, pool, owner, accA.ID, domain.MembershipStateActive, "", time.Now().UTC())

	rd, done := membershipReaderOn(t, ctx, repo)
	defer done()

	_, _, err = rd.ListMine(ctx, owner, repomembership.MinePage{PageSize: 5000})
	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "размер страницы вне [0..1000] отвергается: %v", err)

	_, _, err = rd.ListMine(ctx, owner, repomembership.MinePage{PageToken: "не-курсор"})
	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "негодный токен отвергается: %v", err)

	_, _, err = rd.ListMine(ctx, "", repomembership.MinePage{})
	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "пустой человек не доходит до запроса: %v", err)

	// ПОЛОЖИТЕЛЬНЫЙ контроль: законная форма отвечает страницей — аккаунт
	// заведения (зеркало посева) и `A`.
	rows, _, err := rd.ListMine(ctx, owner, repomembership.MinePage{PageSize: 10})
	require.NoError(t, err)
	require.Len(t, rows, 2)
}

// TestMembership_MineCursorIsServedByItsOwnIndex — порядок обхода своего
// списка `(user_id, created_at, id)` объявлен индексом схемы (§7 п. 7в):
// ведущее равенство по человеку, за ним ключи курсора подряд.
func TestMembership_MineCursorIsServedByItsOwnIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var def string
	err = pool.QueryRow(ctx, `
		SELECT indexdef FROM pg_indexes
		 WHERE schemaname = 'kaname' AND tablename = 'memberships'
		   AND indexname = 'memberships_user_cursor_idx'`).Scan(&def)
	require.NoError(t, err, "индекс под курсор своего списка объявлен схемой")
	require.Contains(t, def, "(user_id, created_at, id)")
}
