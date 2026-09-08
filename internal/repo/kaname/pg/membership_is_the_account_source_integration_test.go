// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_is_the_account_source_integration_test.go — стадия S3 отрыва
// аккаунта от строки пользователя (IAM-ID-1, задача kacho#471): вопрос «в каких
// аккаунтах человек» отвечает ЧЛЕНСТВО, а не колонка `users.account_id`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ — ИСХОД, А НЕ ВЫЗОВ
//
// Читателей колонки, выражающих ИМЕННО ЧЛЕНСТВО, в дереве три, и они лежат в
// трёх разных слоях:
//
//	1. `ListAccountsForUser` — снимок «мои аккаунты» собственного профиля;
//	2. сужение набора кандидатов страницы `Users().List` — «кого мне показывать»;
//	3. звено цепи областей `iam_user → account` (представление
//	   `kaname.resource_scope_edge`) — «через какой аккаунт до личности
//	   достаёт администратор».
//
// Проба сеет состояние, в котором колонка и членства РАСХОДЯТСЯ — человек с
// колонкой `A` и вторым членством в `B`, — и требует, чтобы все три поверхности
// назвали ОБА аккаунта. Пока читают колонку, каждая называет один: проба красна
// по трём независимым утверждениям, а не по одному.
//
// Состояние конструируется вставкой строки членства напрямую, и это законно:
// глагол, заводящий второе членство, переезжает на ресурс членства следующим
// шагом стадии, а свойство читателей обязано быть верным ДО него — иначе
// переезд немедленно даст поверхность, которая о втором членстве не знает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ У КАЖДОГО УТВЕРЖДЕНИЯ СТОИТ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ
//
// «Человек виден через членство» зеленеет и на реализации, которая пропускает
// всех. Поэтому рядом с каждым включением стоит исключение: человек, чьего
// членства в спрашиваемом аккаунте нет, не назван ни одной из трёх
// поверхностей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЛОВУШКА, НАЗВАННАЯ ОТДЕЛЬНО: СОСТОЯНИЕ ЧЛЕНСТВА ≠ СОСТОЯНИЕ ЛИЧНОСТИ
//
// Зеркало S1 переводит состояние строки в состояние членства правилом
// «PENDING → PENDING, иначе ACTIVE» (470001), поэтому у ЗАБЛОКИРОВАННОГО
// человека членство остаётся `ACTIVE` — и это намеренно: блокировка есть
// свойство личности, а не членства (решение по вопросу В-8 приёмки).
//
// Следствие, которое легко упустить: читатель, сегодня отбирающий по
// `users.invite_status = 'ACTIVE'`, а завтра по `memberships.state = 'ACTIVE'`,
// НАЧИНАЕТ ВИДЕТЬ ЗАБЛОКИРОВАННЫХ. Это расширение видимости, а не перенос
// источника. Проба требует, чтобы состояние личности продолжало отсекать:
// заблокированный аккаунтов не называет, разблокированный — называет снова.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// seedMembership кладёт строку членства НАПРЯМУЮ — тем же выражением
// идентификатора, каким её кладут бэкфилл и зеркало (470001), чтобы повторная
// вставка той же пары не заводила второй строки.
func seedMembership(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID, accountID domain.AccountID, state string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.memberships (id, user_id, account_id, state)
		VALUES (kaname.membership_mirror_id($1, $2), $1, $2, $3)
		ON CONFLICT (user_id, account_id) DO UPDATE SET state = EXCLUDED.state`,
		string(userID), string(accountID), state)
	require.NoError(t, err, "сев членства (%s → %s)", userID, accountID)
}

// scopeParents — аккаунты, которые цепь областей называет предками личности.
func scopeParents(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT parent_id FROM kaname.resource_scope_edge
		 WHERE object_type = 'iam_user' AND object_id = $1 AND parent_type = 'account'
		 ORDER BY parent_id`, string(userID))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// listCandidates — идентификаторы страницы, отобранной сужением по названным
// аккаунтам. Именно СОСТАВ страницы, а не факт вызова сужения.
func listCandidates(t *testing.T, ctx context.Context, repo *kanamepg.Repository, accounts ...domain.AccountID) []string {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		ids = append(ids, string(a))
	}
	rows, _, err := rd.Users().List(ctx, repouser.ListFilter{
		PageSize:   100,
		Candidates: &visibility.PageScope{AccountIDs: ids, ObjectIDs: []string{}},
	})
	require.NoError(t, err)
	out := make([]string, 0, len(rows))
	for _, u := range rows {
		out = append(out, string(u.ID))
	}
	return out
}

func accountIDStrings(in []domain.AccountID) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, string(a))
	}
	return out
}

// TestMembershipIsTheAccountSource — три поверхности читают членство.
func TestMembershipIsTheAccountSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	// Два аккаунта со своими владельцами. Второй нужен целиком: членство ведёт
	// внешним ключом на строку аккаунта, и выдуманный идентификатор её не имел бы.
	_, accA := bootstrapAdmin(t, ctx, repo, "msA")
	_, accB := bootstrapAdmin(t, ctx, repo, "msB")

	// Человек, чья колонка называет A. Зеркало S1 заведёт ему членство в A.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	twoAccounts := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           twoAccounts,
		AccountID:    accA,
		ExternalID:   domain.ExternalSubject("ext-ms-two-" + string(twoAccounts)),
		Email:        domain.Email("two-accounts@example.com"),
		DisplayName:  domain.DisplayName("Two Accounts"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err)
	// Человек, состоящий ТОЛЬКО в A — отрицательный контроль каждой поверхности.
	onlyA := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           onlyA,
		AccountID:    accA,
		ExternalID:   domain.ExternalSubject("ext-ms-only-" + string(onlyA)),
		Email:        domain.Email("only-a@example.com"),
		DisplayName:  domain.DisplayName("Only A"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// РАСХОЖДЕНИЕ, ради которого написана проба: второе членство, которого нет
	// в колонке.
	seedMembership(t, ctx, pool, twoAccounts, accB, "ACTIVE")

	// Перепись предусловия: «ноль находок» обязано быть отличимо от «ноль
	// прочитанного» (testing.md §«Гейт на класс» п. 3).
	var seenUsers, seenMemberships int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.users`).Scan(&seenUsers))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.memberships`).Scan(&seenMemberships))
	require.Greater(t, seenUsers, 0, "осмотренных строк ноль — проба не о том дереве")
	require.Equal(t, seenUsers+1, seenMemberships,
		"членств обязано быть на одно больше строк: зеркало плюс второе, посеянное пробой")
	t.Logf("перепись: строк пользователей %d, членств %d", seenUsers, seenMemberships)

	// ── Поверхность 1: снимок «мои аккаунты» собственного профиля ──────────
	t.Run("снимок аккаунтов называет оба членства", func(t *testing.T) {
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()

		got, err := rd.Users().ListAccountsForUser(ctx, twoAccounts)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{string(accA), string(accB)}, accountIDStrings(got),
			"снимок читает колонку, а не членства: назван только один аккаунт")

		// Положительный контроль: у человека с одним членством назван ровно один.
		gotOne, err := rd.Users().ListAccountsForUser(ctx, onlyA)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{string(accA)}, accountIDStrings(gotOne),
			"человек с одним членством обязан называть ровно один аккаунт")
	})

	// ── Поверхность 2: состав страницы списка пользователей ────────────────
	t.Run("страница списка отбирается членствами", func(t *testing.T) {
		inB := listCandidates(t, ctx, repo, accB)
		require.Contains(t, inB, string(twoAccounts),
			"сужение читает колонку: человек с членством в B в страницу B не попал")
		require.NotContains(t, inB, string(onlyA),
			"положительный контроль: человек без членства в B в страницу B попасть не может")

		inA := listCandidates(t, ctx, repo, accA)
		require.Contains(t, inA, string(twoAccounts))
		require.Contains(t, inA, string(onlyA))
	})

	// ── Поверхность 3: звено цепи областей ────────────────────────────────
	t.Run("цепь областей называет оба аккаунта", func(t *testing.T) {
		parents := scopeParents(t, ctx, pool, twoAccounts)
		require.ElementsMatch(t, []string{string(accA), string(accB)}, parents,
			"звено цепи выведено из колонки: администратор B до личности не достаёт")

		onlyParents := scopeParents(t, ctx, pool, onlyA)
		require.ElementsMatch(t, []string{string(accA)}, onlyParents,
			"положительный контроль: у человека с одним членством звено ровно одно")
	})
}

// TestBlockedIdentityGainsNoAccountThroughMembership — состояние ЛИЧНОСТИ
// продолжает отсекать, хотя состояние членства этого не делает.
//
// Зеркало S1 переводит BLOCKED в членство `ACTIVE` намеренно (блокировка —
// свойство личности). Читатель, перешедший на членство и потерявший проверку
// состояния личности, начал бы называть аккаунты заблокированному — то есть
// расширил бы видимость под видом переноса источника.
func TestBlockedIdentityGainsNoAccountThroughMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	_, accA := bootstrapAdmin(t, ctx, repo, "blkA")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	blocked := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           blocked,
		AccountID:    accA,
		ExternalID:   domain.ExternalSubject("ext-blk-" + string(blocked)),
		Email:        domain.Email("blocked@example.com"),
		DisplayName:  domain.DisplayName("Blocked"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	read := func() []string {
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		got, err := rd.Users().ListAccountsForUser(ctx, blocked)
		require.NoError(t, err)
		return accountIDStrings(got)
	}

	// Положительный контроль ДО отрицания: пока личность активна, аккаунт назван.
	require.Contains(t, read(), string(accA), "активная личность обязана называть свой аккаунт")

	_, err = pool.Exec(ctx, `UPDATE kaname.users SET invite_status = 'BLOCKED' WHERE id = $1`, string(blocked))
	require.NoError(t, err)

	// Членство при этом ОСТАЛОСЬ активным — иначе проба измеряла бы не то.
	var state string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT state FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(blocked), string(accA)).Scan(&state))
	require.Equal(t, "ACTIVE", state,
		"зеркало обязано оставить членство активным: блокировка — свойство личности (В-8)")

	require.NotContains(t, read(), string(accA),
		"заблокированная личность получила аккаунт через членство — видимость расширена")
}

// TestScopeEdgeReadsNoUserAccountColumn — цепь областей больше не называет
// колонку принадлежности в своём определении.
//
// Утверждение о ТЕКСТЕ представления, а не о его исходе, и потому стоит рядом с
// пробами исхода, а не вместо них: исход при одном членстве одинаков у обоих
// источников by construction (зеркало S1), поэтому по исходу источник не
// различить, а снятие колонки на S4 обязано не иметь читателя ЗАРАНЕЕ.
func TestScopeEdgeReadsNoUserAccountColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var def string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT pg_get_viewdef('kaname.resource_scope_edge'::regclass, true)`).Scan(&def))
	require.NotEmpty(t, def, "определение представления пусто — проба не о том дереве")

	// Контроль в обратную сторону: представление ЧИТАЕТ таблицу членств. Без
	// него отрицание ниже зеленело бы и на представлении, потерявшем ветвь
	// личности целиком.
	require.True(t, strings.Contains(def, "memberships"),
		"цепь областей обязана читать членства — иначе у личности нет звена вовсе")

	// Ветвь личности не должна брать аккаунт из строки пользователя.
	for _, line := range strings.Split(def, "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "u.account_id") || strings.Contains(low, "users o") {
			t.Fatalf("цепь областей всё ещё выводит звено личности из колонки: %s", strings.TrimSpace(line))
		}
	}
	t.Logf("осмотрено строк определения представления: %d", len(strings.Split(def, "\n")))
}
