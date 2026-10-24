// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_second_subject_reads_integration_test.go — чтения по субъекту
// выдачи находят выдачу, где этот субъект стоит НЕ первым (kaname#888, остаток
// класса kaname#880).
//
// Выдача несёт субъектов в двух проекциях: одиночная пара строки
// `access_bindings` (subject_type, subject_id) — это ПЕРВЫЙ субъект, и набор
// `access_binding_subjects` — каждый. Чтение, спрашивающее только пару, видит
// одного первого: второму выдача не показана, хотя права по ней у него есть.
//
// Одна посадка на все пробы; у каждой пробы — законный близнец (первый субъект
// той же выдачи находится и до правки, значит красное не от посадки) и
// отрицательный (посторонний выдачу не видит, значит правка не расширила ответ).

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// secondSubjectFixture — посадка:
//
//	multi:     [owner, second, team]  на аккаунт acc — второй и третий субъекты не первые;
//	groupPair: [other, team]          на аккаунт acc — группа, где член НЕ состоит, стоит первой,
//	                                  группа, где состоит, — второй;
//
// member состоит в team и не состоит в other; outsider не назван нигде.
type secondSubjectFixture struct {
	repo      *kanamepg.Repository
	acc       domain.Account
	owner     domain.UserID
	second    domain.UserID
	member    domain.UserID
	outsider  domain.UserID
	team      domain.Group
	other     domain.Group
	multi     domain.AccessBinding
	groupPair domain.AccessBinding
}

func seedSecondSubjectFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) secondSubjectFixture {
	t.Helper()
	repo := kanamepg.New(pool, nil)
	f := secondSubjectFixture{repo: repo}

	f.owner = mustSeedUser(t, ctx, pool, "ss2o")
	f.acc = seedAccount(t, ctx, repo, "acc-ss2", f.owner)
	// Второй субъект — человек СО СВОИМ аккаунтом и без членства в acc: иначе
	// аккаунт acc пришёл бы ему через членство, и проба ListAccountsForUser
	// зеленела бы не той ветвью.
	f.second = mustSeedUser(t, ctx, pool, "ss2s")
	f.member = seedUserInAccount(t, ctx, pool, f.acc.ID, "ss2m")
	f.outsider = mustSeedUser(t, ctx, pool, "ss2x")
	f.team = seedGroup(t, ctx, repo, f.acc.ID, "ss2-team")
	f.other = seedGroup(t, ctx, repo, f.acc.ID, "ss2-other")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID: f.team.ID, MemberType: "user", MemberID: domain.SubjectID(f.member),
	}))
	require.NoError(t, w.Commit(ctx))

	roleMulti := seedCustomRole(t, ctx, repo, f.acc.ID, "ss2_multi")
	roleGroups := seedCustomRole(t, ctx, repo, f.acc.ID, "ss2_groups")

	f.multi = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(f.owner),
		RoleID: roleMulti.ID, ResourceType: "account", ResourceID: string(f.acc.ID),
		GrantedByUserID: f.owner,
	})
	insertSubjects(t, ctx, repo, f.multi.ID, []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.owner)},
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.second)},
		{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(f.team.ID)},
	})

	f.groupPair = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(f.other.ID),
		RoleID: roleGroups.ID, ResourceType: "account", ResourceID: string(f.acc.ID),
		GrantedByUserID: f.owner,
	})
	insertSubjects(t, ctx, repo, f.groupPair.ID, []domain.Subject{
		{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(f.other.ID)},
		{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(f.team.ID)},
	})
	return f
}

func openSecondSubjectFixture(t *testing.T) (context.Context, secondSubjectFixture, func() kaname.Reader) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	f := seedSecondSubjectFixture(t, ctx, pool)
	reader := func() kaname.Reader {
		rd, err := f.repo.Reader(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = rd.Rollback(ctx) })
		return rd
	}
	return ctx, f, reader
}

func secondSubjectIDs(bs []domain.AccessBinding) []domain.AccessBindingID {
	out := make([]domain.AccessBindingID, 0, len(bs))
	for _, b := range bs {
		out = append(out, b.ID)
	}
	return out
}

func TestSecondSubject_ListBySubjectFindsTheBinding(t *testing.T) {
	ctx, f, reader := openSecondSubjectFixture(t)
	rd := reader()
	page := repoab.PageFilter{PageSize: 100}

	first, _, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeUser, domain.SubjectID(f.owner), page)
	require.NoError(t, err)
	require.Contains(t, secondSubjectIDs(first), f.multi.ID, "близнец: первый субъект выдачи находится")

	got, _, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeUser, domain.SubjectID(f.second), page)
	require.NoError(t, err)
	assert.Equal(t, []domain.AccessBindingID{f.multi.ID}, secondSubjectIDs(got),
		"выдача, где человек стоит вторым, обязана найтись — и ровно одной строкой")

	grp, _, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeGroup, domain.SubjectID(f.team.ID), page)
	require.NoError(t, err)
	assert.ElementsMatch(t, []domain.AccessBindingID{f.multi.ID, f.groupPair.ID}, secondSubjectIDs(grp),
		"группа, стоящая третьей и второй, обязана найти обе выдачи")

	none, _, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeUser, domain.SubjectID(f.outsider), page)
	require.NoError(t, err)
	assert.Empty(t, none, "посторонний не назван ни в одной выдаче")
}

func TestSecondSubject_ListSubjectFilterFindsTheBinding(t *testing.T) {
	ctx, f, reader := openSecondSubjectFixture(t)
	rd := reader()

	first, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{SubjectID: string(f.owner), PageSize: 100})
	require.NoError(t, err)
	require.Contains(t, secondSubjectIDs(first), f.multi.ID, "близнец: фильтр по первому субъекту находит выдачу")

	got, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{SubjectID: string(f.second), PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, []domain.AccessBindingID{f.multi.ID}, secondSubjectIDs(got),
		"фильтр subject по второму субъекту обязан найти выдачу ровно одной строкой")

	none, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{SubjectID: string(f.outsider), PageSize: 100})
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestSecondSubject_ListByAccountSubjectTypeFilterFindsTheBinding(t *testing.T) {
	ctx, f, reader := openSecondSubjectFixture(t)
	rd := reader()

	users, _, err := rd.AccessBindings().ListByAccount(ctx, f.acc.ID, repoab.AccountPageFilter{SubjectTypeFilter: string(domain.SubjectTypeUser), PageSize: 100})
	require.NoError(t, err)
	require.Contains(t, secondSubjectIDs(users), f.multi.ID, "близнец: вид первого субъекта находит выдачу")
	assert.NotContains(t, secondSubjectIDs(users), f.groupPair.ID, "в выдаче из двух групп нет ни одного человека")

	groups, _, err := rd.AccessBindings().ListByAccount(ctx, f.acc.ID, repoab.AccountPageFilter{SubjectTypeFilter: string(domain.SubjectTypeGroup), PageSize: 100})
	require.NoError(t, err)
	assert.ElementsMatch(t, []domain.AccessBindingID{f.multi.ID, f.groupPair.ID}, secondSubjectIDs(groups),
		"выдача человеку и группе обязана найтись по виду group, хотя группа в ней не первая")

	sas, _, err := rd.AccessBindings().ListByAccount(ctx, f.acc.ID, repoab.AccountPageFilter{SubjectTypeFilter: string(domain.SubjectTypeServiceAccount), PageSize: 100})
	require.NoError(t, err)
	assert.NotContains(t, secondSubjectIDs(sas), f.multi.ID, "сервисного аккаунта в выдаче нет")
}

func TestSecondSubject_ListSubjectPrivilegesFindsTheBinding(t *testing.T) {
	ctx, f, reader := openSecondSubjectFixture(t)
	rd := reader()
	page := repoab.PageFilter{PageSize: 100}
	byID := func(rows []domain.SubjectPrivilege) map[domain.AccessBindingID]domain.SubjectPrivilege {
		m := map[domain.AccessBindingID]domain.SubjectPrivilege{}
		for _, r := range rows {
			_, dup := m[r.BindingID]
			require.False(t, dup, "одна строка на выдачу: %s повторена", r.BindingID)
			m[r.BindingID] = r
		}
		return m
	}

	ownerRows, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx, domain.SubjectTypeUser, domain.SubjectID(f.owner), page)
	require.NoError(t, err)
	ownerPriv, ok := byID(ownerRows)[f.multi.ID]
	require.True(t, ok, "близнец: первый субъект видит свою выдачу")
	require.Equal(t, domain.DerivationDirect, ownerPriv.Derivation)

	// Точка 1 — ПРЯМАЯ ветвь: человек назван выдачей вторым.
	secondRows, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx, domain.SubjectTypeUser, domain.SubjectID(f.second), page)
	require.NoError(t, err)
	secondPriv, ok := byID(secondRows)[f.multi.ID]
	if assert.True(t, ok, "прямая ветвь: выдача, где человек стоит вторым, обязана найтись") {
		assert.Equal(t, domain.DerivationDirect, secondPriv.Derivation, "человек назван выдачей сам — DIRECT")
		assert.Empty(t, secondPriv.ViaGroupID)
	}
	assert.Len(t, secondRows, 1)

	// Точка 2 — ГРУППОВАЯ ветвь: группа члена названа выдачей не первой.
	memberRows, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx, domain.SubjectTypeUser, domain.SubjectID(f.member), page)
	require.NoError(t, err)
	m := byID(memberRows)
	for _, b := range []domain.AccessBinding{f.multi, f.groupPair} {
		p, ok := m[b.ID]
		if assert.True(t, ok, "групповая ветвь: выдача %s группе члена, стоящей не первой, обязана найтись", b.ID) {
			assert.Equal(t, domain.DerivationGroup, p.Derivation)
			// Первой в groupPair стоит группа, где член НЕ состоит: назвать её
			// значило бы отправить администратора снимать не то членство.
			assert.Equal(t, f.team.ID, p.ViaGroupID, "несущая группа — та, где член состоит")
		}
	}
	assert.Len(t, memberRows, 2)

	none, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx, domain.SubjectTypeUser, domain.SubjectID(f.outsider), page)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestSecondSubject_ListAccountsForUserFindsTheAccount(t *testing.T) {
	ctx, f, reader := openSecondSubjectFixture(t)
	rd := reader()

	ownerAccs, err := rd.Users().ListAccountsForUser(ctx, f.owner)
	require.NoError(t, err)
	require.Contains(t, ownerAccs, f.acc.ID, "близнец: первый субъект (и владелец) видит аккаунт")

	got, err := rd.Users().ListAccountsForUser(ctx, f.second)
	require.NoError(t, err)
	assert.Contains(t, got, f.acc.ID, "аккаунт выдачи, где человек стоит вторым, обязан прийти через выдачу")

	none, err := rd.Users().ListAccountsForUser(ctx, f.outsider)
	require.NoError(t, err)
	assert.NotContains(t, none, f.acc.ID)
}
