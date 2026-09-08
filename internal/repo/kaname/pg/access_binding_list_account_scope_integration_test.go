// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_list_account_scope_integration_test.go — SQL-сторона поля
// `ListFilter.AccountID` (задача #1737, приёмка
// services/iam/docs/engineering/acceptance/subject-grants-within-an-account.md).
//
// Что здесь утверждается и чего НЕ видит проба уровня use-case: настоящий
// предикат по настоящей таблице `projects` — то есть что фан-аут «аккаунт ⇒ его
// проекты» действительно ходит в базу, а не воспроизведён дублёром.
//
// Покрытие:
//   - IAM-AB-SIA-01: охват = сам аккаунт ПЛЮС каждый его проект; чужой аккаунт
//     не попадает (третья строка в фикстуре стоит именно за этим — без неё
//     «чужого нет» верно by construction);
//   - IAM-AB-SIA-02: композиция с предикатом субъекта;
//   - IAM-AB-SIA-03: композиция с include_revoked, обе стороны;
//   - IAM-AB-SIA-05: состав ответа СОВПАДАЕТ с ListByAccount при том же охвате.
//     Сверка ПО СОСТАВУ, не по индексу: порядок у глаголов разный намеренно
//     (List — created_at ASC, ListByAccount — created_at DESC).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func abIDsOf(rows []domain.AccessBinding) []string {
	out := make([]string, 0, len(rows))
	for _, b := range rows {
		out = append(out, string(b.ID))
	}
	return out
}

func TestAB_SIA_ListNarrowedToAccountScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: `defer pool.Close()` ждёт возврата ВСЕХ соединений, и
	// проба, упавшая внутри открытой транзакции, соединение не вернёт — пакет
	// упирается в -timeout и печатает FAIL, то есть «не выполнилось» приходит
	// под видом красного.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sia01o")
	subject := mustSeedUser(t, ctx, pool, "sia01s")
	other := mustSeedUser(t, ctx, pool, "sia01x")

	home := seedAccount(t, ctx, repo, "acc-sia-home", owner)
	foreign := seedAccount(t, ctx, repo, "acc-sia-frgn", owner)
	homeProj := seedProject(t, ctx, repo, home.ID, "proj-sia-home")

	// (1) субъект на самом аккаунте
	onAccount := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(home.ID),
	})
	// (2) он же на ПРОЕКТЕ этого аккаунта — фан-аут обязан его достать
	onProject := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "project", ResourceID: string(homeProj.ID),
	})
	// (3) он же в ЧУЖОМ аккаунте — сужение обязано его убрать. Без этой строки
	// утверждение «ничего вне аккаунта» зеленело бы на реализации, выбросившей поле.
	onForeign := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(foreign.ID),
	})
	// (4) ДРУГОЙ субъект в том же аккаунте — для проверки конъюнкции
	onAccountOther := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(other),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(home.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// IAM-AB-SIA-01 — охват: аккаунт плюс его проекты, и ничего вне.
	rows, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{
		PageSize: 100, AccountID: string(home.ID),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{string(onAccount.ID), string(onProject.ID), string(onAccountOther.ID)},
		abIDsOf(rows),
		"фан-аут обязан достать и привязку аккаунта, и привязку его проекта")
	assert.NotContains(t, abIDsOf(rows), string(onForeign.ID),
		"привязка чужого аккаунта в ответе появиться не может")

	// Положительный контроль обратной совместимости (IAM-AB-SIA-04): без поля
	// чужая строка видна. Без него утверждение выше зеленело бы на реализации,
	// которая не отдаёт ничего.
	all, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{
		PageSize: 100, SubjectID: string(subject),
	})
	require.NoError(t, err)
	assert.Contains(t, abIDsOf(all), string(onForeign.ID),
		"без поля выдача в чужом аккаунте остаётся видна — поведение до изменения")

	// IAM-AB-SIA-02 — композиция с предикатом субъекта.
	rows, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{
		PageSize: 100, AccountID: string(home.ID), SubjectID: string(subject),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{string(onAccount.ID), string(onProject.ID)}, abIDsOf(rows),
		"предикаты конъюнктивны: чужой субъект того же аккаунта не проходит")

	// IAM-AB-SIA-05 — состав совпадает с ListByAccount при том же охвате.
	byAccount, _, err := rd.AccessBindings().ListByAccount(ctx, home.ID,
		repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err)
	unified, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{
		PageSize: 100, AccountID: string(home.ID),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, abIDsOf(byAccount), abIDsOf(unified),
		"тот же охват: сверка ПО СОСТАВУ — порядок у глаголов разный намеренно")
	require.NotEmpty(t, byAccount,
		"сверка составов на пустом множестве ничего не утверждает")
}

// IAM-AB-SIA-03 — поле композируется с include_revoked, и утверждается ПАРА:
// с флагом видны обе строки, без флага — только живая. Одно «обе видны»
// зеленело бы на реализации, не скрывающей отозванные никогда.
func TestAB_SIA03_AccountScopeComposesWithIncludeRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: `defer pool.Close()` ждёт возврата ВСЕХ соединений, и
	// проба, упавшая внутри открытой транзакции, соединение не вернёт — пакет
	// упирается в -timeout и печатает FAIL, то есть «не выполнилось» приходит
	// под видом красного.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sia03o")
	subject := mustSeedUser(t, ctx, pool, "sia03s")
	acc := seedAccount(t, ctx, repo, "acc-sia03", owner)

	live := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(acc.ID),
	})
	// Отозванная строка вставляется напрямую: частичный UNIQUE не пропустит
	// второй живой пятёрки того же состава.
	revokedID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.access_bindings
		(id, subject_type, subject_id, role_id, resource_type, resource_id, status,
		 granted_by_user_id, revoked_at, revoked_by_user_id, created_at)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'REVOKED', '', now(), $5, now())`,
		revokedID, string(subject), seedSystemRoleIDIAMAdmin, string(acc.ID), string(owner))
	require.NoError(t, err)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	withRevoked, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{
		PageSize: 100, AccountID: string(acc.ID), IncludeRevoked: true,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{string(live.ID), revokedID}, abIDsOf(withRevoked),
		"с флагом сужение по аккаунту отдаёт и отозванную строку")

	withoutRevoked, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{
		PageSize: 100, AccountID: string(acc.ID),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{string(live.ID)}, abIDsOf(withoutRevoked),
		"без флага отозванная строка скрыта — умолчание не меняется полем")
}
