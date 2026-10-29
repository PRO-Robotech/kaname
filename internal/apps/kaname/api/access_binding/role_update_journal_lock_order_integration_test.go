// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_update_journal_lock_order_integration_test.go — две встречные смены ролей,
// чьи выдачи стоят на одних объектах одного субъекта, не встают в тупик на строках
// прямого факта (kaname#617, SD-942-617-1).
//
// ПРЕДМЕТ. Смена роли сверяет кортежи уровня выдачи каждой действующей выдачи роли
// (RoleTupleReconciler) в транзакции правки роли. Строки журнала складывает в
// прямой факт операторный триггер: внутри ОДНОГО оператора он берёт замки строк
// факта в общем порядке (объект, субъект). Сверка писала журнал оператором на
// каждую выдачу веера — снятия, затем выдачи, — то есть порядком выдач роли.
// Роль R1 с выдачами на проекты [Pa, Pb] брала факты Pa раньше Pb; роль R2 с
// выдачами [Pb, Pa] — Pb раньше Pa. Две смены, идущие разом, брали одни строки
// встречно, и база снимала одну из транзакций отказом 40P01.
//
// КАК ГОНКА СДЕЛАНА ДЕТЕРМИНИРОВАННОЙ. Держатель берёт строку факта `viewer` на Pa
// (меньший идентификатор). Смена R1 стартует первой и встаёт за держателем на
// первой строке Pa. Смена R2 стартует второй: в мире «встречно» она успевает
// взять факты Pb и встаёт за держателем (либо за R1) на Pa; в мире «одинаково» её
// первая строка — Pa, и она встаёт, ничего не взяв. Держатель отпускает строку —
// дальше исход определён порядком внутри смен, а не случаем.
//
// Близнец меняет РОВНО ОДИН факт — порядок выдач роли R2 (какой проект она
// назначила первым); роли, субъект, проекты, ярусы, держатель — те же.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// TestRoleUpdatesOfOneSubjectCommitWhenTheirFanoutsMeetCrosswise — R1 сверяет
// выдачи [Pa, Pb], R2 — [Pb, Pa]: обе смены коммитятся.
func TestRoleUpdatesOfOneSubjectCommitWhenTheirFanoutsMeetCrosswise(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	err1, err2 := raceTwoRoleUpdates(t, "x617", true)
	require.NoError(t, err1, "смена роли R1 не должна падать тупиком на встречной смене роли R2 того же субъекта")
	require.NoError(t, err2, "смена роли R2 не должна падать тупиком на встречной смене роли R1 того же субъекта")
}

// TestRoleUpdatesOfOneSubjectCommitWhenTheirFanoutsMeetInOneOrder — законный
// близнец: обе роли сверяют выдачи в порядке [Pa, Pb]. Зелен на любой реализации
// сверки; без него красное выше не отличить от поломки гонки.
func TestRoleUpdatesOfOneSubjectCommitWhenTheirFanoutsMeetInOneOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	err1, err2 := raceTwoRoleUpdates(t, "y617", false)
	require.NoError(t, err1)
	require.NoError(t, err2)
}

// raceTwoRoleUpdates заводит субъекту по две выдачи двух ролей «только
// разрешения» на два проекта, выпускает их ярус чтения и сталкивает смены обеих
// ролей на ярус правки под держателем строки факта меньшего проекта. crosswise —
// выдачи R2 заведены в порядке [Pb, Pa], иначе [Pa, Pb].
func raceTwoRoleUpdates(t *testing.T, suffix string, crosswise bool) (err1, err2 error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, suffix+"o")
	acc := seedAccountByOwner(t, ctx, pool, "acc-"+suffix, owner)
	member := mustSeedUser(t, ctx, pool, suffix+"m")
	pa := seedProjectInAccount(t, ctx, pool, acc, "pa-"+suffix)
	pb := seedProjectInAccount(t, ctx, pool, acc, "pb-"+suffix)
	if pb < pa {
		pa, pb = pb, pa
	}
	r1 := seedAccountCustomRole(t, ctx, pool, acc, suffix+"_r1")
	r2 := seedAccountCustomRole(t, ctx, pool, acc, suffix+"_r2")

	// Порядок заведения — порядок веера: ListActiveByRole идёт по created_at.
	insertProjectGrant(t, ctx, repo, member, r1, pa)
	insertProjectGrant(t, ctx, repo, member, r1, pb)
	if crosswise {
		insertProjectGrant(t, ctx, repo, member, r2, pb)
		insertProjectGrant(t, ctx, repo, member, r2, pa)
	} else {
		insertProjectGrant(t, ctx, repo, member, r2, pa)
		insertProjectGrant(t, ctx, repo, member, r2, pb)
	}

	readRole := func(id domain.RoleID) domain.Role {
		return domain.Role{ID: id, AccountID: acc, Name: "read", Permissions: domain.Permissions{"iam.users.*.read"}}
	}
	editRole := func(id domain.RoleID) domain.Role {
		return domain.Role{ID: id, AccountID: acc, Name: "edit", Permissions: domain.Permissions{"iam.users.*.update"}}
	}
	// Ярус чтения выпускается той же сверкой из пустого реестра — последовательно.
	require.NoError(t, reconcileRoleInTx(ctx, repo, r1, readRole(r1)))
	require.NoError(t, reconcileRoleInTx(ctx, repo, r2, readRole(r2)))

	subject := "user:" + string(member)
	for _, p := range []domain.ProjectID{pa, pb} {
		require.Equal(t, 1, projectFactRows(t, ctx, pool, subject, "viewer", p),
			"предусловие: факт яруса чтения субъекта на проекте %s выпущен", p)
	}

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	var locked int
	require.NoError(t, holder.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.relation_fact
		  WHERE object_type = 'project' AND object_id = $1 AND relation = 'viewer' AND subject = $2
		  FOR UPDATE) s`, string(pa), subject).Scan(&locked))
	require.Equal(t, 1, locked, "предусловие: строка факта проекта %s взята держателем", pa)

	run := func(id domain.RoleID) <-chan error {
		done := make(chan error, 1)
		go func() { done <- reconcileRoleInTx(ctx, repo, id, editRole(id)) }()
		return done
	}
	done1 := run(r1)
	waitRoleLockWaiters(t, ctx, pool, 1)
	done2 := run(r2)
	waitRoleLockWaiters(t, ctx, pool, 2)

	require.NoError(t, holder.Commit(ctx))
	err1, err2 = <-done1, <-done2
	for _, e := range []error{err1, err2} {
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) {
			t.Logf("отказ базы: SQLSTATE %s — %s", pgErr.Code, pgErr.Message)
		}
	}
	if err1 == nil && err2 == nil {
		for _, p := range []domain.ProjectID{pa, pb} {
			require.Equal(t, 1, projectFactRows(t, ctx, pool, subject, "editor", p),
				"после обеих смен ярус правки субъекта на проекте %s стоит", p)
		}
	}
	return err1, err2
}

// insertProjectGrant заводит действующую выдачу роли субъекту на проект со строкой
// перечня субъектов и пустым реестром выпущенного.
func insertProjectGrant(t *testing.T, ctx context.Context, repo *kanamepg.Repository, subject domain.UserID, role domain.RoleID, prj domain.ProjectID) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(context.Background()) }()
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{
		ID:          domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: role, ResourceType: "project", ResourceID: string(prj),
		Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
}

// reconcileRoleInTx — шаг сверки кортежей выдач роли в своей транзакции, тот же,
// что Role.Update зовёт в транзакции правки.
func reconcileRoleInTx(ctx context.Context, repo *kanamepg.Repository, id domain.RoleID, role domain.Role) error {
	w, err := repo.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(context.Background()) }()
	if err := accessbindingapp.NewRoleTupleReconciler().ReconcileRoleTuples(ctx, w, id, role); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// projectFactRows — сколько строк прямого факта отношения субъекта стоит на проекте.
func projectFactRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject, relation string, prj domain.ProjectID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.relation_fact
		  WHERE object_type = 'project' AND object_id = $1 AND relation = $2 AND subject = $3`,
		string(prj), relation, subject).Scan(&n))
	return n
}

// waitRoleLockWaiters ждёт, пока в базе пробы не наберётся n сеансов, ждущих
// замок: гонка поставлена, когда база её видит, а не когда истёк сон.
func waitRoleLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var waiting int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("предусловие гонки не создано: ждущих замок %d из %d", waiting, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
