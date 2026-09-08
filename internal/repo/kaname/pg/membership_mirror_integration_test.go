// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_mirror_integration_test.go — стадия S1 отрыва аккаунта от строки
// пользователя (IAM-ID-1, задача kacho#470): двойная запись.
//
// На S1 авторитет принадлежности остаётся у колонки `users.account_id`, а
// `memberships` — её зеркало. Зеркало обязано быть точным при КАЖДОМ писателе,
// а не при одном.
//
// # Почему зеркало держит база, а не Go
//
// Писателей строки пользователя больше одного, и они не однородны: четыре пути
// репозитория (Upsert · InsertPending · InsertActive · Delete) — и ТРИ
// применённые миграции, которые сеют служебные строки-якоря сырым SQL. Зеркало,
// написанное в Go, эти три не покрывает by construction, как не покроет ни
// восстановление из дампа, ни следующую посевную миграцию. Инвариант,
// отвечающий одному вызывающему вместо каждого писателя, — это ban #10; поэтому
// зеркало ведёт триггер, и проба спрашивает БАЗУ, а не код.
//
// Каждое утверждение ниже спрашивает СОСТОЯНИЕ таблицы после операции, а не факт
// вызова: «двойная запись вызвана» зеленеет при неверном зеркале.

package pg_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// membershipsOf — состояние зеркала для одной строки пользователя.
func membershipsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID) []struct {
	ID        string
	AccountID string
	State     string
} {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT id, account_id, state
		  FROM kaname.memberships
		 WHERE user_id = $1
		 ORDER BY account_id`, string(userID))
	require.NoError(t, err)
	defer rows.Close()
	var out []struct {
		ID        string
		AccountID string
		State     string
	}
	for rows.Next() {
		var r struct {
			ID        string
			AccountID string
			State     string
		}
		require.NoError(t, rows.Scan(&r.ID, &r.AccountID, &r.State))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func countMembershipsInAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.memberships WHERE account_id = $1`, string(acc)).Scan(&n))
	return n
}

// TestIntegration_MembershipMirrorFollowsEveryWriter — зеркало точно на каждом
// пути записи строки пользователя.
func TestIntegration_MembershipMirrorFollowsEveryWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	ownerID, accID := bootstrapAdmin(t, ctx, repo, "mir1")

	// ── писатель, заведший аккаунт: его собственная строка уже зеркалирована ──
	own := membershipsOf(t, ctx, pool, ownerID)
	require.Len(t, own, 1, "InsertActive обязан оставить ровно одно членство")
	require.Equal(t, string(accID), own[0].AccountID)
	require.Equal(t, "ACTIVE", own[0].State)
	require.Regexp(t, `^mbr-[0-9a-z]{17}$`, own[0].ID,
		"идентификатор членства — дефис-канон платформы: он адресуется снаружи начиная с S3, "+
			"а чеканится уже здесь и живёт с этой строкой всю её жизнь (ban #15)")

	// ── InsertPending: приглашённый → членство в состоянии «приглашён» ───────
	pendingID := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID:          pendingID,
			AccountID:   accID,
			Email:       "pending-mir1@example.com",
			DisplayName: "Pending",
			InvitedBy:   ownerID,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	pend := membershipsOf(t, ctx, pool, pendingID)
	require.Len(t, pend, 1)
	require.Equal(t, "PENDING", pend[0].State,
		"состояние членства следует состоянию приглашения строки (IAM-ID-1-39)")

	// ── ActivateInvite: состояние членства едет следом ───────────────────────
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().ActivateInvite(ctx, pendingID,
			domain.ExternalSubject("ext-mir1-activated"), domain.DisplayName("Pending"))
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	act := membershipsOf(t, ctx, pool, pendingID)
	require.Len(t, act, 1, "активация не вправе ни задвоить членство, ни завести второе")
	require.Equal(t, "ACTIVE", act[0].State,
		"первый вход переводит строку в «активен» — членство обязано поехать следом (IAM-ID-1-04)")
	require.Equal(t, pend[0].ID, act[0].ID,
		"идентификатор членства неизменяем: активация меняет состояние, а не идентичность")

	// ── Delete: зеркало уходит вместе со строкой ─────────────────────────────
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		require.NoError(t, w.UsersW().Delete(ctx, pendingID))
		require.NoError(t, w.Commit(ctx))
	}
	require.Empty(t, membershipsOf(t, ctx, pool, pendingID),
		"снятие строки уносит её зеркало: осиротевшее членство ссылалось бы на человека, которого нет")

	// Положительный контроль к предыдущему отрицанию: соседняя строка НЕ тронута.
	// Без него «членств нет» зеленело бы и при зеркале, снесённом целиком.
	require.Len(t, membershipsOf(t, ctx, pool, ownerID), 1,
		"снятие одной строки не вправе трогать зеркало другой")
}

// TestIntegration_MembershipMirrorIsOnePerUserAccountPair — «человек × аккаунт»
// уникален, и держит это база.
func TestIntegration_MembershipMirrorIsOnePerUserAccountPair(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	userID, accID := bootstrapAdmin(t, ctx, repo, "mir2")

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.memberships (id, user_id, account_id, state)
		VALUES ($1, $2, $3, 'ACTIVE')`,
		"mbr-00000000000000002", string(userID), string(accID))
	require.Error(t, err,
		"второе членство того же человека в том же аккаунте обязано отвергаться КОНСТРУКЦИЕЙ базы, "+
			"а не проверкой в use-case (ban #10)")

	// Положительный контроль: та же вставка в ДРУГОЙ аккаунт проходит — иначе
	// отказ выше означал бы «сюда вообще нельзя писать», а не «пара уникальна».
	otherAcc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.AccountsW().Insert(ctx, domain.Account{
			ID:          otherAcc,
			Name:        domain.AccountName("acc-mir2-other"),
			OwnerUserID: userID,
			Labels:      domain.Labels{},
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.memberships (id, user_id, account_id, state)
		VALUES ($1, $2, $3, 'ACTIVE')`,
		"mbr-00000000000000003", string(userID), string(otherAcc))
	require.NoError(t, err,
		"один человек в двух аккаунтах — это ДВА членства: ровно та форма, ради которой заводится ресурс")
	require.Len(t, membershipsOf(t, ctx, pool, userID), 2)
}

// TestIntegration_MembershipMirrorUnderConcurrentWriters — зеркало не теряется и
// не задваивается под конкуренцией.
//
// Гонка настоящая, а не последовательная: N писателей входят в один аккаунт
// одновременно, каждый своей транзакцией (data-integrity.md §Чек-лист п.5 —
// без конкурентной пробы инвариант не мёржим).
func TestIntegration_MembershipMirrorUnderConcurrentWriters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	_, accID := bootstrapAdmin(t, ctx, repo, "mir3")
	const writers = 8

	var wg sync.WaitGroup
	errs := make([]error, writers)
	ready := make(chan struct{})
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready // все стартуют разом: иначе это последовательный прогон с лишними словами
			uid := domain.UserID(ids.NewID(domain.PrefixUser))
			w, werr := repo.Writer(ctx)
			if werr != nil {
				errs[i] = werr
				return
			}
			if _, ierr := w.UsersW().InsertActive(ctx, domain.User{
				ID:           uid,
				AccountID:    accID,
				ExternalID:   domain.ExternalSubject(fmt.Sprintf("ext-mir3-%d-%s", i, uid)),
				Email:        domain.Email(fmt.Sprintf("mir3-%d@example.com", i)),
				DisplayName:  domain.DisplayName("Racer"),
				InviteStatus: domain.InviteStatusActive,
			}); ierr != nil {
				_ = w.Rollback(ctx)
				errs[i] = ierr
				return
			}
			errs[i] = w.Commit(ctx)
		}()
	}
	close(ready)
	wg.Wait()
	for i, e := range errs {
		require.NoError(t, e, "писатель %d", i)
	}

	// bootstrapAdmin уже оставил одно членство в этом аккаунте.
	require.Equal(t, writers+1, countMembershipsInAccount(t, ctx, pool, accID),
		"под конкуренцией зеркало не теряет строк и не задваивает их: "+
			"ровно одно членство на каждого вошедшего")
}

// TestIntegration_PersonalAccountGateCountsOwnershipNotMembership — директива
// владельца (п. 3) сохраняется дословно.
//
// Личный аккаунт заводится при первом появлении человека, и ворота этого
// решения спрашивают «сколько у него СОБСТВЕННЫХ аккаунтов», а не «сколько у
// него членств». Отрыв создаёт ровно один соблазн — переформулировать ворота
// через членства, — и это ОТМЕНИЛО БЫ директиву для приглашённого: он членство
// имеет, личного аккаунта не получит (IAM-ID-1-15, IAM-ID-1-16).
//
// Проба различает две величины на живых строках: у человека, состоящего в чужом
// аккаунте и не владеющего ничем, они РАЗНЫЕ. На дереве, где членств ещё нет,
// такое различение неконструируемо — поэтому проба заводится здесь, вместе с
// ресурсом, а не «потом».
func TestIntegration_PersonalAccountGateCountsOwnershipNotMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	ownerID, accID := bootstrapAdmin(t, ctx, repo, "gate1")

	// Человек в ЧУЖОМ аккаунте: членство есть, собственного аккаунта нет.
	memberID := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().InsertActive(ctx, domain.User{
			ID:           memberID,
			AccountID:    accID, // состоит в аккаунте ownerID, но не владеет им
			ExternalID:   domain.ExternalSubject("ext-gate1-member"),
			Email:        "member-gate1@example.com",
			DisplayName:  "Member",
			InviteStatus: domain.InviteStatusActive,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	ownedByMember, err := rd.Accounts().CountAccountsByOwner(ctx, memberID)
	require.NoError(t, err)
	memberships := len(membershipsOf(t, ctx, pool, memberID))

	require.Zero(t, ownedByMember,
		"предикат ворот — «собственных аккаунтов ноль». Для этого человека он выполнен, "+
			"значит личный аккаунт ему полагается (директива RC-5 действует и для приглашённого)")
	require.Equal(t, 1, memberships,
		"а членство у него ЕСТЬ — и будь ворота переформулированы через членства, "+
			"они бы не сработали и человек остался бы без личного аккаунта")
	require.NotEqual(t, ownedByMember, memberships,
		"две величины обязаны РАЗЛИЧАТЬСЯ на этой фикстуре: равные, они не различали бы "+
			"верную формулировку ворот от отменяющей директиву")

	// Положительный контроль: у владельца та же пара величин совпадает и не
	// нулевая — то есть предикат ворот вообще способен вернуть не-ноль.
	ownedByOwner, err := rd.Accounts().CountAccountsByOwner(ctx, ownerID)
	require.NoError(t, err)
	require.Equal(t, 1, ownedByOwner,
		"у владельца собственный аккаунт есть — ворота молчат, второго личного не заводится (IAM-ID-1-17)")
}
