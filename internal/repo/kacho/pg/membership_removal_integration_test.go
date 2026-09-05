// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_removal_integration_test.go — исключение человека из аккаунта
// (#1127): что оно снимает, чего не трогает и что его не отменяет.
//
// # Три утверждения, и каждое закрывает свой способ ошибиться
//
//  1. СНИМАЕТ РОВНО ЧЛЕНСТВО. Строка `iam_user` не меняется ни в одном поле, и
//     членства в ДРУГИХ аккаунтах остаются. Иначе «исключить из моего аккаунта»
//     тихо становится действием над личностью — тем самым классом, который
//     #1102 и #1131 из рук аккаунта забрали.
//
//  2. НЕ ОТМЕНЯЕТСЯ САМО. Зеркало членства ведёт триггер на строке человека, и в
//     редакции 20260823053000 оно вставляло членство при КАЖДОМ срабатывании —
//     то есть первый же вход исключённого возвращал его в аккаунт, откуда его
//     вывели. Приглашения не было, решения распорядителя не было, а участие
//     есть. Это плечо и есть предмет миграции 20260824010000; рядом стоит
//     положительный контроль — зеркало по-прежнему ПРАВИТ существующее членство,
//     иначе «не воскрешает» было бы неотличимо от «зеркало сломано целиком».
//
//  3. НЕ ОСИРОТИТ ПРАВА. Членство, несущее живую выдачу в этом аккаунте, не
//     снимается: отложенный страж (миграция 472002) отвергает транзакцию на
//     КОММИТЕ, и наружу это обязано выходить контракт-тоном FAILED_PRECONDITION,
//     а не «сервис сломан».
//
// Настоящий Postgres. Пропускается под кратким режимом.

package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// TestIntegration_RemoveMembershipTakesTheMembershipAndNothingElse — плечо 1.
func TestIntegration_RemoveMembershipTakesTheMembershipAndNothingElse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	ownerA, accA := bootstrapAdmin(t, ctx, repo, "rmm1")
	_, accB := bootstrapAdmin(t, ctx, repo, "rmm2")

	// Человек, состоящий в ДВУХ аккаунтах: одна строка личности, два членства.
	// Это и есть та фигура, ради которой исключение отделено от удаления.
	person := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID: person, AccountID: accA,
			Email: "two-accounts-rmm@example.com", DisplayName: "Two", InvitedBy: ownerA,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		got, inserted, ierr := w.UsersW().InsertPending(ctx, domain.User{
			ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: accB,
			Email: "two-accounts-rmm@example.com", DisplayName: "Two", InvitedBy: ownerA,
		})
		require.NoError(t, ierr)
		require.False(t, inserted,
			"ПРЕДПОСЫЛКА: приглашение известной почты во второй аккаунт не вправе заводить "+
				"вторую строку личности — иначе фикстура собрала не ту фигуру")
		require.Equal(t, person, got.ID)
		require.NoError(t, w.Commit(ctx))
	}
	require.Len(t, membershipsOf(t, ctx, pool, person), 2,
		"ПРЕДПОСЫЛКА: у человека обязано быть ДВА членства — иначе «второе уцелело» ниже "+
			"утверждается о том, чего не было")

	before := readUserRow(t, ctx, pool, person)

	// ── снятие ───────────────────────────────────────────────────────────────
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		removed, rerr := w.UsersW().RemoveMembership(ctx, person, accA)
		require.NoError(t, rerr)
		require.True(t, removed, "снятие существующего членства обязано сообщить, что оно было")
		require.NoError(t, w.Commit(ctx))
	}

	left := membershipsOf(t, ctx, pool, person)
	require.Len(t, left, 1, "снято обязано быть РОВНО одно членство")
	require.Equal(t, string(accB), left[0].AccountID,
		"уцелеть обязано членство ДРУГОГО аккаунта: исключение из A не касается B")

	// ── граница: строка личности не тронута НИ В ОДНОМ поле ──────────────────
	require.Equal(t, before, readUserRow(t, ctx, pool, person),
		"исключение из аккаунта изменило строку ЛИЧНОСТИ. Это действие над ЧЛЕНСТВОМ: человек, "+
			"выведенный из аккаунта A, обязан работать в аккаунте B без единого изменения записи "+
			"— тот же идентификатор, та же почта, то же состояние, те же метки")

	// ── идемпотентность: повтор проходит и сообщает, что снимать было нечего ──
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		removed, rerr := w.UsersW().RemoveMembership(ctx, person, accA)
		require.NoError(t, rerr,
			"повтор исключения обязан проходить: аргумент — ОТСУТСТВИЕ членства, а не переход, "+
				"и направление, делающее систему строже, не может падать на повторе")
		require.False(t, removed,
			"повтор обязан сообщить, что членства не было: вызывающий отличает «исключил» от "+
				"«его здесь не было», и от этого зависит, писать ли в журналы")
		require.NoError(t, w.Commit(ctx))
	}
	require.Len(t, membershipsOf(t, ctx, pool, person), 1,
		"повтор не вправе трогать оставшееся членство")
}

// TestIntegration_RemovedMembershipIsNotResurrectedByARowUpdate — плечо 2.
//
// Это ПРОБА НА МИГРАЦИЮ 20260824010000. До неё зеркало вставляло членство при
// каждом срабатывании триггера, поэтому первый вход исключённого возвращал его
// в аккаунт: `ActivateInvite` пишет `invite_status`, триггер срабатывает, членство
// появляется заново — уже «активным».
func TestIntegration_RemovedMembershipIsNotResurrectedByARowUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	ownerID, accID := bootstrapAdmin(t, ctx, repo, "rmres")

	// Приглашённый: его `users.account_id` называет ИМЕННО тот аккаунт, из
	// которого его исключат, — то есть худший случай, а не удобный.
	excluded := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID: excluded, AccountID: accID,
			Email: "excluded-rmres@example.com", DisplayName: "Excluded", InvitedBy: ownerID,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	// Положительный контроль — сосед, которого НЕ исключали. Без него
	// «воскрешения нет» было бы неотличимо от «зеркало сломано целиком».
	kept := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID: kept, AccountID: accID,
			Email: "kept-rmres@example.com", DisplayName: "Kept", InvitedBy: ownerID,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	require.Len(t, membershipsOf(t, ctx, pool, excluded), 1)
	require.Equal(t, "PENDING", membershipsOf(t, ctx, pool, kept)[0].State,
		"ПРЕДПОСЫЛКА: контрольное членство обязано быть «приглашён», иначе переход состояния "+
			"ниже ничего не показывает")

	// ── исключение ───────────────────────────────────────────────────────────
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		removed, rerr := w.UsersW().RemoveMembership(ctx, excluded, accID)
		require.NoError(t, rerr)
		require.True(t, removed)
		require.NoError(t, w.Commit(ctx))
	}
	require.Empty(t, membershipsOf(t, ctx, pool, excluded))

	// ── первый вход: строка человека ПРАВИТСЯ, триггер зеркала срабатывает ───
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().ActivateInvite(ctx, excluded,
			domain.ExternalSubject("ext-rmres-activated"), domain.DisplayName("Excluded"))
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	// ── ОТРИЦАНИЕ — предмет пробы ────────────────────────────────────────────
	require.Empty(t, membershipsOf(t, ctx, pool, excluded),
		"исключённый человек ВЕРНУЛСЯ в аккаунт от правки собственной строки. Зеркало членства "+
			"не вправе ЗАВОДИТЬ членство на правке: приглашения не было, решения распорядителя "+
			"не было, а участие есть — и заметить это нечем, потому что «не доехало» и "+
			"«отозвано намеренно» снаружи выглядят одинаково (миграция 20260824010000)")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — зеркало по-прежнему ПРАВИТ существующее ─────
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().ActivateInvite(ctx, kept,
			domain.ExternalSubject("ext-rmres-kept"), domain.DisplayName("Kept"))
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	keptAfter := membershipsOf(t, ctx, pool, kept)
	require.Len(t, keptAfter, 1,
		"КОНТРОЛЬ: у неисключённого членство обязано остаться — иначе отрицание выше зеленеет "+
			"на зеркале, снесённом целиком")
	require.Equal(t, "ACTIVE", keptAfter[0].State,
		"КОНТРОЛЬ: первый вход обязан перевести существующее членство в «активно» — зеркало "+
			"правит то, что есть, и это его вторая половина")
}

// TestIntegration_MembershipCarryingRightsIsRefusedWithContractTone — плечо 3.
func TestIntegration_MembershipCarryingRightsIsRefusedWithContractTone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	ownerID, accID := bootstrapAdmin(t, ctx, repo, "rmrgt")

	person := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID: person, AccountID: accID,
			Email: "granted-rmrgt@example.com", DisplayName: "Granted", InvitedBy: ownerID,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	// Живая выдача этому человеку В ЭТОМ аккаунте — то, что страж и охраняет.
	roleID := seedAccountRole(t, ctx, pool, accID, "rmrgtrole")
	bindingID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `INSERT INTO kacho_iam.access_bindings
	          (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	        VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		bindingID, string(person), string(roleID), string(accID))
	require.NoError(t, err)

	w, werr := repo.Writer(ctx)
	require.NoError(t, werr)
	removed, rerr := w.UsersW().RemoveMembership(ctx, person, accID)
	require.NoError(t, rerr,
		"страж ОТЛОЖЕННЫЙ: на самом стейтменте он молчать обязан, иначе он навязывал бы "+
			"вызывающему порядок стейтментов внутри транзакции")
	require.True(t, removed)

	commitErr := w.Commit(ctx)
	require.Error(t, commitErr,
		"членство, несущее живую выдачу в этом аккаунте, снялось. Тогда право осталось без "+
			"носителя, и заметить это нечем: отзыв тише выдачи")
	require.ErrorIs(t, commitErr, iamerr.ErrFailedPrecondition,
		"отказ обязан быть FAILED_PRECONDITION («состояние ресурса не позволяет»), а не "+
			"INTERNAL: распорядитель аккаунта, честно упёршийся в «сперва отзови права», "+
			"прочитал бы «сервис сломан» и пошёл бы искать поломку")
	require.Contains(t, commitErr.Error(), string(person),
		"текст отказа обязан НАЗЫВАТЬ человека: без него вызывающему нечего исправлять")
	require.Contains(t, commitErr.Error(), string(accID),
		"текст отказа обязан НАЗЫВАТЬ аккаунт: членство есть пара, и половина её не адресует")
	require.NotContains(t, commitErr.Error(), "SQLSTATE",
		"текст сервера наружу не эхается — в нём имя ограничения и значения (разведка схемы)")

	// Строка на месте: транзакция не прошла целиком.
	require.Len(t, membershipsOf(t, ctx, pool, person), 1,
		"отказ обязан откатить снятие: половина исключения хуже отсутствия исключения")
}

// readUserRow — ВСЕ поля строки личности одним снимком.
//
// Составом, а не выборочными полями: проверка двух колонок из девяти зеленела бы
// на правке седьмой, а утверждение здесь ровно про то, что не тронуто НИЧЕГО.
func readUserRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.UserID) string {
	t.Helper()
	var out string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT format('%s|%s|%s|%s|%s|%s|%s|%s|%s',
		              id, coalesce(account_id,''), external_id, email, display_name,
		              invite_status, coalesce(invited_by,''), labels::text, created_at)
		  FROM kacho_iam.users WHERE id = $1`, string(id)).Scan(&out))
	require.NotEmptyf(t, out, "строка личности %s не прочитана — снимок беспредметен", id)
	return out
}
