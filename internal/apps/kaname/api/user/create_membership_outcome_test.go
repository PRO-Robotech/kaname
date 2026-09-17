// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// create_membership_outcome_test.go — ИСХОД, а не вызов: `MembershipService.Create`
// на живой базе (kaname#181, предикат снятия пп. 3–4; IAM-ID-1-01/-02/-05).
//
// Утверждается СОСТОЯНИЕ таблиц и то, что видит `MembershipService.List`
// названного аккаунта, — а не то, что писатель не отказал. «Не отказал» зеленело
// бы и тогда, когда членство не появилось вовсе, и тогда, когда второй глагол
// завёл бы вторую строку.
//
// Два глагола на одну пару «человек × аккаунт» дают ОДНУ строку членства В
// ЛЮБОМ ПОРЯДКЕ, и оба порядка прогоняются: порядок — тот единственный факт,
// которым положительный близнец отличается от своего зеркала.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	membershipapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// listedMemberships — то, что отдаёт `MembershipService.List` названного аккаунта
// по человеку: тем же читателем и тем же фильтром, что обработчик.
func listedMemberships(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	acc domain.AccountID, uid domain.UserID,
) []domain.Membership {
	t.Helper()
	s, err := repo.MembershipReader(ctx)
	require.NoError(t, err)
	defer s.Close(ctx)
	rows, _, err := s.Memberships().List(ctx, repomembership.ListFilter{
		AccountID: acc,
		Filter:    `userId="` + string(uid) + `"`,
	})
	require.NoError(t, err)
	return rows
}

func countRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, q, args...).Scan(&n))
	return n
}

// membershipOf ждёт операцию и возвращает её ответ как Membership.
func membershipOf(t *testing.T, ops *fakeUsrOps, op *operations.Operation) *iamv1.Membership {
	t.Helper()
	done := awaitUsrOp(t, ops, op.ID)
	require.Nil(t, done.Error, "операция обязана завершиться без отказа: %v", done.Error)
	m := &iamv1.Membership{}
	require.NoError(t, done.Response.UnmarshalTo(m), "response — Membership")
	return m
}

// TestIntegration_KAN181_CreateMembershipThenInviteIsOneRow — новый глагол
// заводит строку членства, видимую списком аккаунта; повтор ПРЕЖНИМ глаголом
// той же пары строку не удваивает (предикат п. 3).
func TestIntegration_KAN181_CreateMembershipThenInviteIsOneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	admin, acc := seedUserWithAccount(t, ctx, repo, "cm1")
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})
	ctx = operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(admin)})
	const email = domain.Email("fresh-cm1@example.com")

	// ── новый глагол ─────────────────────────────────────────────────────────
	op, err := uc.CreateMembership(ctx, membershipapp.CreateInput{AccountID: acc, Email: email})
	require.NoError(t, err)
	created := membershipOf(t, ops, op)
	uid := domain.UserID(created.GetUserId())
	assert.Equal(t, string(acc), created.GetAccountId())
	assert.Equal(t, iamv1.Membership_PENDING, created.GetState(), "неизвестная почта: приглашён, не входил")
	assert.Regexp(t, `^mbr-[0-9a-z]{17}$`, created.GetId())
	assert.Equal(t, string(admin), created.GetInvitedBy())

	rows := listedMemberships(t, ctx, repo, acc, uid)
	require.Len(t, rows, 1, "членство ВИДИМО списком названного аккаунта")
	assert.Equal(t, created.GetId(), string(rows[0].ID), "ответ операции и список называют ОДНУ строку")
	assert.Equal(t, domain.MembershipStatePending, rows[0].State)

	// ── повтор ПРЕЖНИМ глаголом той же пары ──────────────────────────────────
	op2, err := uc.Execute(ctx, InviteUserInput{AccountID: acc, Email: email})
	require.NoError(t, err)
	done2 := awaitUsrOp(t, ops, op2.ID)
	require.Nil(t, done2.Error)

	assert.Equal(t, 1, countRows(t, ctx, pool,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`, string(uid), string(acc)),
		"два глагола на одну пару — ОДНО членство")
	assert.Equal(t, 1, countRows(t, ctx, pool,
		`SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`, string(email)),
		"строка человека одна")
	again := listedMemberships(t, ctx, repo, acc, uid)
	require.Len(t, again, 1)
	assert.Equal(t, created.GetId(), string(again[0].ID), "идентификатор членства переиспользуется")
}

// TestIntegration_KAN181_InviteThenCreateMembershipIsOneRow — ЗЕРКАЛО: порядок
// обратный, исход тот же. Без него «не удваивает» было бы свойством одного
// порядка вызовов.
func TestIntegration_KAN181_InviteThenCreateMembershipIsOneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	admin, acc := seedUserWithAccount(t, ctx, repo, "cm2")
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})
	ctx = operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(admin)})
	const email = domain.Email("fresh-cm2@example.com")

	op1, err := uc.Execute(ctx, InviteUserInput{AccountID: acc, Email: email})
	require.NoError(t, err)
	done1 := awaitUsrOp(t, ops, op1.ID)
	require.Nil(t, done1.Error)
	invited := &iamv1.User{}
	require.NoError(t, done1.Response.UnmarshalTo(invited))
	uid := domain.UserID(invited.GetId())
	before := listedMemberships(t, ctx, repo, acc, uid)
	require.Len(t, before, 1)

	op2, err := uc.CreateMembership(ctx, membershipapp.CreateInput{AccountID: acc, Email: email})
	require.NoError(t, err)
	created := membershipOf(t, ops, op2)
	assert.Equal(t, string(before[0].ID), created.GetId(),
		"повтор новым глаголом отвечает ТОЙ ЖЕ строкой — идентификатор вычислен из пары")
	assert.Equal(t, string(uid), created.GetUserId(), "человек тот же")
	assert.Equal(t, 1, countRows(t, ctx, pool,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`, string(uid), string(acc)))
}

// TestIntegration_KAN181_KnownEmailIntoSecondAccountKeepsOneUserRow —
// IAM-ID-1-02 новым глаголом: у человека, действующего в A, приглашение в B
// строки НЕ заводит, а добавляет членство в B — сразу ACTIVE (предикат п. 4).
func TestIntegration_KAN181_KnownEmailIntoSecondAccountKeepsOneUserRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	// Человек ДЕЙСТВУЕТ в аккаунте A: строка со внешним субъектом, вошедший.
	activeID, accA := seedUserWithAccount(t, ctx, repo, "cm3a")
	var email string
	require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM kaname.users WHERE id = $1`, string(activeID)).Scan(&email))
	adminB, accB := seedUserWithAccount(t, ctx, repo, "cm3b")
	// Контроль: третий аккаунт, куда человека никто не звал.
	_, accC := seedUserWithAccount(t, ctx, repo, "cm3c")

	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})
	ctx = operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(adminB)})

	op, err := uc.CreateMembership(ctx, membershipapp.CreateInput{
		AccountID: accB, Email: domain.Email(email), DisplayName: "Renamed By Inviter",
	})
	require.NoError(t, err)
	// МЕТАДАННЫЕ называют существующую строку, а не кандидата: приёмка
	// спрашивает почту до чеканки операции, поэтому разрешение осиротевшей
	// операции по паре из метаданных находит ту же строку, что и транзакция.
	md := &iamv1.CreateMembershipMetadata{}
	require.NoError(t, op.Metadata.UnmarshalTo(md))
	assert.Equal(t, string(activeID), md.GetUserId(),
		"metadata.user_id известной почты — её строка, не свежий кандидат")

	m := membershipOf(t, ops, op)

	assert.Equal(t, string(activeID), m.GetUserId(),
		"известная почта: ответ называет СУЩЕСТВУЮЩУЮ строку человека, а не кандидата")
	assert.Equal(t, string(accB), m.GetAccountId())
	assert.Equal(t, iamv1.Membership_ACTIVE, m.GetState(),
		"человек уже входил — членство действует сразу, шага принятия нет")
	assert.Equal(t, string(adminB), m.GetInvitedBy(), "след приглашения — область АККАУНТА B")

	assert.Equal(t, 1, countRows(t, ctx, pool,
		`SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`, email),
		"второй строки человека не заводится (IAM-ID-1-02)")
	var displayName string
	require.NoError(t, pool.QueryRow(ctx, `SELECT display_name FROM kaname.users WHERE id = $1`, string(activeID)).Scan(&displayName))
	assert.NotEqual(t, "Renamed By Inviter", displayName, "приглашающий не переписывает имя известному человеку")

	assert.Len(t, listedMemberships(t, ctx, repo, accA, activeID), 1, "членство в A цело")
	assert.Len(t, listedMemberships(t, ctx, repo, accB, activeID), 1, "членство в B появилось")
	assert.Len(t, listedMemberships(t, ctx, repo, accC, activeID), 0,
		"КОНТРОЛЬ: в аккаунте, куда не звали, членства нет — глагол заводит ровно одно")
	assert.Equal(t, 2, countRows(t, ctx, pool,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = $1`, string(activeID)),
		"одна строка, два членства")

}
