// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// group_member_belongs_to_the_group_account_integration_test.go — Д-3 приёмки
// role-rights-stay-within-what-is-named.md (PRO-Robotech/kaname#1037) на уровне
// хранилища: участник группы принадлежит её аккаунту, отказ неотличим от отказа
// по несуществующему участнику, и строка, на которой держится ответ, держится до
// коммита вставки.
package pg_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// d3World — аккаунт A с группой, учёткой и тремя людьми (членство ACTIVE,
// членство PENDING, членства нет), аккаунт B с учёткой.
type d3World struct {
	ctx                     context.Context
	pool                    *pgxpool.Pool
	repo                    *kanamepg.Repository
	group                   domain.GroupID
	saA, saB                string
	usrActive, usrPending   domain.UserID
	usrNoMembership, ownerA domain.UserID
	accA                    domain.AccountID
}

func newD3World(t *testing.T) d3World {
	t.Helper()
	ctx, pool := kac127Setup(t)
	repo := kanamepg.New(pool, nil)
	w := d3World{ctx: ctx, pool: pool, repo: repo}
	w.ownerA = mustSeedUser(t, ctx, pool, "d3own")
	w.accA = seedAccount(t, ctx, repo, "acc-d3-a", w.ownerA).ID
	accB := seedAccount(t, ctx, repo, "acc-d3-b", mustSeedUser(t, ctx, pool, "d3ownb")).ID
	w.group = seedGroup(t, ctx, repo, w.accA, "grp-d3").ID
	w.saA = seedSAID(t, ctx, pool, string(w.accA), "d3a")
	w.saB = seedSAID(t, ctx, pool, string(accB), "d3b")
	w.usrActive = mustSeedUser(t, ctx, pool, "d3act")
	w.usrPending = mustSeedUser(t, ctx, pool, "d3pen")
	w.usrNoMembership = mustSeedUser(t, ctx, pool, "d3non")
	for _, m := range []struct {
		user  domain.UserID
		state string
	}{{w.usrActive, "ACTIVE"}, {w.usrPending, "PENDING"}} {
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.memberships (id, user_id, account_id, state)
			VALUES (kaname.membership_mirror_id($1, $2), $1, $2, $3)`,
			string(m.user), string(w.accA), m.state)
		require.NoErrorf(t, err, "посев: членство %s (%s)", m.user, m.state)
	}
	return w
}

// require — RequireMemberOfGroupAccount одной транзакцией записи, откатываемой.
func (w d3World) require(t *testing.T, m domain.GroupMember) error {
	t.Helper()
	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(w.ctx) }()
	return wr.GroupsW().RequireMemberOfGroupAccount(w.ctx, m)
}

// Шесть строк ESC-23 на уровне хранилища плюс эталон формы: отказ вставки по
// несуществующему участнику, поднятый триггером схемы и разобранный
// преобразователем. Чужой и несуществующий — одна форма: признак и текст.
func TestGroup_RequireMemberOfGroupAccount_ForeignIsLikeMissing(t *testing.T) {
	w := newD3World(t)
	absentSA := ids.NewID(domain.PrefixServiceAccount)
	member := func(typ domain.SubjectType, id string) domain.GroupMember {
		return domain.GroupMember{GroupID: w.group, MemberType: typ, MemberID: domain.SubjectID(id)}
	}

	// Эталон: та же вставка мимо проверки — отказ триггера существования.
	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	refTrigger := wr.GroupsW().AddMember(w.ctx, member(domain.SubjectTypeServiceAccount, absentSA))
	_ = wr.Rollback(w.ctx)
	require.Error(t, refTrigger, "эталон: вставка несуществующего участника принята")
	require.True(t, errors.Is(refTrigger, iamerr.ErrReferenceMissing), "эталон: признак (%v)", refTrigger)

	for _, r := range []struct {
		name     string
		m        domain.GroupMember
		admitted bool
	}{
		{"a учётка аккаунта группы", member(domain.SubjectTypeServiceAccount, w.saA), true},
		{"c человек с членством ACTIVE", member(domain.SubjectTypeUser, string(w.usrActive)), true},
		{"b учётка другого аккаунта", member(domain.SubjectTypeServiceAccount, w.saB), false},
		{"d человек без членства", member(domain.SubjectTypeUser, string(w.usrNoMembership)), false},
		{"e человек с членством PENDING", member(domain.SubjectTypeUser, string(w.usrPending)), false},
		{"e' владелец аккаунта без строки членства", member(domain.SubjectTypeUser, string(w.ownerA)), false},
		{"f учётки нет нигде", member(domain.SubjectTypeServiceAccount, absentSA), false},
	} {
		got := w.require(t, r.m)
		if r.admitted {
			assert.NoErrorf(t, got, "Д-3 %s: отказ", r.name)
			continue
		}
		if !assert.Errorf(t, got, "Д-3 %s: принят", r.name) {
			continue
		}
		assert.Truef(t, errors.Is(got, iamerr.ErrReferenceMissing), "Д-3 %s: признак (%v)", r.name, got)
		assert.Equalf(t, refTrigger.Error(), got.Error(), "Д-3 %s: текст отличим от отказа триггера", r.name)
	}
}

// Ответ держится до коммита: пока транзакция добавления держит FOR SHARE
// строки членства (учётки), снятие этой строки ждёт её, а не проходит в окно
// между проверкой и вставкой. Близнец — то же снятие без держащей транзакции:
// проходит, то есть ожидание создано именно замком проверки.
func TestGroup_RequireMemberOfGroupAccount_HoldsTheRowUntilCommit(t *testing.T) {
	w := newD3World(t)
	for _, r := range []struct {
		name   string
		m      domain.GroupMember
		remove string
		arg    string
	}{
		{"членство человека",
			domain.GroupMember{GroupID: w.group, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(w.usrActive)},
			`DELETE FROM kaname.memberships WHERE user_id = $1`, string(w.usrActive)},
		{"учётка",
			domain.GroupMember{GroupID: w.group, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(w.saA)},
			`DELETE FROM kaname.service_accounts WHERE id = $1`, w.saA},
	} {
		t.Run(r.name, func(t *testing.T) {
			holder, err := w.repo.Writer(w.ctx)
			require.NoError(t, err)
			held := true
			defer func() {
				if held {
					_ = holder.Rollback(w.ctx)
				}
			}()
			require.NoError(t, holder.GroupsW().RequireMemberOfGroupAccount(w.ctx, r.m), "Дано: участник из аккаунта группы")

			removeUnder := func() error {
				tx, err := w.pool.Begin(w.ctx)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback(w.ctx) }()
				_, err = tx.Exec(w.ctx, `SET LOCAL lock_timeout = '2s'`)
				require.NoError(t, err)
				_, err = tx.Exec(w.ctx, r.remove, r.arg)
				return err // откат — строка остаётся для близнеца
			}
			err = removeUnder()
			require.Error(t, err, "снятие прошло, пока проверка принадлежности не закоммичена — окно гонки открыто")
			assertSQLState(t, err, "55P03")

			require.NoError(t, holder.Rollback(w.ctx))
			held = false
			assert.NoError(t, removeUnder(), "близнец: без держащей транзакции снятие проходит — ожидание создал замок проверки")
		})
	}
}
