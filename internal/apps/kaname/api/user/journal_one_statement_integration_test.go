// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// journal_one_statement_integration_test.go — приглашение и активация
// приглашения кладут журнал прав ОДНИМ оператором на транзакцию (kaname#617).
//
// Между операторами журнала одной транзакции замки строк прямого факта берутся
// порядком вызовов писателя, а не общим порядком (объект, субъект), который
// свёртка держит лишь внутри оператора: транзакция с двумя операторами сходится в
// кольцо с любым писателем, берущим те же факты в общем порядке (40P01).
//
// Число операторов считает триггер счётчика в базе пробы (journalstmt), а не
// двойник писателя: утверждается то, что положила база.
//
// Близнецы — пути той же транзакции с ОДНИМ набором кортежей (приглашение без
// проекта, активация без личных ресурсов): один оператор на любой ревизии, и
// счётчик, читающий «один», отличим от счётчика, читающего что угодно.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalstmt"
)

// journalWorld — база пробы, аккаунт приглашающего и проект в нём.
type journalWorld struct {
	ctx     context.Context
	repo    *kanamepg.Repository
	probe   *journalstmt.Probe
	inviter domain.UserID
	acc     domain.AccountID
	prj     string
}

func newJournalWorld(t *testing.T) (*journalWorld, func(string, ...any)) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	inviter, acc := seedUserWithAccount(t, ctx, pool, "jrn617")
	prj := ids.NewID(domain.PrefixProject)
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.projects (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, '', '{}'::jsonb, now())`,
		prj, string(acc), "p-"+strings.ToLower(prj[4:12]))
	require.NoError(t, err)
	w := &journalWorld{ctx: ctx, repo: kanamepg.New(pool, nil), inviter: inviter, acc: acc, prj: prj}
	w.probe = journalstmt.Install(t, ctx, pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}
	return w, exec
}

// invite приглашает новый адрес, с проектом либо без, и ждёт исхода операции.
func (w *journalWorld) invite(t *testing.T, email string, withProject bool) {
	t.Helper()
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(w.repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(cmMailLimit, nil)
	in := InviteUserInput{AccountID: w.acc, Email: domain.Email(email)}
	if withProject {
		in.ProjectID = domain.ProjectID(w.prj)
		in.RoleID = domain.RoleID(domain.ClusterAdminRoleID)
	}
	op, err := uc.Execute(operations.WithPrincipal(w.ctx, operations.Principal{Type: "user", ID: string(w.inviter)}), in)
	require.NoError(t, err)
	require.NotNil(t, op)
	var done *operations.Operation
	require.Eventually(t, func() bool {
		got, gerr := ops.Get(w.ctx, op.ID)
		if gerr != nil || !got.Done {
			return false
		}
		done = got
		return true
	}, 10*time.Second, 20*time.Millisecond, "операция приглашения обязана завершиться")
	require.Nil(t, done.Error, "приглашение обязано завершиться успехом: %v", done.Error)
}

func TestInvite_WithProjectGrantLaysItsJournalInOneStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	w, _ := newJournalWorld(t)
	w.probe.Reset(t, w.ctx)

	w.invite(t, fmt.Sprintf("jrn617-grant-%s@example.test", strings.ToLower(w.prj[4:10])), true)

	c := w.probe.Count(t, w.ctx)
	t.Logf("перепись журнала: транзакций %d, операторов %d, наибольшее на транзакцию %d", c.Transactions, c.Statements, c.MaxPerTx)
	require.Positive(t, c.Statements, "предпосылка: приглашение с выдачей на проект писало журнал")
	assert.Equal(t, 1, c.MaxPerTx, "транзакция приглашения кладёт указатель выдачи и указатель личности одним оператором журнала")
}

func TestInvite_WithoutProjectLaysOneStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	w, _ := newJournalWorld(t)
	w.probe.Reset(t, w.ctx)

	w.invite(t, fmt.Sprintf("jrn617-plain-%s@example.test", strings.ToLower(w.prj[4:10])), false)

	c := w.probe.Count(t, w.ctx)
	require.Positive(t, c.Statements, "предпосылка: приглашение новой личности писало журнал")
	assert.Equal(t, 1, c.MaxPerTx, "близнец: один набор кортежей — один оператор на любой ревизии")
}

// pendingInvitee приглашает адрес без проекта и готовит строку к активации так,
// как её готовит полоса формы: способ входа записан на строку приглашения
// регистрацией (kaname#456), адрес подтверждён. Без способа входа действующую
// личность база не фиксирует (`users_active_has_a_way_in_fk`).
func (w *journalWorld) pendingInvitee(t *testing.T, exec func(string, ...any), tag string) domain.User {
	t.Helper()
	email := fmt.Sprintf("jrn617-%s-%s@example.test", tag, strings.ToLower(w.prj[4:10]))
	w.invite(t, email, false)
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(t, err)
	pendings, err := rd.Users().FindPendingByEmail(w.ctx, domain.Email(email))
	_ = rd.Rollback(w.ctx)
	require.NoError(t, err)
	require.Len(t, pendings, 1, "предпосылка: приглашение завело строку PENDING")
	exec(activewayin.InviteePasswordSQL, string(pendings[0].ID))
	exec(`UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, string(pendings[0].ID))
	return pendings[0]
}

// activateCounted исполняет шаг активации в своей транзакции и возвращает перепись.
func (w *journalWorld) activateCounted(t *testing.T, step func(Writer) error) journalstmt.Census {
	t.Helper()
	w.probe.Reset(t, w.ctx)
	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(context.Background()) }()
	require.NoError(t, step(wr), "шаг активации приглашения")
	require.NoError(t, wr.Commit(w.ctx))
	c := w.probe.Count(t, w.ctx)
	t.Logf("перепись журнала: транзакций %d, операторов %d, наибольшее на транзакцию %d", c.Transactions, c.Statements, c.MaxPerTx)
	require.Positive(t, c.Statements, "предпосылка: активация писала журнал")
	return c
}

func TestActivateInviteOnVerification_LaysItsJournalInOneStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	w, exec := newJournalWorld(t)
	p := w.pendingInvitee(t, exec, "act")
	c := w.activateCounted(t, func(wr Writer) error {
		_, err := ActivateInviteOnVerificationTx(w.ctx, wr, p, string(p.ID))
		return err
	})
	assert.Equal(t, 1, c.MaxPerTx, "активация кладёт указатель личности и личные ресурсы одним оператором журнала")
}

func TestActivateInvite_AloneLaysOneStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	w, exec := newJournalWorld(t)
	p := w.pendingInvitee(t, exec, "one")
	c := w.activateCounted(t, func(wr Writer) error {
		_, err := ActivateInviteTx(w.ctx, wr, p, domain.NewOwnLaneSubject(), "", string(p.ID))
		return err
	})
	assert.Equal(t, 1, c.MaxPerTx, "близнец: одна активация без личных ресурсов — один оператор на любой ревизии")
}
