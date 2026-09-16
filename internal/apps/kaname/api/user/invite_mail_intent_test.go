// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_mail_intent_test.go — приглашение СО-КОММИТИТ намерение отправить
// письмо (приёмка ID-MAIL-1, Р23/Р25).
//
// Проба утверждает СВОЙСТВО пути, а не наличие функции: без неё приглашение
// создавалось бы, письмо не уходило бы никогда, и отличить это состояние от
// исправного было бы нечем — строка-то появляется.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
)

// Test_Invite_CoCommitsTheMailIntent — несущее утверждение.
//
// Намерение появляется В ТОЙ ЖЕ транзакции, что и строка приглашения, и несёт
// адресата, аккаунт и ключ партиции. Атомарность самой записи проверяет
// интеграционная проба на живой базе; здесь — что путь её ВООБЩЕ зовёт.
func Test_Invite_CoCommitsTheMailIntent(t *testing.T) {
	repo := &invPrincRepo{}
	uc := NewInviteUserUseCase(repo, newFakeUsrOps(), invPrincAllowAll{}).
		WithInviteMailRateLimit(outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	require.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return repo.inserted
	}, 5*time.Second, 10*time.Millisecond, "приглашение обязано дойти до писателя")

	repo.mu.Lock()
	defer repo.mu.Unlock()

	require.Len(t, repo.mailIntents, 1,
		"состоявшееся приглашение обязано оставить РОВНО ОДНО намерение отправить письмо: "+
			"ноль означает приглашение, о котором человек не узнает никогда, а больше "+
			"одного — два письма на одно приглашение")
	got := repo.mailIntents[0]
	assert.Equal(t, invPrincEmail, got.To,
		"намерение обязано нести адресата — без него письмо отправить некому")
	assert.Equal(t, invPrincAccount, got.AccountID,
		"намерение обязано нести аккаунт: это атрибуция письма")
	assert.NotEmpty(t, got.UserID,
		"намерение обязано нести строку приглашения — она же ключ партиции порядка, "+
			"и пустой ключ слил бы письма всех адресатов в одну партицию")
}

// Test_Invite_ReinviteOfAPendingRowSendsAgainWithinTheCap — MAIL-36: повторное
// приглашение того же адреса в тот же аккаунт идемпотентно, и письмо уходит
// ПОВТОРНО в пределах ограничения частоты (MAIL-25).
//
// Здесь стояла противоположная проба — «строка не заводилась, письма быть не
// должно», — и её предел держался построением, потому что ограничителя ещё не
// было. Теперь предел держит окно адресата у писателя очереди, и повтор вызова
// перестаёт быть способом слать письма без предела: сверх нормы письмо не
// ставится, а ответ глагола остаётся тем же (Р9).
func Test_Invite_ReinviteOfAPendingRowSendsAgainWithinTheCap(t *testing.T) {
	repo := &inviteIdempotentRepo{existing: domain.User{
		ID:           domain.UserID("usr0000000000000exst"),
		AccountID:    domain.AccountID(invPrincAccount),
		Email:        domain.Email(invPrincEmail),
		InviteStatus: domain.InviteStatusPending,
	}}
	ops := newFakeUsrOps()
	obs := &countingMailIntentObserver{}
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 2, Window: time.Hour}
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(limit, obs)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
	var ops3 []*operations.Operation
	for i := 0; i < 3; i++ {
		op, err := uc.Execute(ctx, InviteUserInput{
			AccountID: domain.AccountID(invPrincAccount),
			Email:     domain.Email(invPrincEmail),
		})
		require.NoError(t, err, "повторное приглашение идемпотентно, а не отказ")
		require.NotNil(t, op)
		require.Eventually(t, func() bool {
			got, gerr := ops.Get(context.Background(), op.ID)
			return gerr == nil && got.Done
		}, 5*time.Second, 10*time.Millisecond, "асинхронное продолжение обязано завершиться")
		done, gerr := ops.Get(context.Background(), op.ID)
		require.NoError(t, gerr)
		require.Nil(t, done.Error, "вызов %d: сверхнормативное приглашение ответило ОШИБКОЙ — отказ по частоте "+
			"стал отличим от ответа в норме (Р9)", i+1)
		ops3 = append(ops3, done)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.Len(t, repo.mailIntents, limit.MaxPerWindow,
		"три повторных приглашения при норме %d писем на адрес обязаны дать ровно %d намерения: "+
			"меньше — повтор не шлёт (MAIL-36), больше — ограничение не действует (MAIL-25)",
		limit.MaxPerWindow, limit.MaxPerWindow)
	for _, m := range repo.mailIntents {
		assert.Equal(t, invPrincEmail, m.To)
		assert.Equal(t, invPrincAccount, m.AccountID)
	}
	assert.Equal(t, limit.MaxPerWindow, obs.queued, "счётчик queued расходится с очередью")
	assert.Equal(t, 1, obs.rateLimited,
		"сверхнормативное письмо обязано быть видно оператору клеткой rate_limited — "+
			"для вызывающего оно неотличимо от нормы, и это единственное место, где оно существует")

	// Ответы неотличимы: у всех трёх операций один и тот же вид исхода.
	for i := 1; i < len(ops3); i++ {
		assert.Equal(t, ops3[0].Error == nil, ops3[i].Error == nil)
		assert.Equal(t, ops3[0].Response != nil, ops3[i].Response != nil)
	}
}

// Test_Invite_NoMailForAnAlreadyActiveMember — граница: выкупленному
// приглашению письмо не уходит. Приглашать некуда — человек уже в аккаунте, и
// «вы приглашены» было бы письмом без предмета. Положительный контроль —
// проба выше: у PENDING письмо уходит.
func Test_Invite_NoMailForAnAlreadyActiveMember(t *testing.T) {
	repo := &inviteIdempotentRepo{existing: domain.User{
		ID:           domain.UserID("usr0000000000000actv"),
		AccountID:    domain.AccountID(invPrincAccount),
		Email:        domain.Email(invPrincEmail),
		ExternalID:   domain.ExternalSubject("sub-active"),
		InviteStatus: domain.InviteStatusActive,
	}}
	ops := newFakeUsrOps()
	obs := &countingMailIntentObserver{}
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).
		WithInviteMailRateLimit(outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}, obs)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got, gerr := ops.Get(context.Background(), op.ID)
		return gerr == nil && got.Done
	}, 5*time.Second, 10*time.Millisecond)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Empty(t, repo.mailIntents, "выкупленному приглашению ушло письмо")
	assert.Zero(t, obs.queued+obs.rateLimited, "намерение считалось там, где его не просили")
}

// Test_Invite_WithoutAWiredLimitRefusesToSend — ограничитель не факультативен:
// use-case, которому не провязали ограничение, письма не шлёт — писатель
// отвергает нулевое ограничение, и приглашение не проходит. Это громкий отказ
// вместо письма без предела; провязку в композиционном корне держит проба cmd.
func Test_Invite_WithoutAWiredLimitRefusesToSend(t *testing.T) {
	repo := &invPrincRepo{}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got, gerr := ops.Get(context.Background(), op.ID)
		return gerr == nil && got.Done
	}, 5*time.Second, 10*time.Millisecond)
	done, err := ops.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.NotNil(t, done.Error, "приглашение без ограничения частоты прошло — письмо ушло бы без предела")
	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Empty(t, repo.mailIntents)
}

// countingMailIntentObserver — дублёр счётчика исходов намерения.
type countingMailIntentObserver struct {
	mu          sync.Mutex
	queued      int
	rateLimited int
}

func (c *countingMailIntentObserver) IncInviteMailIntent(outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch outcome {
	case MailIntentQueued:
		c.queued++
	case MailIntentRateLimited:
		c.rateLimited++
	default:
		panic("unknown invite mail intent outcome: " + outcome)
	}
}

// inviteIdempotentRepo — дублёр, у которого приглашённый УЖЕ есть в аккаунте.
//
// Он надстроен над общим дублёром пакета вложением, а не написан заново: копия
// разошлась бы с оригиналом молча, и проба утверждала бы о пути, которого в
// продукте нет. Переопределено ровно одно решение — «человек уже есть», — и это
// то самое, чем идемпотентный путь отличается от заведения строки.
type inviteIdempotentRepo struct {
	invPrincRepo
	existing domain.User
}

func (f *inviteIdempotentRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &inviteIdempotentReader{existing: f.existing}, nil
}

func (f *inviteIdempotentRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	return &invPrincWriter{parent: &f.invPrincRepo}, nil
}

type inviteIdempotentReader struct {
	invPrincReader
	existing domain.User
}

func (r *inviteIdempotentReader) Users() repouser.ReaderIface {
	return inviteExistingUserRdr{existing: r.existing}
}

type inviteExistingUserRdr struct {
	invPrincUserRdr
	existing domain.User
}

func (r inviteExistingUserRdr) GetByAccountEmail(
	context.Context, domain.AccountID, domain.Email,
) (domain.User, error) {
	return r.existing, nil
}
