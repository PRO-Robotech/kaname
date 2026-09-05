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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	repouser "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
)

// Test_Invite_CoCommitsTheMailIntent — несущее утверждение.
//
// Намерение появляется В ТОЙ ЖЕ транзакции, что и строка приглашения, и несёт
// адресата, аккаунт и ключ партиции. Атомарность самой записи проверяет
// интеграционная проба на живой базе; здесь — что путь её ВООБЩЕ зовёт.
func Test_Invite_CoCommitsTheMailIntent(t *testing.T) {
	repo := &invPrincRepo{}
	uc := NewInviteUserUseCase(repo, newFakeUsrOps(), invPrincAllowAll{})

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

// Test_Invite_EmitsNoMailIntentWhenNoInviteRowIsCreated — граница, названная
// вслух: письмо уходит ровно ОДНО на пару (аккаунт, адрес).
//
// Повторное приглашение того же адреса в тот же аккаунт идемпотентно и до
// заведения строки не доходит — значит и намерения не порождает. Это НЕ
// упущение, а предел, держащийся построением: эмиссия на каждом вызове сделала
// бы приглашение средством рассылки — обладатель права приглашать слал бы на
// произвольный адрес со скоростью вызовов API, и никакой ручки против этого не
// было бы (§4.6 приёмки). Повторная отправка — предмет СВОЕГО глагола со своим
// ограничением частоты (§10 пп. 9 и 17), и заводить её здесь молча нельзя.
func Test_Invite_EmitsNoMailIntentWhenNoInviteRowIsCreated(t *testing.T) {
	repo := &inviteIdempotentRepo{existing: domain.User{
		ID:           domain.UserID("usr0000000000000exst"),
		AccountID:    domain.AccountID(invPrincAccount),
		Email:        domain.Email(invPrincEmail),
		InviteStatus: domain.InviteStatusPending,
	}}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err, "повторное приглашение идемпотентно, а не отказ")
	require.NotNil(t, op)

	// Ждём завершения асинхронного продолжения по НАБЛЮДАЕМОМУ следу — исходу
	// операции, — а не паузой: пауза утверждала бы о времени, а не о работе.
	require.Eventually(t, func() bool {
		got, gerr := ops.Get(context.Background(), op.ID)
		return gerr == nil && got.Done
	}, 5*time.Second, 10*time.Millisecond,
		"асинхронное продолжение приглашения обязано завершиться")

	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Empty(t, repo.mailIntents,
		"строка приглашения не заводилась — письма быть не должно: иначе повтор вызова "+
			"становится способом слать письма на произвольный адрес без предела")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ отрицания живёт в соседней пробе выше
	// (Test_Invite_CoCommitsTheMailIntent): она требует РОВНО ОДНО намерение на
	// пути, где строка заводится. Без неё «намерений ноль» зеленело бы на
	// приглашении, которое не эмитит письма НИКОГДА.
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

func (f *inviteIdempotentRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &inviteIdempotentReader{existing: f.existing}, nil
}

func (f *inviteIdempotentRepo) Writer(context.Context) (kachorepo.Writer, error) {
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
