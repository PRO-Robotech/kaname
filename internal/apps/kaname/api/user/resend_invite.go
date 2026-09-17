// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// resend_invite.go — UserService.ResendInvite: письмо приглашения уходит ЕЩЁ
// РАЗ тому, кто приглашён и ещё не выкупил приглашение (приёмка ID-MAIL-1,
// §10 п. 9; MAIL-38; задача продукта #1774).
//
// # Что приходит взамен снятого поля ссылки
//
// Решение Р10 сняло с контракта ссылку первого входа: вернуть её вызывающему
// значило бы выдать приглашающему предъявителя, которым тот войдёт ЗА
// приглашённого. Администратор, у которого «письмо не дошло», получает вместо
// ссылки этот глагол: письмо составляется и уходит ещё раз тем же путём, через
// очередь в нашей базе, и предъявителя оно не несёт — доступ даёт владение
// почтовым ящиком (Р24).
//
// # Порядок проверок — и почему он такой
//
//  1. аноним — отказ до всего;
//  2. формат ОБОИХ идентификаторов — синхронный INVALID_ARGUMENT, не операция;
//  3. право приглашать — то же отношение, что у Invite (`editor` на аккаунт):
//     повторная отправка есть та же поверхность допуска, и более дешёвой двери
//     к письму от имени платформы заводиться не должно;
//  4. строка человека в НАЗВАННОМ аккаунте — иначе NOT_FOUND тем же текстом,
//     что и для человека, которого нет нигде (hide-existence: наличие строки в
//     чужом аккаунте вызывающему знать не положено);
//  5. приглашение ждёт выкупа (PENDING) и не истекло — иначе FAILED_PRECONDITION
//     с указанием следующего шага. Срок есть свойство ВЫДАЧИ (Р24, §10 п. 22),
//     и повтор письма его не двигает: пересылать письмо, по которому вход уже
//     отвергнется, значит обещать то, что не исполнится.
//
// Пункты 4–5 читаются синхронно и намеренно: отказ на них — состояние предмета,
// и клиенту он нужен сразу, а не через опрос операции.
//
// # Ограничение частоты стоит на пути этого глагола по построению
//
// Единственный путь письма — `Writer.EmitInviteMail`, и он списывает окно
// адресата ПЕРЕД постановкой намерения (MAIL-25). Сверх нормы письмо не
// ставится, а операция завершается ТЕМ ЖЕ исходом, что и в норме: отказ по
// частоте не вправе быть оракулом (Р9). Различие видно только счётчику
// намерений — и это единственное место, где оно существует.

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// ResendInviteUseCase — повторная отправка письма приглашения.
type ResendInviteUseCase struct {
	repo        Repo
	opsRepo     operations.Repo
	authz       AuthzChecker
	mailLimit   outboxtypes.InviteMailRateLimit
	mailIntents InviteMailIntentObserver
	// now — часы; подменяются пробой срока. Нулевое поле — настоящие часы.
	now func() time.Time
}

// NewResendInviteUseCase — конструктор. Ограничение частоты — ОБЯЗАТЕЛЬНЫЙ
// аргумент, а не необязательная провязка: у глагола, чей единственный предмет
// — письмо, ограничитель не факультативен. Наблюдатель nil-safe.
func NewResendInviteUseCase(
	r Repo, opsRepo operations.Repo, authz AuthzChecker,
	limit outboxtypes.InviteMailRateLimit, obs InviteMailIntentObserver,
) *ResendInviteUseCase {
	return &ResendInviteUseCase{repo: r, opsRepo: opsRepo, authz: authz, mailLimit: limit, mailIntents: obs}
}

// Execute — синхронные проверки, затем операция.
func (uc *ResendInviteUseCase) Execute(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(userID), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(accountID), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}

	allowed, err := canInviteUsers(ctx, uc.authz, string(accountID))
	if err != nil {
		return nil, fmt.Errorf("authz check: %w", err)
	}
	if !allowed {
		return nil, status.Errorf(codes.PermissionDenied,
			"Permission denied to invite users in account %s", accountID)
	}

	row, err := uc.resendableInvite(ctx, userID, accountID)
	if err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Resend invite %s in account %s", userID, accountID),
		&iamv1.ResendInviteMetadata{UserId: string(userID), AccountId: string(accountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doResend(ctx, row, accountID)
	})
	return &op, nil
}

// resendableInvite — строка приглашения, которую есть смысл пересылать, либо
// отказ в тоне контракта.
func (uc *ResendInviteUseCase) resendableInvite(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (domain.User, error) {
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return domain.User{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Членство спрашивается ПЕРВЫМ, и по его отсутствию отвечается ровно тем
	// текстом, что и по отсутствию строки: иначе «строка есть, но не здесь»
	// стало бы отличимо от «строки нет», а это оракул существования человека в
	// чужом аккаунте.
	inAccount, err := rd.Users().MembershipExists(ctx, userID, accountID)
	if err != nil {
		return domain.User{}, shared.MapRepoErr(err)
	}
	if !inAccount {
		return domain.User{}, status.Errorf(codes.NotFound, "User %s not found", userID)
	}
	row, err := rd.Users().Get(ctx, userID)
	if err != nil {
		return domain.User{}, shared.MapRepoErr(err)
	}
	switch row.InviteStatus {
	case domain.InviteStatusPending:
	case domain.InviteStatusBlocked:
		return domain.User{}, status.Errorf(codes.FailedPrecondition,
			"User %s is blocked — an invitation letter is not sent to a blocked person", userID)
	default:
		return domain.User{}, status.Errorf(codes.FailedPrecondition,
			"invitation of User %s is already redeemed — there is nothing to resend", userID)
	}
	if row.InviteExpired(uc.clock()) {
		return domain.User{}, status.Errorf(codes.FailedPrecondition,
			"invitation of User %s has expired — invite again to issue a new one", userID)
	}
	return row, nil
}

// doResend — асинхронная часть: намерение в очередь ОДНОЙ транзакцией, с
// ограничением частоты у писателя.
func (uc *ResendInviteUseCase) doResend(ctx context.Context, row domain.User, accountID domain.AccountID) (*anypb.Any, error) {
	queued, err := shared.DoWithWriteTx(ctx, uc.repo,
		func(ctx context.Context, w Writer) (bool, error) {
			return w.EmitInviteMail(ctx, outboxtypes.InviteMailIntent{
				UserID:    string(row.ID),
				AccountID: string(accountID),
				To:        string(row.Email),
				Limit:     uc.mailLimit,
			})
		})
	if err != nil {
		return nil, err
	}
	// Исход считается ПОСЛЕ коммита и НЕ меняет ответа: сверхнормативное письмо
	// молчит для вызывающего и говорит для оператора.
	if uc.mailIntents != nil {
		if queued {
			uc.mailIntents.IncInviteMailIntent(MailIntentQueued)
		} else {
			uc.mailIntents.IncInviteMailIntent(MailIntentRateLimited)
		}
	}
	return marshalUser(row)
}

func (uc *ResendInviteUseCase) clock() time.Time {
	if uc.now != nil {
		return uc.now()
	}
	return time.Now().UTC()
}
