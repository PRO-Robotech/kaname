// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// reset_access_keys.go — `UserService/ResetAccessKeys`: сброс ключей доступа
// человека администратором облака (задача PRO-Robotech/kaname#638, предмет
// PRO-Robotech/kacho#2702; приёмка
// `docs/engineering/acceptance/cloud-administrator-resets-login-methods.md`,
// редакция 5, Р1–Р8). Ключ человек снимает сам (`AccessKeyService/Revoke`), но
// тот, у кого устройство отняли или кто его утратил, не знает, какой ключ снять,
// а держатель устройства может держать и сессию. Путь даёт этот глагол:
// отношение `identity_suspender` на `iam_user` и пол «2», как у
// `ResetSecondFactor`/`Block`. Держатель — только администратор облака (Р2):
// распорядитель аккаунта, посторонний и сам человек получают от края
// `PERMISSION_DENIED`, один на существующем и несуществующем `user_id`.
//
// # Одна транзакция — под замком строки личности
//
// Транзакцию открывает хранилище ключей тем же писателем, что снятие ключа
// (`AccessKeyRepo.RevokeWriter`, kaname#669): ПЕРВЫМ оператором взята строка
// личности замком писателя нескольких сессий — второй сброс того же человека
// ждёт первого и затем не находит ни одной строки. Дальше, в этом порядке:
//
//  1. испытания регистрации ключа, выданные и не предъявленные, сняты (Р7):
//     регистрация, начатая сессией, которую сброс отсекает, ключа после обоих
//     исходов не оставляет — либо её испытания уже нет (условный оператор
//     потребления отвечает «нет»), либо её строка ключа зафиксирована раньше и
//     снимается следующим шагом. Порядок «испытания раньше ключей» несущий:
//     регистрация, державшая испытание под замком, фиксируется до того, как
//     сброс доходит до строк ключей, и следующий оператор её строку видит;
//  2. ВСЕ строки ключей сняты одним оператором; слоты потолка возвращает
//     триггер той же транзакции (Р3). Ноль снятых — человек сбросом уже лишён
//     ключей (гонка двух сбросов, Р5): исход операции — тот же отказ, без
//     отсечки и события;
//  3. ВСЕ сессии человека покрыты отсечкой моментом общего источника (kaname#589)
//     с причиной `access-keys-reset` и актором — администратором (Р4);
//  4. событие `iam.user.access_keys_reset` с обоими акторами (Р4).
//
// # Что синхронно, а что в Operation
//
// «Ключей нет» судится ДО порождения Operation: `FAILED_PRECONDITION` с
// токеном `ACCESS_KEYS_NOT_ENROLLED`; есть ли у человека пароль, исхода не
// меняет (Р5). Синхронная сверка только классифицирует; инвариант держит
// оператор снятия под замком.
//
// # Чего глагол НЕ делает
//
// Не снимает, не подменяет и не обесценивает строку пароля, не пишет отметку
// открытого пути восстановления, не меняет статус личности (Р8); не трогает
// второй фактор (`ResetSecondFactor`), блокировку, членства и выдачи; не
// заводит способа входа за человека (Р6).

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// Отказ «сбрасывать нечего» (Р5): текст и токен — часть контракта.
const (
	// ReasonAccessKeysNotEnrolled — `ErrorInfo.reason` отказа.
	ReasonAccessKeysNotEnrolled = "ACCESS_KEYS_NOT_ENROLLED"
	// TextAccessKeysNotEnrolled — текст отказа.
	TextAccessKeysNotEnrolled = "user has no access key to reset"
)

// AccessKeyEnrollment — есть ли у человека хоть одна строка ключа доступа
// (узкий порт над хранилищем способов): судится до порождения Operation.
type AccessKeyEnrollment interface {
	AccessKeyEnrolled(ctx context.Context, userID domain.UserID) (bool, error)
}

// AccessKeysResetStore — порт хранилища ключей для сброса: писатель одной
// транзакции, первым оператором которой взята строка личности userID.
// Реализует адаптер хранилища ключей (композиционный корень).
type AccessKeysResetStore interface {
	ResetWriter(ctx context.Context, userID domain.UserID) (AccessKeysResetWriter, error)
}

// AccessKeysResetWriter — ровно то, что нужно сбросу; порядок вызовов задаёт
// глагол (шапка файла).
type AccessKeysResetWriter interface {
	// RetireRegistrationChallenges снимает выданные и не предъявленные
	// испытания регистрации ключа человека; возвращает число снятых.
	RetireRegistrationChallenges(ctx context.Context, userID domain.UserID) (int64, error)
	// DeleteAccessKeysOf снимает все строки ключей человека одним оператором;
	// возвращает число снятых.
	DeleteAccessKeysOf(ctx context.Context, userID domain.UserID) (int64, error)
	// UpsertCutoff — отсечка «все сессии человека до момента» (Ф-л).
	UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error
	// EmitAudit — событие в очередь аудита той же транзакцией.
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// ResetAccessKeysUseCase — сброс ключей доступа администратором облака.
type ResetAccessKeysUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	keys    AccessKeyEnrollment
	store   AccessKeysResetStore
	// cutoffClock — ОБЩИЙ для всех реплик источник момента отсечки (kaname#589).
	cutoffClock revocationpolicy.Clock
}

// NewResetAccessKeysUseCase — построение. Источник момента отсечки подаёт
// корень ([ResetAccessKeysUseCase.WithCutoffClock]); без него сброс
// отказывает, а не берёт часы процесса.
func NewResetAccessKeysUseCase(r Repo, opsRepo operations.Repo, keys AccessKeyEnrollment, store AccessKeysResetStore) *ResetAccessKeysUseCase {
	return &ResetAccessKeysUseCase{repo: r, opsRepo: opsRepo, keys: keys, store: store}
}

// WithCutoffClock провязывает источник момента отсечки. Composition-root only.
func (u *ResetAccessKeysUseCase) WithCutoffClock(c revocationpolicy.Clock) *ResetAccessKeysUseCase {
	u.cutoffClock = c
	return u
}

// Execute — порядок: личность вызывающего → форма id → строка человека (промах
// контракт-тоном) → есть ли ключи → Operation → сброс одним коммитом.
func (u *ResetAccessKeysUseCase) Execute(ctx context.Context, id domain.UserID) (*operations.Operation, error) {
	// Порог «не аноним». КТО вправе — решает МОДЕЛЬ: край проверяет
	// `identity_suspender@iam_user:<user_id>` и пол «2» по записи каталога.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Users().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	enrolled, err := u.keys.AccessKeyEnrolled(ctx, id)
	if err != nil {
		return nil, u.storeErr(ctx, "keys", err)
	}
	if !enrolled {
		return nil, accessKeysNotEnrolledRefusal()
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Reset access keys of user %s", id),
		&iamv1.ResetAccessKeysMetadata{UserId: string(id), AccountId: string(current.AccountID)},
	)
	if err != nil {
		return nil, u.storeErr(ctx, "operation", fmt.Errorf("reset access keys: operation: %w", err))
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, u.storeErr(ctx, "create-operation", fmt.Errorf("reset access keys: create operation: %w", err))
	}
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doReset(ctx, current, actor)
	})
	return &op, nil
}

// doReset — снятие испытаний и ключей, отсечка и событие одним коммитом.
func (u *ResetAccessKeysUseCase) doReset(ctx context.Context, subject domain.User, actor string) (*anypb.Any, error) {
	// Момент отсечки — из общего источника и ДО открытия транзакции писателя:
	// источник читается своим соединением (kaname#589).
	now, err := revocationpolicy.Moment(ctx, u.cutoffClock)
	if err != nil {
		slog.ErrorContext(ctx, "ResetAccessKeys: cutoff moment unavailable",
			"step", "cutoff-moment", "class", revocationpolicy.MomentFailureClass(err))
		return nil, status.Error(codes.Unavailable, shared.MomentUnavailableMessage)
	}
	if u.store == nil {
		return nil, status.Error(codes.Internal, "access keys reset is not wired")
	}
	w, err := u.store.ResetWriter(ctx, subject.ID)
	if err != nil {
		return nil, u.storeErr(ctx, "writer", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	if _, err := w.RetireRegistrationChallenges(ctx, subject.ID); err != nil {
		return nil, u.storeErr(ctx, "challenges", err)
	}
	removed, err := w.DeleteAccessKeysOf(ctx, subject.ID)
	if err != nil {
		return nil, u.storeErr(ctx, "keys", err)
	}
	if removed == 0 {
		// Ключи сняты между сверкой и записью: второй сброс либо сам человек.
		return nil, accessKeysNotEnrolledRefusal()
	}
	revokedBy := domain.UserID(actor)
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: subject.ID, RevokeBefore: now, Reason: domain.RevokeReasonAccessKeysReset, RevokedBy: revokedBy,
	}, revokedBy); err != nil {
		return nil, u.storeErr(ctx, "cutoff", err)
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       auditEventUserAccessKeysReset,
		TenantAccountID: string(subject.AccountID),
		Payload: map[string]any{
			// КТО — проверенная личность администратора облака; КОГО — человек, чьи
			// ключи сняты. Ни адреса, ни имени, ни числа ключей (Р4).
			"actor":   actor,
			"user_id": string(subject.ID),
			"reason":  domain.RevokeReasonAccessKeysReset,
		},
	}); err != nil {
		return nil, u.storeErr(ctx, "audit", err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, u.storeErr(ctx, "commit", err)
	}
	committed = true
	return marshalUser(subject)
}

// storeErr — отказ хранилища на пути операции: класс — общим преобразователем,
// текст драйвера — только в журнал.
func (u *ResetAccessKeysUseCase) storeErr(ctx context.Context, step string, err error) error {
	return shared.LogMappedErr(ctx, slog.Default(), "user.ResetAccessKeys."+step, err, shared.MapRepoErr(err))
}

// accessKeysNotEnrolledRefusal — один отказ «сбрасывать нечего» (Р5) на
// синхронной полосе и в исходе операции.
func accessKeysNotEnrolledRefusal() error {
	st := status.New(codes.FailedPrecondition, TextAccessKeysNotEnrolled)
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: ReasonAccessKeysNotEnrolled,
		Domain: refusaldomain.For(refusaldomain.ServiceIAM),
	})
	if derr != nil {
		return st.Err()
	}
	return withDetails.Err()
}
