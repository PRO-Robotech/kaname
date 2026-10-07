// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// reset_second_factor.go — `UserService/ResetSecondFactor`: сброс второго
// фактора администратором облака (фаза Ф12, задача PRO-Robotech/kacho#1281; приёмка
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`, Р10;
// Ф12-30). Человек, утративший устройство И запасные коды, входит паролем и
// остаётся на «1» без пути к «2» — снятие требует кода (Р9). Путь даёт этот
// глагол: отношение `identity_suspender` на `iam_user` и пол «2», как у
// `Block`/`Unblock`. Держатель — только администратор облака (решение владельца
// 2026-09-18, kaname#254): распорядитель аккаунта, посторонний и сам человек
// получают от края `PERMISSION_DENIED`, один на существующем и несуществующем
// `user_id`; свой фактор человек снимает кодом (`remove`, Р9).
//
// # Одна транзакция — писателя сессии, а не зеркала
//
// Строки `totp` (`active`) и `lookup_secret` сняты; ВСЕ сессии человека покрыты
// отсечкой (момент общего источника, kaname#589) с причиной `second-factor-reset` и актором — администратором облака
// (держатель украденного устройства мог держать и сессию); событие
// `iam.user.second_factor_reset` с обоими акторами — одним коммитом писателя
// хранилища сессий: у него есть и оператор снятия, и отсечка, и очередь аудита.
// Писатель зеркала здесь не участвует — строку личности глагол не трогает.
//
// # Что синхронно, а что в Operation
//
// Состояние строки судится ДО порождения Operation: «фактора нет» — строки
// нет либо только `pending` — отвечает `FAILED_PRECONDITION` с токеном
// `SECOND_FACTOR_NOT_ENROLLED` побайтово одинаково для обоих (снаружи они
// неразличимы — Р1: `pending` способом не является); `pending` не трогается,
// сессии не гасятся. Гонка с самостоятельным снятием между проверкой и записью
// разрешается оператором снятия: он снимает только `active`, и «нет» от него —
// исход Operation, без отсечки и события.
//
// # Чего глагол НЕ делает
//
// Не сбрасывает пароль, не заводит фактора за человека, не снимает блокировку.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// LoginMethodReader — чтение строки способа входа (узкий порт над хранилищем
// способов Ф2): состояние строки `totp` судится до порождения Operation.
type LoginMethodReader interface {
	// Get — NOT_FOUND, если способа этого вида у человека нет.
	Get(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error)
}

// SecondFactorResetStore — порт хранилища сессий для сброса: писатель одной
// транзакции. Реализует адаптер хранилища сессий (композиционный корень).
type SecondFactorResetStore interface {
	ResetWriter(ctx context.Context) (SecondFactorResetWriter, error)
}

// SecondFactorResetWriter — ровно то, что нужно сбросу: снятие обеих строк,
// отсечка, событие, фиксация.
type SecondFactorResetWriter interface {
	// RemoveSecondFactor снимает строку `totp` в состоянии `active` и строку
	// `lookup_secret`; false — строки `active` нет (ничего не снято).
	RemoveSecondFactor(ctx context.Context, userID domain.UserID) (bool, error)
	// UpsertCutoff — отсечка «все сессии человека до момента» (Ф-л).
	UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error
	// EmitAudit — событие в очередь аудита той же транзакцией.
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// ResetSecondFactorUseCase — сброс второго фактора администратором облака.
type ResetSecondFactorUseCase struct {
	repo     Repo
	opsRepo  operations.Repo
	methods  LoginMethodReader
	sessions SecondFactorResetStore
	// cutoffClock — ОБЩИЙ для всех реплик источник момента отсечки (kaname#589).
	cutoffClock revocationpolicy.Clock
}

// NewResetSecondFactorUseCase — построение. Источник момента отсечки подаёт
// корень ([ResetSecondFactorUseCase.WithCutoffClock]); без него снятие
// отказывает, а не берёт часы процесса.
func NewResetSecondFactorUseCase(r Repo, opsRepo operations.Repo, methods LoginMethodReader, sessions SecondFactorResetStore) *ResetSecondFactorUseCase {
	return &ResetSecondFactorUseCase{repo: r, opsRepo: opsRepo, methods: methods, sessions: sessions}
}

// WithCutoffClock провязывает источник момента отсечки. Composition-root only.
//
// Отсечка сравнивается с моментами, которые ставят другие реплики (вход,
// выдача удостоверения, `iat`), — источник у них обязан быть один (kaname#589).
func (u *ResetSecondFactorUseCase) WithCutoffClock(c revocationpolicy.Clock) *ResetSecondFactorUseCase {
	u.cutoffClock = c
	return u
}

// Execute — порядок: личность вызывающего → форма id → строка человека (промах
// контракт-тоном) → состояние строки `totp` → Operation → снятие одним коммитом.
func (u *ResetSecondFactorUseCase) Execute(ctx context.Context, id domain.UserID) (*operations.Operation, error) {
	// Порог «не аноним». КТО вправе сбросить — решает МОДЕЛЬ: край проверяет
	// `identity_suspender@iam_user:<user_id>` и пол «2» по записи каталога до
	// вызова службы (§«Авторизация живёт в МОДЕЛИ, а не в самодельных проверках»).
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
	enrolled, err := u.enrolled(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if !enrolled {
		return nil, notEnrolledRefusal()
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Reset second factor of user %s", id),
		&iamv1.ResetSecondFactorMetadata{UserId: string(id), AccountId: string(current.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doReset(ctx, current, actor)
	})
	return &op, nil
}

// enrolled — есть ли у человека строка `totp` в состоянии `active` (Р1).
func (u *ResetSecondFactorUseCase) enrolled(ctx context.Context, id domain.UserID) (bool, error) {
	row, err := u.methods.Get(ctx, id, domain.LoginMethodTOTP)
	switch {
	case err == nil:
		return row.Enrolled(), nil
	case errors.Is(err, iamerr.ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// doReset — снятие, отсечка и событие одним коммитом писателя сессии.
func (u *ResetSecondFactorUseCase) doReset(ctx context.Context, subject domain.User, actor string) (*anypb.Any, error) {
	// Момент отсечки — из общего источника и ДО открытия транзакции писателя:
	// источник читается своим соединением, и чтение изнутри открытой
	// транзакции брало бы второе соединение на запрос (kaname#589).
	now, err := revocationpolicy.Moment(ctx, u.cutoffClock)
	if err != nil {
		slog.ErrorContext(ctx, "ResetSecondFactor: cutoff moment unavailable",
			"step", "cutoff-moment", "class", revocationpolicy.MomentFailureClass(err))
		return nil, status.Error(codes.Unavailable, shared.MomentUnavailableMessage)
	}
	w, err := u.sessions.ResetWriter(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	removed, err := w.RemoveSecondFactor(ctx, subject.ID)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if !removed {
		// Строка `active` исчезла между проверкой и записью: человек снял сам.
		return nil, notEnrolledRefusal()
	}
	revokedBy := domain.UserID(actor)
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: subject.ID, RevokeBefore: now, Reason: domain.RevokeReasonSecondFactorReset, RevokedBy: revokedBy,
	}, revokedBy); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       auditEventUserSecondFactorReset,
		TenantAccountID: string(subject.AccountID),
		Payload: map[string]any{
			// КТО — проверенная личность администратора облака; КОГО — человек, чей
			// фактор снят. Ни адреса, ни имени: след без личных данных.
			"actor":   actor,
			"user_id": string(subject.ID),
			"reason":  domain.RevokeReasonSecondFactorReset,
		},
	}); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	committed = true
	return marshalUser(subject)
}

// notEnrolledRefusal — один отказ на «строки нет» и «только pending» (матрица
// Р4): FAILED_PRECONDITION, текст и токен — те же, что у глаголов полосы.
func notEnrolledRefusal() error {
	st := status.New(codes.FailedPrecondition, humansession.TextSecondFactorNotEnrolled)
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: humansession.ReasonSecondFactorNotEnrolled,
		Domain: refusaldomain.For(refusaldomain.ServiceIAM),
	})
	if derr != nil {
		return st.Err()
	}
	return withDetails.Err()
}
