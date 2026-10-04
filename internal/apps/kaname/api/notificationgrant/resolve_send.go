// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package notificationgrant

// resolve_send.go — ResolveSendUseCase: решение о письме строки ленты
// (приёмка NTF-1 Р5; замысел З18, CX1-06…CX1-08, CX1-110).
//
// Порядок несущий:
//  1. форма входа — первым шагом, до вопроса о праве;
//  2. субъект вызывающего — `authz.CallerSubject` (служебный субъект звена Р2
//     либо пересланный доверенным принципал). Субъекта нет — отказ СРАЗУ:
//     дверь не спрашивается, запись выдачи не читается;
//  3. право — `reader` на `notification_feed:<namespace>` той же дверью, что
//     отвечает `InternalIAMService/Check`. Отношения нет — тот же отказ,
//     запись выдачи не читается;
//  4. запись выдачи и запись шаблона — одним оператором; сбой чтения —
//     UNAVAILABLE фиксированным текстом, а не «права ещё нет»;
//  5. решение — чистая функция домена на полной точности.
//
// Перехватчика проверки прав для метода нет: решение — одно место, здесь.

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/authz"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	// relationFeedReader — отношение модели: право забрать тело письма.
	relationFeedReader = "reader"
	// objectTypeFeed — тип объекта модели: лента уведомлений пространства.
	objectTypeFeed = "notification_feed"
)

// ResolveSendUseCase — решение о письме.
type ResolveSendUseCase struct {
	reader grantStateReader
	door   feedReaderDoor
	// guard — полоса `notifications.cutoff-guard` (Р5): строка, поставленная
	// раньше отсечки плюс полоса, — REVOKED.
	guard  time.Duration
	logger *slog.Logger
}

// NewResolveSendUseCase — конструктор. Полосу судит строитель службы.
func NewResolveSendUseCase(reader grantStateReader, door feedReaderDoor, guard time.Duration, logger *slog.Logger) *ResolveSendUseCase {
	return &ResolveSendUseCase{reader: reader, door: door, guard: guard, logger: logger}
}

// Execute — решение о строке (namespace, template, enqueuedAt). enqueuedAt nil —
// поле не задано.
func (uc *ResolveSendUseCase) Execute(ctx context.Context, namespace, template string, enqueuedAt *time.Time) (domain.SendDecision, error) {
	if err := validateNamespace(namespace); err != nil {
		return domain.SendDecisionUnspecified, err
	}
	if err := validateTemplate(template); err != nil {
		return domain.SendDecisionUnspecified, err
	}
	if enqueuedAt == nil {
		return domain.SendDecisionUnspecified, fieldRefusal("enqueued_at", "enqueued_at: required")
	}

	caller, named := authz.CallerSubject(ctx)
	if !named {
		return domain.SendDecisionUnspecified, denied()
	}
	verdict, err := uc.door.CheckRelation(ctx, service.CheckRelationRequest{
		Subject:  caller.Subject(),
		Relation: relationFeedReader,
		Object:   objectTypeFeed + ":" + namespace,
	})
	if err != nil {
		return domain.SendDecisionUnspecified, authzguard.AuthzBackendUnavailable()
	}
	if verdict == nil || !verdict.Allowed {
		return domain.SendDecisionUnspecified, denied()
	}

	st, found, err := uc.reader.ReadSendState(ctx, namespace, template)
	if err != nil {
		if uc.logger != nil {
			uc.logger.ErrorContext(ctx, "notification grant read failed", "namespace", namespace, "err", err.Error())
		}
		return domain.SendDecisionUnspecified, status.Error(codes.Unavailable, unavailableText)
	}
	return domain.DecideSend(found, st, *enqueuedAt, uc.guard), nil
}

// denied — отказ обеих ветвей права: один текст и одна причина.
func denied() error {
	return authzguard.HandlerDecidedDenial(iamv1.InternalNotificationGrantService_ResolveSend_FullMethodName)
}
