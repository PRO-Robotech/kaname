// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// resolve.go — ResolveUseCase: исход и адрес одного получателя (приёмка NTF-3
// Р7; замысел З27, CX3-14).
//
// Порядок несущий:
//  1. право вызывающего на справочник (caller.go) — до всего;
//  2. проверка входа целиком (input.go) — до любого вопроса к модели о праве
//     получателя;
//  3. получатель: аудитория `account_owner` сначала находит владельца
//     аккаунта (нет — `AUDIENCE_DENIED`); затем запись субъекта одним
//     оператором: нет — `SUBJECT_NOT_FOUND`, пользователь не ACTIVE —
//     `SUBJECT_INACTIVE`;
//  4. аудитория `resource` — вопрос `v_get` о каждой ссылке той же дверью, что
//     отвечает `InternalIAMService/Check`; ни одна не видна — `AUDIENCE_DENIED`;
//  5. подтверждённый адрес: учётная запись службы либо неподтверждённый адрес —
//     `NO_CONFIRMED_ADDRESS`; иначе `ADDRESS` с видимым подмножеством ссылок.
//
// Вопрос о праве (шаг 4) стоит раньше выдачи адреса (шаг 5) в той же функции:
// адрес не выдаётся субъекту, которому ресурс не виден. Дверь не допускает к
// решению человека с неподтверждённым адресом (kaname#456, Р4а) и называет
// причину `email_not_verified`; такой отказ говорит об адресе, а не об
// аудитории, и даёт `NO_CONFIRMED_ADDRESS` — исход, который шаг 5 дал бы ему
// всё равно.
//
// Ответ-отказ не несёт ни адреса, ни признака подтверждения. Журнал — без
// адреса: только исход.

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// unavailableText — сбой чтения хранилища kaname: фиксированный текст без
// текста драйвера.
const unavailableText = "notification recipient directory temporarily unavailable"

// ResolveResult — исход `Resolve`. Address и Visible заполнены только при
// domain.RecipientAddress.
type ResolveResult struct {
	Outcome domain.RecipientOutcome
	Address string
	// Visible — видимое подмножество ссылок запроса, в порядке запроса.
	Visible []ResourceRef
}

// ResolveUseCase — справочник адресов: один получатель.
type ResolveUseCase struct {
	gate       callerGate
	door       door
	recipients recipientReader
	logger     *slog.Logger
}

// NewResolveUseCase — конструктор. logger обязателен.
func NewResolveUseCase(d door, recipients recipientReader, logger *slog.Logger) *ResolveUseCase {
	return &ResolveUseCase{
		gate:       callerGate{door: d, logger: logger},
		door:       d,
		recipients: recipients,
		logger:     logger,
	}
}

// Execute — исход получателя запроса req.
func (uc *ResolveUseCase) Execute(ctx context.Context, req ResolveRequest) (ResolveResult, error) {
	if err := uc.gate.require(ctx, iamv1.InternalNotificationRecipientService_Resolve_FullMethodName); err != nil {
		return ResolveResult{}, err
	}
	if err := req.validate(); err != nil {
		return ResolveResult{}, err
	}

	subject := req.Subject
	if req.Audience == AudienceAccountOwner {
		owner, found, err := uc.recipients.ReadAccountOwner(ctx, req.AccountID)
		if err != nil {
			return ResolveResult{}, uc.unavailable(ctx, "account owner", err)
		}
		if !found {
			return outcome(domain.RecipientAudienceDenied), nil
		}
		subject = "user:" + owner
	}

	kind, id, known := recipientOf(subject)
	if !known {
		return outcome(domain.RecipientSubjectNotFound), nil
	}
	rec, found, err := uc.recipients.ReadRecipient(ctx, kind, id)
	if err != nil {
		return ResolveResult{}, uc.unavailable(ctx, "recipient", err)
	}
	if !found {
		return outcome(domain.RecipientSubjectNotFound), nil
	}
	if kind == domain.RecipientKindUser && !rec.Active {
		return outcome(domain.RecipientSubjectInactive), nil
	}

	var visible []ResourceRef
	if req.Audience == AudienceResource {
		var notAdmitted bool
		visible, notAdmitted, err = uc.visibleRefs(ctx, subject, req.Relation, req.Refs)
		if err != nil {
			return ResolveResult{}, err
		}
		if len(visible) == 0 {
			if notAdmitted {
				return outcome(domain.RecipientNoConfirmedAddress), nil
			}
			return outcome(domain.RecipientAudienceDenied), nil
		}
	}

	if !rec.HasConfirmedAddress(kind) {
		return outcome(domain.RecipientNoConfirmedAddress), nil
	}
	return ResolveResult{Outcome: domain.RecipientAddress, Address: rec.Email, Visible: visible}, nil
}

// visibleRefs — ссылки, на которые у subject есть relation, в порядке запроса.
// notAdmitted — дверь не допустила субъекта к решению по неподтверждённому
// адресу (тогда видимых нет). Дверь не ответила — UNAVAILABLE.
func (uc *ResolveUseCase) visibleRefs(ctx context.Context, subject, relation string, refs []ResourceRef) (
	visible []ResourceRef, notAdmitted bool, err error,
) {
	for _, ref := range refs {
		verdict, err := uc.door.CheckRelation(ctx, service.CheckRelationRequest{
			Subject:  subject,
			Relation: relation,
			Object:   ref.String(),
		})
		if err != nil {
			uc.logger.ErrorContext(ctx, "recipient directory: audience question unanswered", "err", err.Error())
			return nil, false, authzguard.AuthzBackendUnavailable()
		}
		if verdict == nil {
			continue
		}
		if verdict.Allowed {
			visible = append(visible, ref)
			continue
		}
		for _, reason := range verdict.DenyReasons {
			if reason == service.DenyReasonEmailNotVerified {
				notAdmitted = true
			}
		}
	}
	return visible, notAdmitted, nil
}

// unavailable — сбой чтения хранилища: в журнал — причина, наружу —
// фиксированный текст.
func (uc *ResolveUseCase) unavailable(ctx context.Context, what string, err error) error {
	uc.logger.ErrorContext(ctx, "recipient directory: read failed", "what", what, "err", err.Error())
	return status.Error(codes.Unavailable, unavailableText)
}

// outcome — исход по субъекту: ни адреса, ни ссылок.
func outcome(o domain.RecipientOutcome) ResolveResult { return ResolveResult{Outcome: o} }

// recipientOf — вид и id субъекта `user:<id>` либо `service_account:<id>`.
// Иной вид адресатом письма не бывает: known == false.
func recipientOf(subject string) (domain.RecipientKind, string, bool) {
	kind, id, ok := strings.Cut(subject, ":")
	if !ok || id == "" {
		return 0, "", false
	}
	switch kind {
	case "user":
		return domain.RecipientKindUser, id, true
	case "service_account":
		return domain.RecipientKindServiceAccount, id, true
	default:
		return 0, "", false
	}
}
