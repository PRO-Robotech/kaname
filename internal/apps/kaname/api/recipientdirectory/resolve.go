// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// resolve.go — ResolveUseCase: исход и адрес одного получателя (приёмка NTF-3
// Р7, Р30; замысел З27, CX3-14).
//
// Порядок несущий:
//  1. право вызывающего на справочник (caller.go) — до всего;
//  2. проверка входа целиком (input.go) — до любого вопроса об аудитории;
//  3. аудитория `event` — вопрос о членстве субъекта в аудитории версии события
//     с оградой токена (audience.go): непримененное поколение — отказ кодом
//     `UNAVAILABLE` `OBJECT_GENERATION_NOT_APPLIED`, а не исход по субъекту
//     (Р7: «ждём, не угадываем»), поэтому он стоит раньше исходов;
//  4. получатель: аудитория `account_owner` сначала находит владельца
//     аккаунта (нет — `AUDIENCE_DENIED`); затем запись субъекта одним
//     оператором: нет — `SUBJECT_NOT_FOUND`, пользователь не ACTIVE —
//     `SUBJECT_INACTIVE`;
//  5. аудитория: `event` — субъекта нет в ответе шага 3; `account_reader` —
//     вопрос `v_get` на `account:<id>` той же дверью, что отвечает
//     `InternalIAMService/Check` (контакт не событие: ограды нет); не входит —
//     `AUDIENCE_DENIED`;
//  6. подтверждённый адрес: учётная запись службы либо неподтверждённый адрес —
//     `NO_CONFIRMED_ADDRESS`; иначе `ADDRESS`.
//
// Вопрос об аудитории (шаг 5) стоит раньше выдачи адреса (шаг 6) в той же
// функции: адрес не выдаётся субъекту вне аудитории. Дверь не допускает к
// решению человека с неподтверждённым адресом (kaname#456, Р4а) и называет
// причину `email_not_verified`; такой отказ говорит об адресе, а не об
// аудитории, и даёт `NO_CONFIRMED_ADDRESS` — исход, который шаг 6 дал бы ему
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

// ResolveResult — исход `Resolve`. Address заполнен только при
// domain.RecipientAddress.
type ResolveResult struct {
	Outcome domain.RecipientOutcome
	Address string
}

// ResolveUseCase — справочник адресов: один получатель.
type ResolveUseCase struct {
	gate       callerGate
	door       door
	recipients recipientReader
	audience   eventAudienceReader
	logger     *slog.Logger
}

// NewResolveUseCase — конструктор. logger обязателен.
func NewResolveUseCase(d door, recipients recipientReader, audience eventAudienceReader, logger *slog.Logger) *ResolveUseCase {
	return &ResolveUseCase{
		gate:       callerGate{door: d, logger: logger},
		door:       d,
		recipients: recipients,
		audience:   audience,
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

	inEventAudience := false
	if req.Audience == AudienceEvent {
		objectType, objectID := req.Event.split()
		member, err := readAudience(ctx, uc.audience, uc.logger, domain.EventAudienceQuestion{
			ObjectType: objectType, ObjectID: objectID, Generation: req.Event.Generation,
			AuthzRev: req.Event.AuthzRev, Facts: req.Event.Facts,
			ViaSubscription: req.ViaSubscription, Subject: req.Subject, Limit: 1,
		}, "audience.event.authz_rev")
		if err != nil {
			return ResolveResult{}, err
		}
		inEventAudience = len(member) == 1 && member[0] == req.Subject
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

	switch req.Audience {
	case AudienceEvent:
		if !inEventAudience {
			return outcome(domain.RecipientAudienceDenied), nil
		}
	case AudienceAccountReader:
		reads, notAdmitted, err := uc.readsAccount(ctx, subject, req.AccountID)
		if err != nil {
			return ResolveResult{}, err
		}
		if !reads {
			if notAdmitted {
				return outcome(domain.RecipientNoConfirmedAddress), nil
			}
			return outcome(domain.RecipientAudienceDenied), nil
		}
	case AudienceUnset, AudienceSelf, AudienceAccountOwner:
	}

	if !rec.HasConfirmedAddress(kind) {
		return outcome(domain.RecipientNoConfirmedAddress), nil
	}
	return ResolveResult{Outcome: domain.RecipientAddress, Address: rec.Email}, nil
}

// relationAccountReader — право контакта безопасности на аккаунт (Р19, Р20).
const relationAccountReader = "v_get"

// readsAccount — у subject есть `v_get` на `account:<accountID>`. notAdmitted —
// дверь не допустила субъекта к решению по неподтверждённому адресу. Дверь не
// ответила — UNAVAILABLE.
func (uc *ResolveUseCase) readsAccount(ctx context.Context, subject, accountID string) (reads, notAdmitted bool, err error) {
	verdict, err := uc.door.CheckRelation(ctx, service.CheckRelationRequest{
		Subject:  subject,
		Relation: relationAccountReader,
		Object:   "account:" + accountID,
	})
	if err != nil {
		uc.logger.ErrorContext(ctx, "recipient directory: account reader question unanswered", "err", err.Error())
		return false, false, authzguard.AuthzBackendUnavailable()
	}
	if verdict == nil {
		return false, false, nil
	}
	if verdict.Allowed {
		return true, false, nil
	}
	for _, reason := range verdict.DenyReasons {
		if reason == service.DenyReasonEmailNotVerified {
			notAdmitted = true
		}
	}
	return false, notAdmitted, nil
}

// unavailable — сбой чтения хранилища: в журнал — причина, наружу —
// фиксированный текст.
func (uc *ResolveUseCase) unavailable(ctx context.Context, what string, err error) error {
	uc.logger.ErrorContext(ctx, "recipient directory: read failed", "what", what, "err", err.Error())
	return status.Error(codes.Unavailable, unavailableText)
}

// outcome — исход по субъекту: без адреса.
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
