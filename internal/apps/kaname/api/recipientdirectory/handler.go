// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// handler.go — тонкий gRPC-транспорт InternalNotificationRecipientService:
// разбор запроса → use-case → ответ. Регистрируется ТОЛЬКО на внутреннем
// слушателе (запрет #6).

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Handler реализует iamv1.InternalNotificationRecipientServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalNotificationRecipientServiceServer

	resolve  *ResolveUseCase
	audience *ListEventAudienceUseCase
}

// NewHandler — сборка из двух use-case'ов. Композиционный корень — cmd/kaname.
func NewHandler(resolve *ResolveUseCase, audience *ListEventAudienceUseCase) *Handler {
	return &Handler{resolve: resolve, audience: audience}
}

// Resolve — исход и адрес одного получателя.
func (h *Handler) Resolve(ctx context.Context, req *iamv1.ResolveRecipientRequest) (*iamv1.ResolveRecipientResponse, error) {
	res, err := h.resolve.Execute(ctx, resolveRequestOf(req))
	if err != nil {
		return nil, err
	}
	resp := &iamv1.ResolveRecipientResponse{Outcome: outcomeToProto(res.Outcome)}
	if res.Outcome == domain.RecipientAddress {
		resp.Address = res.Address
	}
	return resp, nil
}

// ListEventAudience — страница аудитории версии события.
func (h *Handler) ListEventAudience(ctx context.Context, req *iamv1.ListEventAudienceRequest) (*iamv1.ListEventAudienceResponse, error) {
	e := EventRef{
		Object: req.GetObject(), Generation: req.GetSourceVersion(), AuthzRev: req.GetAuthzRev(),
		Facts: factsOf(req.GetFacts()),
	}
	page, err := h.audience.Execute(ctx, e, req.GetPageToken(), req.GetPageSize())
	if err != nil {
		return nil, err
	}
	return &iamv1.ListEventAudienceResponse{Subjects: page.Subjects, NextPageToken: page.NextPageToken}, nil
}

// resolveRequestOf — вход use-case'а из сообщения контракта.
func resolveRequestOf(req *iamv1.ResolveRecipientRequest) ResolveRequest {
	out := ResolveRequest{Namespace: req.GetNamespace(), Subject: req.GetSubject()}
	switch a := req.GetAudience().(type) {
	case *iamv1.ResolveRecipientRequest_Event:
		out.Audience = AudienceEvent
		out.Event = EventRef{
			Object: a.Event.GetObject(), Generation: a.Event.GetSourceVersion(), AuthzRev: a.Event.GetAuthzRev(),
			Facts: factsOf(a.Event.GetFacts()),
		}
		out.ViaSubscription = a.Event.GetViaSubscription()
	case *iamv1.ResolveRecipientRequest_Self:
		out.Audience = AudienceSelf
	case *iamv1.ResolveRecipientRequest_AccountReader:
		out.Audience = AudienceAccountReader
		out.AccountID = a.AccountReader.GetAccountId()
	case *iamv1.ResolveRecipientRequest_AccountOwner:
		out.Audience = AudienceAccountOwner
		out.AccountID = a.AccountOwner.GetAccountId()
	default:
		out.Audience = AudienceUnset
	}
	return out
}

// factsOf — факты события из сообщения контракта (nil — фактов нет).
func factsOf(f *iamv1.RecipientEventFacts) domain.EventFacts {
	return domain.EventFacts{
		ProjectID:           f.GetProjectId(),
		AccountID:           f.GetAccountId(),
		Labels:              f.GetLabels(),
		ParentChain:         f.GetParentChain(),
		PreviousLabels:      f.GetPreviousLabels(),
		PreviousParentChain: f.GetPreviousParentChain(),
	}
}

func outcomeToProto(o domain.RecipientOutcome) iamv1.RecipientOutcome {
	switch o {
	case domain.RecipientAddress:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_ADDRESS
	case domain.RecipientSubjectNotFound:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_SUBJECT_NOT_FOUND
	case domain.RecipientSubjectInactive:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_SUBJECT_INACTIVE
	case domain.RecipientAudienceDenied:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED
	case domain.RecipientNoConfirmedAddress:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_NO_CONFIRMED_ADDRESS
	case domain.RecipientOutcomeUnspecified:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_UNSPECIFIED
	default:
		return iamv1.RecipientOutcome_RECIPIENT_OUTCOME_UNSPECIFIED
	}
}
