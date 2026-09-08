// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// basicCredentialResolver — порт авторитета. Реализуется репозиторием
// (`repo/kaname/pg.BasicCredentialRepo`), инжектится в композиционном корне.
type basicCredentialResolver interface {
	ResolveBasic(ctx context.Context, presented string) (domain.BasicCredential, error)
	TouchLastUsed(ctx context.Context, credentialID string, throttle time.Duration) error
	// CheckBasicLive — тот же предикат живости, спрошенный по идентификатору,
	// без предъявления секрета (#1450). Порт ОДИН на оба вопроса намеренно:
	// второй порт об одном предмете дал бы возможность провязать один вопрос и
	// не провязать другой — молча и ровно на том стенде, где это заметить
	// некому.
	CheckBasicLive(ctx context.Context, credentialID string) error
}

// lastUsedThrottle — дроссель записи отметки предъявления. Равен окну вердикта
// края (5 с), и ВТОРОЙ ручки под него не заводится: промах кэша и есть момент,
// когда отметку можно обновить, поэтому более частый дроссель недостижим by
// construction.
const lastUsedThrottle = 5 * time.Second

// WithBasicCredentialResolver провязывает авторитет о предъявленном базовом
// секрете. nil → глагол отвечает Unavailable (fail-closed): «состояние
// удостоверения не установлено» — это НЕ отказ в удостоверении, и подменять
// один другим значило бы предлагать вызывающему исправить то, чего он
// исправить не может.
func (h *Handler) WithBasicCredentialResolver(r basicCredentialResolver) *Handler {
	h.basicCredentials = r
	return h
}

// ResolveBasicCredential — вердикт о предъявленном базовом секрете.
//
// ОТКАЗ ЕДИНЫЙ (§10 приёмки BAT-1). Неизвестный идентификатор, неверный секрет,
// истёкший срок, отозванное удостоверение, неактивный владелец — один и тот же
// код и один и тот же текст. Различимость живёт ВНУТРЬ: в счётчике причин и в
// журнале, не в том, что видит предъявитель.
func (h *Handler) ResolveBasicCredential(
	ctx context.Context, req *iamv1.ResolveBasicCredentialRequest,
) (*iamv1.ResolveBasicCredentialResponse, error) {
	if h.basicCredentials == nil {
		return nil, status.Error(codes.Unavailable, "basic credential authority is not wired")
	}
	if req.GetPresented() == "" {
		// Пустой вход отвергается тем же единым отказом: «поле не заполнено» и
		// «удостоверение негодно» различимы для клиента только тем, что первое
		// подсказывает форму — а форму подсказывать нечему, вход и есть строка.
		return nil, status.Error(codes.Unauthenticated, refusalText)
	}

	cred, err := h.basicCredentials.ResolveBasic(ctx, req.GetPresented())
	switch {
	case errors.Is(err, domain.ErrBasicCredentialRefused):
		return nil, status.Error(codes.Unauthenticated, refusalText)
	case err != nil:
		// Недоступность авторитета — ОТДЕЛЬНЫЙ исход и наружу тоже. Сырой текст
		// драйвера не течёт: он ЛОГИРУЕТСЯ, а на провод уходит фиксированное.
		if h.logger != nil {
			h.logger.ErrorContext(ctx, "basic credential authority failed",
				slog.Any("error", err))
		}
		return nil, status.Error(codes.Unavailable, credentialStateUnknownText)
	}

	// Отметка предъявления обновляется ЗДЕСЬ — на промахе кэша края, а не на
	// каждом запросе: иначе чтение превращается в запись на горячем пути.
	// Одним оператором с предикатом дросселя, не «прочитать и записать».
	if terr := h.basicCredentials.TouchLastUsed(ctx, cred.CredentialID, lastUsedThrottle); terr != nil && h.logger != nil {
		// Отметка — наблюдаемость, а не контроль: её сбой не отменяет вердикта.
		h.logger.WarnContext(ctx, "last-used touch failed", slog.Any("error", terr))
	}

	resp := &iamv1.ResolveBasicCredentialResponse{
		PrincipalType: cred.PrincipalType,
		PrincipalId:   cred.PrincipalID,
		DisplayName:   cred.DisplayName,
		CredentialId:  cred.CredentialID,
	}
	if !cred.ExpiresAt.IsZero() {
		resp.ExpiresAt = timestamppb.New(cred.ExpiresAt.Truncate(time.Second))
	}
	return resp, nil
}

// refusalText — ЕДИНСТВЕННЫЙ текст отказа полосы. Объявлен одним местом: два
// написания разошлись бы, и по различию узнавали бы причину.
const refusalText = "credential refused"
