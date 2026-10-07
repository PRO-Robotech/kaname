// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// audience.go — вопрос об аудитории версии события (Р30) и его отказы кодом,
// общие для `ListEventAudience` и `Resolve{event}`.
//
// Отказ кодом — не исход по субъекту: ответа на вопрос нет, и `notify`
// откладывает строку (Р7, таблица «Отказ вызова справочника»):
//
//	поколение не применено    UNAVAILABLE      reason OBJECT_GENERATION_NOT_APPLIED
//	токен новее снимка        INVALID_ARGUMENT поле authz_rev
//	сбой чтения хранилища     UNAVAILABLE      фиксированный текст, без reason

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// reasonGenerationNotApplied — машинный признак барьера поколения (Р7, Р30).
const reasonGenerationNotApplied = "OBJECT_GENERATION_NOT_APPLIED"

// readAudience — страница аудитории либо отказ кодом. field — путь поля токена
// в сообщении запроса.
func readAudience(ctx context.Context, reader eventAudienceReader, logger *slog.Logger,
	q domain.EventAudienceQuestion, authzRevField string,
) ([]string, error) {
	page, err := reader.ReadEventAudience(ctx, q)
	if err != nil {
		logger.ErrorContext(ctx, "recipient directory: event audience read failed", "err", err.Error())
		return nil, status.Error(codes.Unavailable, unavailableText)
	}
	switch page.Verdict {
	case domain.EventAudienceAnswered:
		return page.Subjects, nil
	case domain.EventAudienceGenerationNotApplied:
		return nil, generationNotApplied(q.ObjectType+":"+q.ObjectID, q.Generation)
	case domain.EventAudienceTokenAhead:
		return nil, shared.InvalidArg(authzRevField,
			authzRevField+": not an authorization revision issued by this service")
	default:
		logger.ErrorContext(ctx, "recipient directory: unknown event audience verdict", "verdict", int(page.Verdict))
		return nil, status.Error(codes.Unavailable, unavailableText)
	}
}

// generationNotApplied — барьер поколения: служба доступа ждёт, а не угадывает.
func generationNotApplied(object string, generation int64) error {
	st := status.New(codes.Unavailable,
		fmt.Sprintf("generation %d of %s is not applied yet", generation, object))
	enriched, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reasonGenerationNotApplied,
		Domain:   refusaldomain.For(refusaldomain.ServiceIAM),
		Metadata: map[string]string{"object": object, "generation": fmt.Sprintf("%d", generation)},
	})
	if err != nil {
		return st.Err()
	}
	return enriched.Err()
}
