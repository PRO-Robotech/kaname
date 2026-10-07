// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package recipientdirectory — InternalNotificationRecipientService: справочник
// адресов получателей писем (приёмка NTF-3 Р7, Р28; замысел З27).
//
// Internal-only (запрет #6): служба регистрируется только на внутреннем
// слушателе, REST-привязок у контракта нет. Вызывающий — служебный принципал
// `service:notify` звена Р2; право — `reader` на
// `notification_recipient_directory:root` той же дверью, что отвечает
// `InternalIAMService/Check`.
package recipientdirectory

// ports.go — узкие порты use-case'ов. Адаптеры — internal/repo/kaname/pg,
// провязка — cmd/kaname. Ни pgx, ни grpc здесь нет.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// door — дверь решения kaname: та же функция вердикта, что отвечает
// `InternalIAMService/Check` (место Д-3). Через неё идут право вызывающего на
// справочник и право получателя на аккаунт (`account_reader`). Вопрос об
// аудитории версии события идёт НЕ дверью: дверь отвечает о праве сейчас, а
// аудитория — о праве, не менявшемся с токена события (eventAudienceReader).
// Реализуется *service.AuthorizeService.
type door interface {
	CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error)
}

// recipientReader — записи получателей. found == false — записи нет; любая
// иная ошибка — сбой чтения. Реализуется *kanamepg.RecipientDirectoryRepo.
type recipientReader interface {
	// ReadRecipient — запись получателя вида kind с идентификатором id.
	ReadRecipient(ctx context.Context, kind domain.RecipientKind, id string) (domain.RecipientRecord, bool, error)
	// ReadAccountOwner — id пользователя-владельца аккаунта.
	ReadAccountOwner(ctx context.Context, accountID string) (string, bool, error)
}

// eventAudienceReader — аудитория версии события (Р30). Реализуется
// *kanamepg.RecipientDirectoryRepo.
type eventAudienceReader interface {
	// ReadEventAudience — барьер поколения и страница аудитории ОДНИМ снимком
	// не старше токена. Исход, не являющийся страницей (поколение не применено,
	// токен новее снимка), — в Verdict, а не ошибкой; ошибка — сбой чтения.
	ReadEventAudience(ctx context.Context, q domain.EventAudienceQuestion) (domain.EventAudiencePage, error)
}
