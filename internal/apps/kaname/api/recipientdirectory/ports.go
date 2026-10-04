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
// `InternalIAMService/Check` (место Д-3). Через неё идут оба вопроса
// справочника: право вызывающего на справочник и право получателя на ресурс.
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

// audienceReader — аудитория проекта. Реализуется *kanamepg.RecipientDirectoryRepo.
type audienceReader interface {
	// ListProjectUsers — id пользователей с действующей прямой привязкой на
	// проект projectID, строго больше afterID, по возрастанию, не больше limit.
	ListProjectUsers(ctx context.Context, projectID, afterID string, limit int) ([]string, error)
}
