// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// list_event_audience.go — ListEventAudienceUseCase: аудитория версии события
// ресурса (приёмка NTF-3 Р7, Р30; NTF3-165…171, 174, 176…178, 181, 183).
//
// Порядок несущий:
//  1. право вызывающего на справочник (caller.go);
//  2. пагинация — `page_size` вне [0..1000] и мусорный `page_token` — отказ с
//     именем поля, до остальной проверки входа и до чтения: мусорный курсор на
//     непримененном поколении — отказ курсора, а не барьер (NTF3-171 (в));
//  3. обязательность `object`, `source_version`, `authz_rev` — до формы;
//  4. форма и тип `object` (тип ресурса модуля), форма токена и цепей;
//  5. одно чтение одним снимком: барьер поколения, затем аудитория с оградой;
//     на элемент больше страницы — признак следующей страницы.
//
// Выдача — пользователи `user:<id>`, чьё право читать объект есть и не менялось
// с токена события; адресов нет. Порядок — по id пользователя по возрастанию,
// курсор — id последнего выданного (shared.EventAudienceCursor).

import (
	"context"
	"log/slog"
	"strings"

	corevalidate "github.com/PRO-Robotech/corelib/validate"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// subjectUserPrefix — форма субъекта аудитории.
const subjectUserPrefix = "user:"

// AudiencePage — страница `ListEventAudience`.
type AudiencePage struct {
	// Subjects — `user:<id>` по возрастанию id.
	Subjects []string
	// NextPageToken — пусто на странице с последним элементом выдачи.
	NextPageToken string
}

// ListEventAudienceUseCase — аудитория версии события.
type ListEventAudienceUseCase struct {
	gate     callerGate
	audience eventAudienceReader
	logger   *slog.Logger
}

// NewListEventAudienceUseCase — конструктор. logger обязателен.
func NewListEventAudienceUseCase(d door, audience eventAudienceReader, logger *slog.Logger) *ListEventAudienceUseCase {
	return &ListEventAudienceUseCase{gate: callerGate{door: d, logger: logger}, audience: audience, logger: logger}
}

// Execute — страница аудитории версии события e.
func (uc *ListEventAudienceUseCase) Execute(ctx context.Context, e EventRef, pageToken string, pageSize int32) (AudiencePage, error) {
	if err := uc.gate.require(ctx, iamv1.InternalNotificationRecipientService_ListEventAudience_FullMethodName); err != nil {
		return AudiencePage{}, err
	}
	size, err := corevalidate.PageSize("page_size", int64(pageSize))
	if err != nil {
		return AudiencePage{}, err
	}
	after, err := shared.DecodeDirectoryPageToken(shared.EventAudienceCursor, "page_token", pageToken)
	if err != nil {
		return AudiencePage{}, err
	}
	if err := e.required(""); err != nil {
		return AudiencePage{}, err
	}
	if err := e.validateForm("", eventObjectType, "is not a resource type of a published kind"); err != nil {
		return AudiencePage{}, err
	}

	objectType, objectID := e.split()
	q := domain.EventAudienceQuestion{
		ObjectType: objectType, ObjectID: objectID, Generation: e.Generation,
		AuthzRev: e.AuthzRev, Facts: e.Facts, Limit: int(size) + 1,
	}
	if after != nil {
		q.AfterSubject = subjectUserPrefix + after.ID
	}
	subjects, err := readAudience(ctx, uc.audience, uc.logger, q, "authz_rev")
	if err != nil {
		return AudiencePage{}, err
	}
	page := AudiencePage{}
	if len(subjects) > int(size) {
		subjects = subjects[:size]
		last := strings.TrimPrefix(subjects[len(subjects)-1], subjectUserPrefix)
		page.NextPageToken = shared.EncodeDirectoryPageToken(shared.EventAudienceCursor,
			shared.DirectoryPosition{ID: last})
	}
	page.Subjects = subjects
	if page.Subjects == nil {
		page.Subjects = []string{}
	}
	return page, nil
}
