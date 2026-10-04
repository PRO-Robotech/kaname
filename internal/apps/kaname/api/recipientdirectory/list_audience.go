// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// list_audience.go — ListProjectAudienceUseCase: субъекты-пользователи проекта
// (приёмка NTF-3 Р7, NTF3-117).
//
// Порядок несущий:
//  1. право вызывающего на справочник (caller.go);
//  2. пагинация — `page_size` вне [0..1000] и мусорный `page_token` — отказ с
//     именем поля, до остальной проверки входа и до чтения: мусорный курсор на
//     пустом результате — отказ, а не пустая страница;
//  3. `project_id`: пусто — `project_id: required` до формата; не по форме —
//     `invalid project id '<X>'`;
//  4. одно чтение: на элемент больше страницы — признак следующей страницы.
//
// Выдача — пользователи с действующей (не отозванной, не истёкшей) прямой
// привязкой на проект; группы не раскрываются, привязки аккаунта не входят,
// адресов нет. Порядок — по id пользователя по возрастанию, курсор — id
// последнего выданного (shared.AudienceCursor).

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corevalidate "github.com/PRO-Robotech/corelib/validate"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// AudiencePage — страница `ListProjectAudience`.
type AudiencePage struct {
	// Subjects — `user:<id>` по возрастанию id.
	Subjects []string
	// NextPageToken — пусто на странице с последним элементом выдачи.
	NextPageToken string
}

// ListProjectAudienceUseCase — аудитория проекта.
type ListProjectAudienceUseCase struct {
	gate     callerGate
	audience audienceReader
	logger   *slog.Logger
}

// NewListProjectAudienceUseCase — конструктор. logger обязателен.
func NewListProjectAudienceUseCase(d door, audience audienceReader, logger *slog.Logger) *ListProjectAudienceUseCase {
	return &ListProjectAudienceUseCase{gate: callerGate{door: d, logger: logger}, audience: audience, logger: logger}
}

// Execute — страница аудитории проекта projectID.
func (uc *ListProjectAudienceUseCase) Execute(ctx context.Context, projectID, pageToken string, pageSize int32) (AudiencePage, error) {
	if err := uc.gate.require(ctx, iamv1.InternalNotificationRecipientService_ListProjectAudience_FullMethodName); err != nil {
		return AudiencePage{}, err
	}
	size, err := corevalidate.PageSize("page_size", int64(pageSize))
	if err != nil {
		return AudiencePage{}, err
	}
	after, err := shared.DecodeDirectoryPageToken(shared.AudienceCursor, "page_token", pageToken)
	if err != nil {
		return AudiencePage{}, err
	}
	if projectID == "" {
		return AudiencePage{}, shared.InvalidArg("project_id", "project_id: required")
	}
	if err := corevalidate.ResourceID("project", "prj", projectID); err != nil {
		return AudiencePage{}, err
	}

	afterID := ""
	if after != nil {
		afterID = after.ID
	}
	limit := int(size)
	ids, err := uc.audience.ListProjectUsers(ctx, projectID, afterID, limit+1)
	if err != nil {
		uc.logger.ErrorContext(ctx, "recipient directory: project audience read failed", "err", err.Error())
		return AudiencePage{}, status.Error(codes.Unavailable, unavailableText)
	}
	page := AudiencePage{}
	if len(ids) > limit {
		ids = ids[:limit]
		page.NextPageToken = shared.EncodeDirectoryPageToken(shared.AudienceCursor,
			shared.DirectoryPosition{ID: ids[len(ids)-1]})
	}
	page.Subjects = make([]string, 0, len(ids))
	for _, id := range ids {
		page.Subjects = append(page.Subjects, "user:"+id)
	}
	return page, nil
}
