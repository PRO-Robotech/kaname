// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_by_subject.go — ListAccessBindingsBySubjectUseCase.
//
// Допуск и сужение здесь НЕ пишутся: и то и другое — общая политика обоих чтений
// выдач субъекта, и живёт она в subject_read_authority.go. Здесь остаётся форма
// чтения: страница курсором из своей базы, затем — для полосы распорядителя
// аккаунта — пообъектный вопрос модели прав о ТОЙ ЖЕ странице.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type ListBySubjectUseCase struct {
	repo Repo
	// relations — модель прав для полос надзора облака и делегированного
	// распорядителя; queries — пообъектный вопрос, которым сужается СТРАНИЦА.
	// Оба обязательны: непровязанный порт это чтение ОТКАЗЫВАЕТ, а не отдаёт
	// несуженный перечень.
	relations clients.RelationStore
	queries   clients.RelationQueries
	// logger — паритет формы провязки с соседними use-case'ами пакета; здесь не
	// читается, потому что решения этого чтения ничего не логируют.
	logger *slog.Logger
}

func NewListBySubjectUseCase(r Repo) *ListBySubjectUseCase {
	return &ListBySubjectUseCase{repo: r}
}

// WithRelationStore wires the rights model for the cluster-admin and delegated
// account-admin admission lanes.
func (u *ListBySubjectUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListBySubjectUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithRelationQueries wires the per-object question the PAGE is narrowed with.
func (u *ListBySubjectUseCase) WithRelationQueries(q clients.RelationQueries) *ListBySubjectUseCase {
	u.queries = q
	return u
}

func (u *ListBySubjectUseCase) Execute(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f repoab.PageFilter) ([]domain.AccessBinding, string, error) {
	// Допуск — ЕДИНЫМ предикатом, общим с ListSubjectPrivileges
	// (subject_read_authority.go). Прежде здесь стояло СВОЁ условие — «вызывающий
	// обязан БЫТЬ субъектом», — и оно расходилось с соседним глаголом: тот же
	// вопрос про того же субъекта получал разный ответ в зависимости от того,
	// какой глагол выбран (#1352).
	//
	// Существование субъекта это чтение НЕ сообщает вовсе: нерезолвящийся субъект
	// отвечает пустой страницей собственному чтению и `PermissionDenied` всякому
	// другому — тот же ответ, что и субъект в чужом аккаунте.
	dec, err := subjectReadAuthority(ctx, u.repo, u.relations, subjectType, subjectID)
	if err != nil {
		return nil, "", err
	}

	rows, next, err := readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().ListBySubject(ctx, subjectType, subjectID, f)
	})
	if err != nil {
		return nil, "", err
	}
	if !dec.lane.narrowsPage() {
		return rows, next, nil
	}

	// Полоса распорядителя аккаунта: строки называют ОБЛАСТЬ каждой выдачи, а
	// области у одного субъекта бывают в разных аккаунтах. Остаются те, чью выдачу
	// вызывающий вправе прочитать по идентификатору (#1354).
	visible, verr := visibleOnNarrowedPage(ctx, u.queries, bindingIDs(rows))
	if verr != nil {
		return nil, "", verr
	}
	return filterVisibleBindings(rows, visible), next, nil
}
