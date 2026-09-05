// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
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
	// Формат страницы — ПЕРВЫМ стейтментом и в ТОЙ ЖЕ функции, которая ниже
	// замыкается допуском (#1437). Вопрос «правильно ли составлен запрос» имеет
	// ОДИН ответ для всех вызывающих, поэтому отвечать на него надо раньше, чем
	// на вопрос «что этому вызывающему видно»: иначе один и тот же мусорный
	// курсор получает `InvalidArgument` тому, у кого полоса есть, и
	// `PermissionDenied` тому, у кого её нет.
	//
	// Проверка стоит ЗДЕСЬ, а не только в хендлере, потому что требование
	// локальное: страж у одного вызывающего не защищает второго вызывающего той
	// же функции, а «репозиторий провалидирует» верно ровно для того пути,
	// который до репозитория доходит, — замыкание до него не доходит by
	// construction. Соседний глагол того же чтения (ListSubjectPrivileges) нёс
	// эту проверку, а здесь её не было: полосы одного механизма обязаны
	// сверяться между собой (`architecture.md`).
	//
	// Разбор — ТОТ ЖЕ, что исполняется на пути чтения (`pagetoken` внутри
	// `shared.ValidatePagination`): второй кодек курсора разошёлся бы с первым
	// молча и ровно там, где расхождение не видно — на валидном входе оба
	// отвечают «валидно».
	if err := shared.ValidatePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}

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
