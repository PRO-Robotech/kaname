// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// list_mine.go — ListMyMembershipsUseCase: страница членств ВЫЗЫВАЮЩЕГО
// (IAM-ID-2, стадия S2; `GET /iam/v1/me/memberships`).
//
// # ЕДИНСТВЕННЫЙ ВХОД — ЛИЧНОСТЬ ИЗ КОНТЕКСТА, И ЭТО РЕШЕНИЕ О ДОСТУПЕ
//
// Своё чтение объявлено полосой `scope_filtered`: край и собственная дверь
// единичного вопроса об объекте не задают, потому что объекта нет — субъект
// ответа ЕСТЬ вызывающий. Решение о доступе при этом не снято, а ПЕРЕНЕСЕНО
// сюда: человек берётся из принципала и уходит доводом запроса к хранилищу
// (`ListMine(ctx, userID, …)`), поэтому чужая строка не читается вовсе. Поля,
// которым можно было бы назвать другого человека, у запроса нет by construction
// (IAM-ID-2-09), и расширить сужение, не тронув контракт, нельзя.
//
// # Отказы — СИНХРОННЫЕ, до открытия чтения, и у каждого назван предмет
//
//   - без принципала — `UNAUTHENTICATED`, а не пустая страница: пустой ответ
//     читался бы как «членств нет» и скрыл бы отказ аутентификации
//     (IAM-ID-2-10). На пути через край и собственную дверь сюда без личности
//     не доходят; ветвь стоит как защита в глубину, а не как рубеж;
//   - машинная учётка — `FAILED_PRECONDITION`: членство — принадлежность
//     ЧЕЛОВЕКА, и ответить служебной учётке пустым перечнем значило бы
//     утверждать о предмете, которого у вопроса нет. Та же полоса, что у
//     чтения пределов личности (`identityquota`), — соседние чтения «про себя»
//     сверены между собой, а не решены порознь;
//   - негодная форма страницы — `INVALID_ARGUMENT`, тем же разбором, что
//     исполнится на пути чтения (IAM-ID-2-11).

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
)

// ErrMineNeedsAHuman — текст отказа машинной учётке; часть контракта.
const ErrMineNeedsAHuman = "memberships are readable by a user principal only"

type ListMyMembershipsUseCase struct{ repo Repo }

func NewListMyMembershipsUseCase(r Repo) *ListMyMembershipsUseCase {
	return &ListMyMembershipsUseCase{repo: r}
}

// Execute — страница членств вызывающего.
func (u *ListMyMembershipsUseCase) Execute(
	ctx context.Context, page repomembership.MinePage,
) ([]domain.Membership, string, error) {
	if err := shared.ValidatePagination(page.PageToken, page.PageSize); err != nil {
		return nil, "", err
	}
	userID, err := userIDOfAuthenticatedCaller(ctx)
	if err != nil {
		return nil, "", err
	}

	rd, closeFn, err := readerOf(ctx, u.repo)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer closeFn()

	rows, next, err := rd.ListMine(ctx, userID, page)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return rows, next, nil
}

// userIDOfAuthenticatedCaller — личность ВЫЗЫВАЮЩЕГО, и ничья больше.
//
// Шаг назван и вынесен не ради читаемости: он и есть доказательство сужения,
// которое читает страж списочных методов (`tools/auditlistfilter`, форма
// `SubjectScoped`). На входе только `ctx`, поэтому назвать чужую личность
// нечем, а расширить это, не тронув подписи, которую страж и читает, нельзя.
//
// Проверяется РОД принципала, а не только непустота идентификатора:
// `authzguard.PrincipalUserID` — accessor АУДИТНЫЙ и машинной учётке отдаёт
// `sva…`, а по такому идентификатору строк членства не бывает — вызывающий
// получил бы пустой перечень вместо ответа по существу.
func userIDOfAuthenticatedCaller(ctx context.Context) (domain.UserID, error) {
	if authzguard.IsAnonymous(ctx) {
		return "", status.Error(codes.Unauthenticated, "caller is not authenticated")
	}
	if p := operations.PrincipalFromContext(ctx); p.Type != "user" {
		return "", status.Error(codes.FailedPrecondition, ErrMineNeedsAHuman)
	}
	userID := authzguard.PrincipalUserID(ctx)
	if userID == "" {
		return "", status.Error(codes.FailedPrecondition, ErrMineNeedsAHuman)
	}
	return domain.UserID(userID), nil
}
