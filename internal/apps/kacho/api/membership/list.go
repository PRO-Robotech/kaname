// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// list.go — ListMembershipsUseCase: страница членств НАЗВАННОГО аккаунта.

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repomembership "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/membership"
)

type ListMembershipsUseCase struct{ repo Repo }

func NewListMembershipsUseCase(r Repo) *ListMembershipsUseCase {
	return &ListMembershipsUseCase{repo: r}
}

// Execute — страница членств одного аккаунта.
//
// # ПОРЯДОК: ФОРМА РАНЬШЕ ВСЕГО ОСТАЛЬНОГО, И ЭТО В ЭТОЙ ЖЕ ФУНКЦИИ
//
// Вопрос «правильно ли составлен запрос» имеет ОДИН ответ для всех вызывающих,
// поэтому отвечать на него надо раньше, чем на любой другой. Проверка стоит
// здесь, а не только в адаптере: путь, который до адаптера не доходит, её бы не
// исполнил, и один и тот же мусорный курсор получал бы разный ответ в
// зависимости от того, что вызывающему выдано.
//
// Разбор курсора зовётся ТОТ ЖЕ, что исполняется на пути чтения: второго кодека
// не заводится — он разошёлся бы с первым молча, потому что на валидном входе
// оба отвечают «валидно».
//
// # ПОЛОС СУЖЕНИЯ НА ДАННЫХ ЗДЕСЬ НЕТ, И ЭТО УТВЕРЖДЕНИЕ, А НЕ УМОЛЧАНИЕ
//
// Страница не фильтруется пообъектно правами вызывающего, потому что фильтровать
// нечего: строки уже отобраны по аккаунту из пути, а право на этот аккаунт край
// проверил ДО вызова. Замыкания по личности здесь нет ни одного — значит и
// порядка «формат раньше замыкания» нарушить нечем.
func (u *ListMembershipsUseCase) Execute(
	ctx context.Context, f repomembership.ListFilter,
) ([]domain.Membership, string, error) {
	if err := shared.ValidatePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}
	if err := shared.ValidateResourceID(string(f.AccountID), domain.PrefixAccount, "account"); err != nil {
		return nil, "", err
	}
	// Терм и оператор — тем же разбором, что исполнится в адаптере. Отказ
	// СИНХРОННЫЙ и не оплачивается обращением к хранилищу.
	if _, err := repomembership.ParseListFilter(f.Filter); err != nil {
		return nil, "", shared.MapRepoErr(err)
	}

	rd, closeFn, err := readerOf(ctx, u.repo)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer closeFn()

	rows, next, err := rd.List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return rows, next, nil
}
